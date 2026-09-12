//! Strict input profile surrounding maintained TUF and Ed25519 implementations.
use super::{Result, error, require};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use tuf::pouf::{Pouf, Pouf1};

pub const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
pub const ROLES: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];
pub const LIMITS: [usize; 4] = [65_536, 2_097_152, 262_144, 16_384];
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    Pouf1::canonicalize(value).map_err(|e| error("TRUST_FORMAT", e))
}
pub fn hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    require(
        s.len() == N * 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "TRUST_FORMAT",
        "invalid lowercase hex",
    )?;
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| error("TRUST_FORMAT", e))?;
    }
    Ok(out)
}
pub fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| error("TRUST_FORMAT", format!("missing string {k}")))
}
pub fn number(v: &Value, k: &str, max: u64) -> Result<u64> {
    let n = v
        .get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| error("TRUST_FORMAT", format!("missing integer {k}")))?;
    require(n > 0 && n <= max, "TRUST_FORMAT", "integer out of bounds")?;
    Ok(n)
}
pub fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn closed(v: &Value, fields: &[&str]) -> Result<()> {
    let o = v
        .as_object()
        .ok_or_else(|| error("TRUST_FORMAT", "expected object"))?;
    require(
        o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)),
        "TRUST_FORMAT",
        "unknown or missing fields",
    )
}

struct Strict(usize);
impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.0 > 32 {
            return Err(serde::de::Error::custom("JSON depth exceeds 32"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("strict integer JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        if v.unsigned_abs() > MAX_SEQUENCE {
            return Err(E::custom("integer precision bound"));
        }
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        if v > MAX_SEQUENCE {
            return Err(E::custom("integer precision bound"));
        }
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Value, E> {
        Err(E::custom("floats forbidden"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(Strict(self.0 + 1))? {
            out.push(v);
        }
        Ok(out.into())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            out.insert(k, a.next_value_seed(Strict(self.0 + 1))?);
        }
        Ok(out.into())
    }
}
pub fn parse(bytes: &[u8], limit: usize) -> Result<Value> {
    require(bytes.len() <= limit, "TRUST_FORMAT", "JSON byte limit")?;
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let v = Strict(0)
        .deserialize(&mut d)
        .map_err(|e| error("TRUST_FORMAT", e))?;
    d.end().map_err(|e| error("TRUST_FORMAT", e))?;
    Ok(v)
}
fn metadata_strings(v: &Value) -> Result<()> {
    match v {
        Value::String(s) => require(
            !s.chars().any(|c| c < '\u{20}'),
            "TRUST_FORMAT",
            "C0 controls outside metadata profile",
        ),
        Value::Array(a) => {
            for v in a {
                metadata_strings(v)?;
            }
            Ok(())
        }
        Value::Object(o) => {
            for (k, v) in o {
                require(!k.chars().any(|c| c < '\u{20}'), "TRUST_FORMAT", "C0 key")?;
                metadata_strings(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
pub fn envelope(bytes: &[u8], role: &str) -> Result<Value> {
    let index = ROLES
        .iter()
        .position(|r| *r == role)
        .ok_or_else(|| error("TRUST_FORMAT", "unknown role"))?;
    let v = parse(bytes, LIMITS[index])?;
    closed(&v, &["signed", "signatures"])?;
    metadata_strings(&v)?;
    let s = &v["signed"];
    require(
        string(s, "_type")? == role && string(s, "spec_version")? == "1.0.0",
        "TRUST_FORMAT",
        "role/specification mismatch",
    )?;
    number(s, "version", u32::MAX as u64)?;
    super::parse_time(string(s, "expires")?)?;
    require(
        s.get("critical").is_none() && s.get("delegations").is_none(),
        "TRUST_FORMAT",
        "unsupported critical/delegation semantics",
    )?;
    let sigs = v["signatures"]
        .as_array()
        .ok_or_else(|| error("TRUST_FORMAT", "signatures array"))?;
    require(sigs.len() <= 32, "TRUST_FORMAT", "signature bound")?;
    let mut seen = BTreeSet::new();
    for sig in sigs {
        closed(sig, &["keyid", "sig"])?;
        let key = string(sig, "keyid")?;
        hex::<32>(key)?;
        hex::<64>(string(sig, "sig")?)?;
        require(seen.insert(key), "TRUST_SIGNATURE", "duplicate signer")?;
    }
    Ok(v)
}
pub fn root_profile(root: &Value) -> Result<()> {
    let s = &root["signed"];
    require(
        s["consistent_snapshot"] == true,
        "TRUST_FORMAT",
        "consistent snapshots required",
    )?;
    let keys = s["keys"]
        .as_object()
        .ok_or_else(|| error("TRUST_FORMAT", "keys object"))?;
    require(keys.len() <= 32, "TRUST_FORMAT", "key bound")?;
    closed(&s["roles"], &ROLES)?;
    let mut publics = BTreeSet::new();
    let mut assigned = BTreeSet::new();
    for (id, k) in keys {
        closed(k, &["keytype", "scheme", "keyval"])?;
        closed(&k["keyval"], &["public"])?;
        require(
            k["keytype"] == "ed25519" && k["scheme"] == "ed25519",
            "TRUST_SIGNATURE",
            "only Ed25519",
        )?;
        let public = hex::<32>(string(&k["keyval"], "public")?)?;
        let pk = VerifyingKey::from_bytes(&public).map_err(|e| error("TRUST_SIGNATURE", e))?;
        require(
            !pk.is_weak()
                && pk.to_edwards().compress().to_bytes() == public
                && publics.insert(public),
            "TRUST_SIGNATURE",
            "weak or duplicate public key",
        )?;
        require(
            digest(&canonical(k)?) == *id,
            "TRUST_SIGNATURE",
            "key ID mismatch",
        )?;
    }
    for (i, role) in ROLES.iter().enumerate() {
        let r = &s["roles"][role];
        closed(r, &["threshold", "keyids"])?;
        let threshold = number(r, "threshold", 32)?;
        let ids = r["keyids"]
            .as_array()
            .ok_or_else(|| error("TRUST_FORMAT", "role key IDs"))?;
        require(
            threshold >= if i < 2 { 2 } else { 1 }
                && threshold <= ids.len() as u64
                && ids.len() >= if i < 2 { 3 } else { 2 },
            "TRUST_SIGNATURE",
            "local quorum/custody floor",
        )?;
        for id in ids {
            let id = id.as_str().ok_or_else(|| error("TRUST_FORMAT", "key ID"))?;
            require(
                keys.contains_key(id) && assigned.insert(id),
                "TRUST_SIGNATURE",
                "missing or reused role key",
            )?;
        }
    }
    require(
        assigned.len() == keys.len(),
        "TRUST_SIGNATURE",
        "unassigned root key",
    )
}
/// Strict Ed25519 is an additional profile gate, never a replacement for TUF verification.
pub fn strict_signers(root: &Value, metadata: &Value, role: &str) -> Result<Vec<String>> {
    let ids = root["signed"]["roles"][role]["keyids"]
        .as_array()
        .ok_or_else(|| error("TRUST_SIGNATURE", "missing role"))?;
    let threshold = number(&root["signed"]["roles"][role], "threshold", 32)?;
    let preimage = canonical(&metadata["signed"])?;
    let mut accepted = Vec::new();
    for sig in metadata["signatures"]
        .as_array()
        .ok_or_else(|| error("TRUST_FORMAT", "signatures"))?
    {
        let id = string(sig, "keyid")?;
        if !ids.iter().any(|v| v == id) {
            continue;
        }
        let pk = VerifyingKey::from_bytes(&hex::<32>(string(
            &root["signed"]["keys"][id]["keyval"],
            "public",
        )?)?)
        .map_err(|e| error("TRUST_SIGNATURE", e))?;
        let sig = Signature::from_bytes(&hex::<64>(string(sig, "sig")?)?);
        if pk.verify_strict(&preimage, &sig).is_ok() {
            accepted.push(id.into());
        }
    }
    require(
        accepted.len() as u64 >= threshold,
        "TRUST_SIGNATURE",
        "insufficient distinct valid signatures",
    )?;
    accepted.sort();
    Ok(accepted)
}
