# Dependency license evidence

SecureFlow releases generate two deterministic Cargo dependency artifacts:

- `evidence/sbom.cdx.json`, a CycloneDX 1.5 component inventory; and
- `evidence/dependency-license-declarations.md`, a human-readable inventory of
  the Cargo declarations and the hashes that bind them to release inputs.

The generator is offline. It reads `Cargo.lock`, explicit workspace manifests,
and local Cargo registry archives. It does not invoke Cargo, query crates.io, or
contact another service.

## Evidence boundary

For a crates.io package, the generator requires a 64-character checksum in
`Cargo.lock`. It opens a non-symlink, regular `.crate` archive from the local
Cargo cache, streams it under a 512 MiB limit, and verifies its SHA-256 against
that checksum. It then reads the normalized `Cargo.toml` from the same open file
descriptor, verifies the package name and version, and hashes the descriptor
again after inspection. The manifest must declare exactly one of `license` and
`license-file`.

A `license` value is retained verbatim. Legacy Cargo declarations containing a
slash are represented as named CycloneDX licenses rather than being rewritten
into a different SPDX expression. A `license-file` path must be relative and
safe; its regular archive member is retained by path and SHA-256 without
guessing a license identifier from its contents.

Source-less lockfile entries must match explicit workspace members. Workspace
version and license inheritance are resolved from `[workspace.package]`; the
member manifest and any declared license file are bounded, opened without
following their final symlink, and hashed from the opened regular file.
Symlinked workspace path components are rejected. Git dependencies,
unknown registries, workspace globs, missing archives, checksum mismatches,
missing declarations, conflicting declarations, missing license files, unsafe
paths, and pre-existing outputs all fail closed.

The SBOM serial number binds the SecureFlow version, exact `Cargo.lock` bytes,
and a canonical hash of all extracted license evidence. Absolute cache paths
and timestamps are excluded. Given identical inputs and verified archive bytes,
the paired artifacts are byte-for-byte deterministic.

## Limitations

This evidence records package-manager declarations. It is not legal advice, a
complete attribution file, or proof of license compatibility or compliance.
In particular, it does not:

- semantically validate every SPDX identifier or expression;
- interpret license-file text or determine resulting obligations;
- discover undeclared notices or compare declared metadata with all source
  files;
- cover the Rust toolchain, operating-system packages, system libraries,
  advisory datasets, generated assets, or other non-Cargo inputs;
- independently authenticate a crates.io publisher or source repository; or
- prove cross-host binary reproducibility.

Release maintainers must review dependency changes and applicable license
texts and obligations separately. A successful generator run means only that
the stated Cargo declarations were extracted from the checksum-bound inputs
under this policy.

## Local verification

Run the focused tests before generating release evidence:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
cargo +1.92.0 fetch --locked
python3 scripts/generate-sbom.py \
  --output /tmp/secureflow-sbom.cdx.json \
  --attribution-output /tmp/secureflow-dependency-license-declarations.md
```

`cargo fetch --locked` runs as an explicit online acquisition step and, without
`--target`, downloads the lockfile dependencies for every target. The generator
then runs offline and fails closed if any checksum-bound `.crate` archive is
still missing from the selected Cargo cache.
