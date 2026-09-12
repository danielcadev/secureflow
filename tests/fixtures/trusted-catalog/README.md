# Synthetic public catalog trust vectors

Every key is deterministically derived from a public test seed. These keys provide no production identity or custody. Private test encodings exist only in temporary generator storage; no private key is committed. Never reuse the seeds for a publisher.

`catalog.manifest.json` and `catalog.sqlite3.zst` are frozen, harmless empty-catalog v1 bundle bytes. They preserve the legacy unsigned-manifest contract. The four TUF envelopes bind that exact manifest and have fixed dates around 2026-09-12. Use the explicit synthetic test clock; their expiry is intentional.

`generate.py` uses Python's sorted, compact UTF-8 JSON and OpenSSL Ed25519 independently of Rust's TUF implementation. Run `python3 tests/fixtures/trusted-catalog/generate.py` to reproduce metadata, `.canonical` signing preimages and `hashes.json`; it does not regenerate the frozen database. The targets extension contains both decomposed and composed Unicode, retained distinctly in the signature preimage.

`hashes.json` covers frozen bundle bytes, metadata and canonical vectors. The Python regression reproduces into a temporary directory and compares every byte. Rust independently checks signatures with the maintained TUF library and exact canonical preimages, and adds negative parser, quorum, lifecycle, time, filesystem and transaction tests using separate synthetic keys.

The complete executable ceremony is `scripts/demo-trusted-catalog.py`. It runs each SecureFlow process inside a network-disabled Bubblewrap namespace. Its copied pending-journal example is explicitly simulated; Rust tests separately interrupt real child processes and impose a file-size write quota. Neither is a real custody ceremony or physical power-loss test.
