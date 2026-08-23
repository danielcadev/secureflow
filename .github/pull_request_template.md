## What changed

Describe the scoped change and the invariant or use case it addresses.

## Verification

- [ ] `cargo +1.92.0 fmt --all -- --check`
- [ ] `cargo +1.92.0 clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo +1.92.0 test --workspace --locked`
- [ ] Contract/schema and negative tests updated when applicable

## Security and evidence

- [ ] No secrets, private target code, credentials, raw traffic, or local databases are included
- [ ] Automated candidates are not presented as validated vulnerabilities
- [ ] Benchmark claims state split, provenance, units, failures, and limitations
- [ ] External code/data has compatible licensing and attribution
