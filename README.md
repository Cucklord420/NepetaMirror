# Nepeta-Mirror
The hero we don't deserve.


Nepeta (NepetaDev) gets full credit for everything in this repository. This is just a mirror. I did not create anything, and none of this is my work.

Integrity verification uses Rust (read-only):

```sh
cargo test --manifest-path rust/verify-repository/Cargo.toml --locked
cargo run --manifest-path rust/verify-repository/Cargo.toml --locked
```

This verifier checks package archives, repository indexes, local `Depiction` and `Icon` references, and the exact set and SHA-256 hashes of the five site assets, all depictions, and all icons recorded in `MIRROR-ASSETS.tsv`. Review asset content and its manifest together for any intentional asset change. These checks establish consistency with metadata tracked in this repository; they do not independently authenticate the original publisher. The current tree has no `InRelease` or `Release.gpg` signature, so publisher authenticity is unverified.
