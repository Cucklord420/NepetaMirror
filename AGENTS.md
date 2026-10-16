# Agent instructions — NepetaMirror

Before changing this repository, read the current default-branch [Toe-Tickling guidebook](https://github.com/Cucklord420/Toe-Tickling), beginning with its `AGENTS.md`, `GUIDEBOOK.md`, and applicable engineering, verification and security rules. This link is an instruction pointer, not a claim that any provider loads the guide automatically. Respect platform instruction priority and access restrictions. If a required reading or verification gate is unavailable, disclose it rather than claiming completion.

This repository preserves upstream Nepeta/Cydia package archives. Keep the original `.deb` packages, package indexes, `Release` metadata, static assets, copyright attribution, and license rights intact. Rust tooling changes must remain read-only to those artifacts. Do not repackage, rewrite, relocate, or relicense them without separate authorization.

For Rust changes, inspect the current branch and concurrently open PRs before editing. Preserve public URLs, verifier outputs, exit behavior, archive hashes, and Linux/Windows behavior. Include negative fixtures for traversal, platform-specific separators, symlinks/reparse points, tampered checksums, malformed archives, duplicate records, and missing files; do not treat a green unit test as one-to-one parity.

Before merging, verify `cargo test --manifest-path rust/verify-repository/Cargo.toml`, `cargo run --manifest-path rust/verify-repository/Cargo.toml`, and current-head GitHub Actions results on supported OSes. Do not claim a test ran when it did not. Follow the guidebook's current Rust Reference reading and evidence gates; keep a change unmerged if a mandatory gate is blocked. Avoid force-pushes, unreviewed merges and production deployments.
