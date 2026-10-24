# Repository instructions — NepetaMirror

Before substantive work, read the complete current `AGENTS.md` and `GUIDEBOOK.md` from the default branch of [Toe-Tickling](https://github.com/Cucklord420/Toe-Tickling). At this checkpoint they are at Toe-Tickling `4f519c3ea1ed120d36aefea014fbf31bc0593304`, with `AGENTS.md` blob `5407f0bcf6dd092033ba80399b02519c13c1a998` and `GUIDEBOOK.md` blob `45bdd5dce12eaf8cb74a22e0868a64852d85ed94`. Confirm the current revisions before each task; this link is an instruction pointer and does not imply automatic loading.

This repository preserves upstream Nepeta/Cydia archives and site material. Keep package archives, published indexes, historical `Release`, depictions, images, attribution, and third-party licenses byte-identical unless the owner gives a separate explicit instruction. Never regenerate or replace mirror data to make a validation pass.

All new application code and tests in this repository must be Rust. GitHub Actions workflow orchestration may use the minimum necessary runner-native shell for setup and platform checks; keep substantive validation in Rust. Keep the verifier read-only. Use isolated, securely created test directories; a test may remove only a directory it created and owns. Do not follow symlinks or reparse points from mirror paths. Treat the tracked `Release` file as an integrity reference, not proof of publisher authenticity.

Mirror file path components are intentionally restricted to portable ASCII names. Revisit the path rules before adding non-ASCII or platform-specific filenames.

Before changing the verifier, inspect `rust/verify-repository/`, `.github/workflows/validate.yml`, the real indexes and package paths, and relevant migration history. Run `cargo fmt --check`, locked tests, strict Clippy, the verifier itself, original-versus-Rust behavior checks, and adversarial fixtures on the exact final candidate. Preserve synthetic test data only; never add real package contents to tests or logs. Report unsupported Windows filesystem layouts, Pages/runtime behavior, and external trust limits as blockers rather than inferring success.

For every substantive task, record the exact current Toe-Tickling AGENTS.md and GUIDEBOOK.md revisions actually read. A URL, stale checkpoint, or prior task's note is not proof of current policy intake. Never execute mirrored package binaries or scripts in CI; CI may inspect package bytes only with the read-only verifier.
