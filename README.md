# Nepeta-Mirror
The hero we don't deserve.


Nepeta (NepetaDev) gets full credit for everything in this repository. This is just a mirror. I did not create anything, and none of this is my work.

Integrity verification uses Rust (read-only):

```sh
cargo test --manifest-path rust/verify-repository/Cargo.toml --locked
cargo run --manifest-path rust/verify-repository/Cargo.toml --locked
```

This read-only verifier checks package archives, repository indexes, local `Depiction` and `Icon` references, and the exact set and SHA-256 hashes of the five site assets, all depictions, and all icons listed in `MIRROR-ASSETS.tsv`. Review asset content and its manifest together for any intentional asset change. It checks consistency against this repository's metadata; it does not authenticate the original publisher or modify/relicense historical files.

## Publisher trust and provenance

The repository README does not instruct users to add this fork as a Cydia or Zebra source. The inherited Release description mentions Cydia and Zebra as supported formats; that description is not a publisher-authenticity claim. For example, the inspected inherited depiction `depiction/me.nepeta.exo.4` links its Cydia button to `repo.nepeta.me`, not to this fork. No signature-based trust claim is made here.

The Rust verifier checks consistency against metadata tracked in this repository. That does not authenticate the original publisher: an altered Release file and matching altered indexes or archives could remain internally consistent. The historical Release file at [the checked mirror revision](https://github.com/Cucklord420/NepetaMirror/blob/20b9dab1a3127ebfeeb9068376c49145047df80b/Release) contains digest tables, but the repository root at that revision has no `InRelease` or `Release.gpg` signature file.

I checked the source snapshots listed here; this was a bounded review, not an exhaustive search of keyservers or archival catalogs. In [alexPNG/Nepeta-Mirror at commit 46aa3a32bb0a459cf5599ecb2a9a62a309106585](https://github.com/alexPNG/Nepeta-Mirror/tree/46aa3a32bb0a459cf5599ecb2a9a62a309106585), the [Release file](https://github.com/alexPNG/Nepeta-Mirror/blob/46aa3a32bb0a459cf5599ecb2a9a62a309106585/Release) contains descriptive fields but no checksum sections; its root has no `InRelease` or `Release.gpg`. That snapshot's [Packages file](https://github.com/alexPNG/Nepeta-Mirror/blob/46aa3a32bb0a459cf5599ecb2a9a62a309106585/Packages) (blob `8e91101c748a119ed924b09f3348ce5c6e8ea9e4`) differs from the `Packages` file preserved here at the checked revision (blob `58a37d1a59bfc7234d6d9c3c67fde69db3d311c1`), so it does not independently authenticate this snapshot. The [Chr0nicT mirror site](https://chr0nict.github.io/Nepeta-Mirror/) currently says its mirror assets were removed. I did not recover a signed release, a matching trusted publisher key, or independent authenticated checksums from these inspected sources. The provenance and publisher authenticity of the historical files here therefore remain unverified.
