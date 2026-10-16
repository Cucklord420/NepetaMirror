//! Read-only Rust parity verifier for the frozen Nepeta/Cydia package mirror.
//! Keeps original package archives unchanged and attributed to upstream.

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use xz2::read::XzDecoder;
use xz2::stream::{Stream, CONCATENATED};

const INDEXES: [&str; 5] = ["Packages", "Packages.bz2", "Packages.gz", "Packages.lzma", "Packages.xz"];

fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

// Refuse links in metadata, indexes, site assets, and package paths, including
// ancestors of the repository root. Checks do not make a concurrently edited
// checkout race-free; the verifier should run against a stable checkout.
fn checked_regular_file(root: &Path, name: &str) -> Result<PathBuf, String> {
    let path = root.join(name);
    for ancestor in path.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|e| format!("Cannot inspect {name}: {e}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("Linked file or directory is not allowed: {name}"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x0400 != 0 {
                return Err(format!("Reparse-point path is not allowed: {name}"));
            }
        }
    }
    if !path.is_file() {
        return Err(format!("Not a regular file: {name}"));
    }
    Ok(path)
}

fn index_bytes(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    fs::read(checked_regular_file(root, name)?)
        .map_err(|e| format!("Cannot read {name}: {e}"))
}

fn verify_release(root: &Path) -> Result<(), String> {
    let release =
        fs::read_to_string(checked_regular_file(root, "Release")?).map_err(|e| e.to_string())?;
    let mut in_sha = false;
    let mut found = HashSet::<String>::new();
    for line in release.lines() {
        if line == "SHA256:" {
            in_sha = true;
            continue;
        }
        if line.chars().next().is_some_and(|c| !c.is_whitespace()) {
            in_sha = false;
        }
        if !in_sha || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 {
            return Err("Invalid SHA256 record in Release".into());
        }
        let (hash, length, filename) = (fields[0], fields[1], fields[2]);
        if !INDEXES.contains(&filename) {
            return Err(format!("Unexpected path in Release SHA256 section: {filename}"));
        }
        if !found.insert(filename.to_string()) {
            return Err(format!("Duplicate Release SHA256 entry: {filename}"));
        }
        let bytes = index_bytes(root, filename)?;
        let declared: usize = length.parse().map_err(|_| "Invalid declared length".to_string())?;
        if declared != bytes.len() || !hash.eq_ignore_ascii_case(&digest(&bytes)) {
            return Err(format!("Invalid Release SHA256 or length for {filename}"));
        }
    }
    if found.len() != INDEXES.len() || INDEXES.iter().any(|name| !found.contains(*name)) {
        return Err("Incomplete Release SHA256 section".into());
    }
    Ok(())
}

fn decompressed(root: &Path, name: &str, max_len: usize) -> Result<Vec<u8>, String> {
    let file = File::open(checked_regular_file(root, name)?).map_err(|e| e.to_string())?;
    let reader: Box<dyn Read> = match name {
        "Packages.bz2" => Box::new(BzDecoder::new(file)),
        "Packages.gz" => Box::new(GzDecoder::new(file)),
        "Packages.lzma" | "Packages.xz" => {
            let stream = Stream::new_auto_decoder(u64::MAX, CONCATENATED)
                .map_err(|e| e.to_string())?;
            Box::new(XzDecoder::new_stream(file, stream))
        }
        _ => return Err(format!("Unknown index compression: {name}")),
    };
    // An index that expands beyond the already verified plain index cannot
    // match it. Bound inflation before allocating the entire output.
    let mut bounded = reader.take((max_len as u64).saturating_add(1));
    let mut output = Vec::new();
    bounded.read_to_end(&mut output).map_err(|e| format!("{name}: {e}"))?;
    if output.len() > max_len {
        return Err(format!("{name} decompresses beyond the Packages index size"));
    }
    Ok(output)
}

fn verify_index_parity(root: &Path) -> Result<Vec<u8>, String> {
    let plain = index_bytes(root, "Packages")?;
    for name in INDEXES.iter().skip(1) {
        if decompressed(root, name, plain.len())? != plain {
            return Err(format!("{name} does not decompress to the Packages index"));
        }
    }
    Ok(plain)
}

fn package_name_is_safe(filename: &str) -> bool {
    let mut components = filename.split('/');
    if components.next() != Some("packages") {
        return false;
    }
    let remainder: Vec<&str> = components.collect();
    !remainder.is_empty()
        && remainder.last().is_some_and(|name| name.ends_with(".deb"))
        && remainder.iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && !part.chars().any(|ch| {
                    ch.is_control() || matches!(ch, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
                })
        })
}

// A package must be a real file in the checkout, never a linked target.
fn checked_package_path(root: &Path, filename: &str) -> Result<PathBuf, String> {
    if !package_name_is_safe(filename) {
        return Err(format!("Unsafe or missing package filename: {filename}"));
    }
    checked_regular_file(root, filename)
}

fn verify_packages(root: &Path, plain: &[u8]) -> Result<usize, String> {
    let text = std::str::from_utf8(plain)
        .map_err(|_| "Packages index is not UTF-8".to_string())?
        .replace("\r\n", "\n");
    let mut seen = HashSet::<String>::new();
    let mut count = 0usize;
    for entry in text.trim().split("\n\n") {
        if entry.trim().is_empty() {
            continue;
        }
        let mut fields = HashMap::<String, String>::new();
        for line in entry.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                // Debian control field names are case-insensitive and cannot repeat.
                let key = key.to_ascii_lowercase();
                if fields.insert(key.clone(), value.trim().to_string()).is_some() {
                    return Err(format!("Duplicate Packages control field: {key}"));
                }
            }
        }
        let filename = fields.get("filename").map_or("", String::as_str);
        if !package_name_is_safe(filename) {
            return Err(format!("Unsafe or missing package filename: {filename}"));
        }
        if !seen.insert(filename.to_string()) {
            return Err(format!("Repeated package filename in Packages: {filename}"));
        }
        let package_path = checked_package_path(root, filename)?;
        let bytes = fs::read(package_path).map_err(|e| format!("{filename}: {e}"))?;
        let size = fields
            .get("size")
            .ok_or_else(|| "Missing Size field".to_string())?
            .parse::<usize>()
            .map_err(|_| "Invalid Size field".to_string())?;
        let expected = fields.get("sha256").ok_or_else(|| "Missing SHA256 field".to_string())?;
        if size != bytes.len() || !expected.eq_ignore_ascii_case(&digest(&bytes)) {
            return Err(format!("Package checksum or length mismatch: {filename}"));
        }
        count += 1;
    }
    if count == 0 {
        return Err("Packages index is empty".into());
    }
    Ok(count)
}

fn verify(root: &Path) -> Result<usize, String> {
    for required in ["README.md", "index.html", "style.css"] {
        checked_regular_file(root, required)?;
    }
    verify_release(root)?;
    let plain = verify_index_parity(root)?;
    verify_packages(root, &plain)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn main() {
    match verify(&root()) {
        Ok(count) => println!("Validated {} indexes and {count} package archives.", INDEXES.len()),
        Err(error) => {
            eprintln!("Mirror verification failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_safety_rejects_traversal_and_bad_extensions() {
        assert!(package_name_is_safe("packages/test.deb"));
        assert!(!package_name_is_safe("packages/../outside.deb"));
        assert!(!package_name_is_safe("/packages/test.deb"));
        assert!(!package_name_is_safe("other/test.deb"));
        assert!(!package_name_is_safe("packages/test.zip"));
        for bad in ["packages//test.deb", "packages/./test.deb",
                    "packages\\test.deb", "packages/folder/../test.deb",
                    "packages/test?.deb", "packages/test.deb/"] {
            assert!(!package_name_is_safe(bad), "accepted unsafe package path: {bad}");
        }
    }

    #[test]
    fn sha256_matches_known_test_vector() {
        assert_eq!(
            digest(b"abc"),
            ["ba7816bf8f01cfea414140de5dae2223", "b00361a396177a9cb410ff61f20015ad"].concat()
        );
    }

    #[test]
    fn compressed_index_expansion_is_bounded_by_plain_index() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "nepeta-bounded-inflate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let payload = vec![b'X'; 16_384];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&payload).unwrap();
        fs::write(root.join("Packages.gz"), encoder.finish().unwrap()).unwrap();

        assert!(decompressed(&root, "Packages.gz", 100).is_err());
        assert_eq!(decompressed(&root, "Packages.gz", payload.len()).unwrap(), payload);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_root_files_fail_closed() {
        let missing = std::env::temp_dir().join("nonexistent-nepeta-mirror-rust-fixture");
        assert!(verify(&missing).is_err());
    }


    #[test]
    fn mutated_release_records_and_package_files_are_rejected() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "nepeta-negative-rust-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let index_bytes = b"fixture";
        let mut release = String::from("SHA256:\n");
        for name in INDEXES {
            fs::write(root.join(name), index_bytes).unwrap();
            release.push_str(&format!(" {} {} {}\n", digest(index_bytes), index_bytes.len(), name));
        }
        fs::write(root.join("Release"), &release).unwrap();
        assert!(verify_release(&root).is_ok());
        fs::write(root.join("Packages"), b"tampered").unwrap();
        assert!(verify_release(&root).is_err());
        fs::write(root.join("Packages"), index_bytes).unwrap();

        let duplicate = format!("{release} {} {} {}\n", digest(index_bytes), index_bytes.len(), "Packages");
        fs::write(root.join("Release"), duplicate).unwrap();
        assert!(verify_release(&root).is_err());
        let incomplete = format!("SHA256:\n {} {} Packages\n", digest(index_bytes), index_bytes.len());
        fs::write(root.join("Release"), incomplete).unwrap();
        assert!(verify_release(&root).is_err());

        fs::create_dir_all(root.join("packages")).unwrap();
        let bytes = b"fictional test archive";
        fs::write(root.join("packages/example.deb"), bytes).unwrap();
        let record = format!(
            "Package: example\nFilename: packages/example.deb\nSize: {}\nSHA256: {}\n",
            bytes.len(),
            digest(bytes)
        );
        assert_eq!(verify_packages(&root, record.as_bytes()).unwrap(), 1);
        // Debian control field names are case-insensitive; duplicates are invalid.
        let mixed_case = record
            .replace("Filename:", "fIlEnAmE:")
            .replace("Size:", "sIzE:")
            .replace("SHA256:", "sha256:");
        assert_eq!(verify_packages(&root, mixed_case.as_bytes()).unwrap(), 1);
        let duplicate = format!("{record}Filename: packages/not-the-archive.deb\n");
        assert!(verify_packages(&root, duplicate.as_bytes()).is_err());
        let duplicate_case = format!("{record}fIlEnAmE: packages/not-the-archive.deb\n");
        assert!(verify_packages(&root, duplicate_case.as_bytes()).is_err());
        let duplicate_checksum = format!("{record}sha256: {}\n", "0".repeat(64));
        assert!(verify_packages(&root, duplicate_checksum.as_bytes()).is_err());
        let repeated = format!("{record}\n{record}");
        assert!(verify_packages(&root, repeated.as_bytes()).is_err());
        let traversed = record.replace("packages/example.deb", "packages/../example.deb");
        assert!(verify_packages(&root, traversed.as_bytes()).is_err());
        let tampered = record.replace(&digest(bytes), &"0".repeat(64));
        assert!(verify_packages(&root, tampered.as_bytes()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn linked_release_indexes_and_site_assets_are_rejected() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let root = std::env::temp_dir().join(format!(
            "nepeta-metadata-links-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let data = b"fictional index";
        let mut release = String::from("SHA256:\n");
        for name in INDEXES {
            fs::write(root.join(name), data).unwrap();
            release.push_str(&format!(" {} {} {}\n", digest(data), data.len(), name));
        }
        fs::write(root.join("external-release"), &release).unwrap();
        symlink("external-release", root.join("Release")).unwrap();
        assert!(verify_release(&root).is_err(), "linked Release accepted");

        fs::remove_file(root.join("Release")).unwrap();
        fs::write(root.join("Release"), release).unwrap();
        assert!(verify_release(&root).is_ok());
        fs::rename(root.join("Packages.gz"), root.join("external-packages.gz")).unwrap();
        symlink("external-packages.gz", root.join("Packages.gz")).unwrap();
        assert!(verify_release(&root).is_err(), "linked Packages.gz accepted");

        fs::write(root.join("README.md"), "fixture").unwrap();
        fs::rename(root.join("README.md"), root.join("outside-readme")).unwrap();
        symlink("outside-readme", root.join("README.md")).unwrap();
        assert!(checked_regular_file(&root, "README.md").is_err());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn live_repository_content_passes_all_checks() {
        assert!(verify(&root()).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_archive_does_not_count_as_an_in_repository_payload() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "nepeta-rust-link-{}-{}",
            std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("packages")).unwrap();
        let actual = root.join("actual.deb");
        let payload = b"fixture payload only";
        fs::write(&actual, payload).unwrap();
        symlink(&actual, root.join("packages/alias.deb")).unwrap();
        let record = format!(
            "Filename: packages/alias.deb\nSize: {}\nSHA256: {}\n",
            payload.len(), digest(payload)
        );
        assert!(verify_packages(&root, record.as_bytes()).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

}
