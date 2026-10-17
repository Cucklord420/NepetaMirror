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

fn index_bytes(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    fs::read(root.join(name)).map_err(|e| format!("Cannot read {name}: {e}"))
}

fn verify_release(root: &Path) -> Result<(), String> {
    let release = fs::read_to_string(root.join("Release")).map_err(|e| e.to_string())?;
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

fn decompressed(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    let file = File::open(root.join(name)).map_err(|e| e.to_string())?;
    let mut reader: Box<dyn Read> = match name {
        "Packages.bz2" => Box::new(BzDecoder::new(file)),
        "Packages.gz" => Box::new(GzDecoder::new(file)),
        "Packages.lzma" | "Packages.xz" => {
            let stream = Stream::new_auto_decoder(u64::MAX, CONCATENATED)
                .map_err(|e| e.to_string())?;
            Box::new(XzDecoder::new_stream(file, stream))
        }
        _ => return Err(format!("Unknown index compression: {name}")),
    };
    let mut output = Vec::new();
    reader.read_to_end(&mut output).map_err(|e| format!("{name}: {e}"))?;
    Ok(output)
}

fn verify_index_parity(root: &Path) -> Result<Vec<u8>, String> {
    let plain = index_bytes(root, "Packages")?;
    for name in INDEXES.iter().skip(1) {
        if decompressed(root, name)? != plain {
            return Err(format!("{name} does not decompress to the Packages index"));
        }
    }
    Ok(plain)
}

fn package_name_is_safe(filename: &str) -> bool {
    filename.starts_with("packages/")
        && filename.ends_with(".deb")
        && !filename.split('/').any(|component| component == "..")
        && !Path::new(filename).is_absolute()
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
                // Debian control field names are case-insensitive and unique per stanza.
                let normalized_key = key.to_ascii_lowercase();
                if fields
                    .insert(normalized_key, value.trim().to_string())
                    .is_some()
                {
                    return Err(format!("Duplicate package control field: {key}"));
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
        let bytes = fs::read(root.join(filename)).map_err(|e| format!("{filename}: {e}"))?;
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
        if !root.join(required).is_file() {
            return Err(format!("Missing static site file: {required}"));
        }
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
    }

    #[test]
    fn sha256_matches_known_test_vector() {
        assert_eq!(
            digest(b"abc"),
            ["ba7816bf8f01cfea414140de5dae2223", "b00361a396177a9cb410ff61f20015ad"].concat()
        );
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
        let repeated = format!("{record}\n{record}");
        assert!(verify_packages(&root, repeated.as_bytes()).is_err());

        let duplicate_field = format!("{record}Filename: packages/example.deb\n");
        let error = verify_packages(&root, duplicate_field.as_bytes()).unwrap_err();
        assert!(error.contains("Duplicate package control field"), "{error}");
        let differently_cased_duplicate = format!("{record}filename: packages/example.deb\n");
        assert!(verify_packages(&root, differently_cased_duplicate.as_bytes()).is_err());

        let mixed_case_fields = record
            .replace("Filename:", "fIlEnAmE:")
            .replace("Size:", "sIzE:")
            .replace("SHA256:", "sha256:");
        assert_eq!(verify_packages(&root, mixed_case_fields.as_bytes()).unwrap(), 1);

        let traversed = record.replace("packages/example.deb", "packages/../example.deb");
        assert!(verify_packages(&root, traversed.as_bytes()).is_err());
        let tampered = record.replace(&digest(bytes), &"0".repeat(64));
        assert!(verify_packages(&root, tampered.as_bytes()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_repository_content_passes_all_checks() {
        assert!(verify(&root()).is_ok());
    }
}
