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

// Refuse linked release metadata, package indexes and site assets, including
// linked repository ancestors. Run the verifier on a stable checkout: these
// read-only checks cannot prevent a concurrent filesystem replacement.
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

fn decompressed(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    let file = File::open(checked_regular_file(root, name)?).map_err(|e| e.to_string())?;
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
    let Some(relative) = filename.strip_prefix("packages/") else {
        return false;
    };
    relative.ends_with(".deb")
        && !relative.contains('\\')
        && !relative.contains(':')
        && !relative.chars().any(|ch| ch.is_control() || matches!(ch, '*' | '?' | '"' | '<' | '>' | '|'))
        && relative
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn verify_packages(root: &Path, plain: &[u8]) -> Result<usize, String> {
    let text = std::str::from_utf8(plain)
        .map_err(|_| "Packages index is not UTF-8".to_string())?
        .replace("\r\n", "\n");
    // Resolve the expected package directory once; reject a directory symlink.
    let canonical_root = fs::canonicalize(root).map_err(|e| format!("Cannot resolve root: {e}"))?;
    let package_root = fs::canonicalize(root.join("packages"))
        .map_err(|e| format!("Cannot resolve packages directory: {e}"))?;
    if package_root != canonical_root.join("packages") {
        return Err("Packages directory resolves outside its expected location".into());
    }

    let mut seen = HashSet::<String>::new();
    let mut count = 0usize;
    for entry in text.trim().split("\n\n") {
        if entry.trim().is_empty() {
            continue;
        }
        let mut fields = HashMap::<String, String>::new();
        let mut previous_key: Option<String> = None;
        for line in entry.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Debian Filename, Size, and SHA256 fields are single-line values.
                if matches!(previous_key.as_deref(), Some("filename" | "size" | "sha256")) {
                    return Err("Folded security-critical Packages field".into());
                }
                continue;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| "Malformed Packages control field".to_string())?;
            // Debian field names are case-insensitive; duplicates are invalid.
            let key = key.to_ascii_lowercase();
            if fields.insert(key.clone(), value.trim().to_string()).is_some() {
                return Err(format!("Duplicate Packages control field: {key}"));
            }
            previous_key = Some(key);
        }
        let filename = fields.get("filename").map_or("", String::as_str);
        if !package_name_is_safe(filename) {
            return Err(format!("Unsafe or missing package filename: {filename}"));
        }
        if !seen.insert(filename.to_string()) {
            return Err(format!("Repeated package filename in Packages: {filename}"));
        }
        // Reject aliases even when their targets remain inside the packages directory.
        let mut checked = root.to_path_buf();
        for part in filename.split('/') {
            checked.push(part);
            let metadata = fs::symlink_metadata(&checked)
                .map_err(|e| format!("{filename}: {e}"))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("Symlink in package path: {filename}"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x0400 != 0 {
                    return Err(format!("Reparse-point in package path: {filename}"));
                }
            }
        }
        // Junctions/reparse points and other links must also remain contained.
        let resolved = fs::canonicalize(&checked).map_err(|e| format!("{filename}: {e}"))?;
        if !resolved.starts_with(&package_root) {
            return Err(format!("Package path resolves outside packages/: {filename}"));
        }
        if !fs::metadata(&resolved).map_err(|e| format!("{filename}: {e}"))?.is_file() {
            return Err(format!("Package is not a regular file: {filename}"));
        }
        let bytes = fs::read(&resolved).map_err(|e| format!("{filename}: {e}"))?;
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
        assert!(!package_name_is_safe("packages/..\\outside.deb"));
        assert!(!package_name_is_safe("packages/dir\\..\\outside.deb"));
        assert!(!package_name_is_safe("packages//test.deb"));
        assert!(!package_name_is_safe("packages/./test.deb"));
        assert!(!package_name_is_safe("packages/C:outside.deb"));
        assert!(!package_name_is_safe("packages/bad\nname.deb"));
        assert!(!package_name_is_safe("packages/bad\tname.deb"));
        assert!(!package_name_is_safe("packages/bad?name.deb"));
        assert!(!package_name_is_safe("packages/bad|name.deb"));
        assert!(package_name_is_safe("packages/subdir/test.deb"));
    }

    #[cfg(unix)]
    #[test]
    fn package_symlink_outside_expected_directory_is_rejected() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "nepeta-symlink-rust-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("packages")).unwrap();
        let bytes = b"synthetic fixture; not a real package";
        fs::write(root.join("outside.deb"), bytes).unwrap();
        symlink("../outside.deb", root.join("packages/linked.deb")).unwrap();
        let record = format!(
            "Package: linked\nFilename: packages/linked.deb\nSize: {}\nSHA256: {}\n",
            bytes.len(),
            digest(bytes)
        );
        let failure = verify_packages(&root, record.as_bytes()).unwrap_err();
        assert!(failure.contains("Symlink in package path"), "{failure}");
        fs::remove_dir_all(root).unwrap();
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
        let mixed_case = record
            .replace("Filename:", "fIlEnAmE:")
            .replace("Size:", "sIzE:")
            .replace("SHA256:", "sha256:");
        assert_eq!(verify_packages(&root, mixed_case.as_bytes()).unwrap(), 1);
        for ambiguous in [
            format!("{record}Filename: packages/other.deb\n"),
            format!("{record}fIlEnAmE: packages/other.deb\n"),
            format!("{record}sha256: {}\n", "0".repeat(64)),
            record.replace("Filename: packages/example.deb", "Filename: packages/example.deb\n extra.deb"),
            format!("{record}not-a-control-field\n"),
        ] {
            assert!(verify_packages(&root, ambiguous.as_bytes()).is_err());
        }
        let description = format!("{record}Description: sample\n continued description\n");
        assert_eq!(verify_packages(&root, description.as_bytes()).unwrap(), 1);
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
}
