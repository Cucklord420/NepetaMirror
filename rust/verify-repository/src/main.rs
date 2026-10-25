//! Read-only Rust parity verifier for the frozen Nepeta/Cydia package mirror.
//! Keeps original package archives unchanged and attributed to upstream.

use bzip2::read::MultiBzDecoder;
use flate2::read::MultiGzDecoder;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use xz2::read::XzDecoder;
use xz2::stream::{Stream, CONCATENATED};

const INDEXES: [&str; 5] = [
    "Packages",
    "Packages.bz2",
    "Packages.gz",
    "Packages.lzma",
    "Packages.xz",
];
const RELEASE_SECTIONS: [&str; 4] = ["MD5Sum", "SHA1", "SHA256", "SHA512"];
const MAX_RELEASE_BYTES: u64 = 64 * 1024;
// The tracked Packages index is currently 166,092 bytes; the cap leaves over 96x headroom.
const MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;
// A compressed LZMA stream cannot request more than this decoder memory budget.
const MAX_LZMA_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STATIC_ASSET_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ASSET_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_STATIC_ASSET_COUNT: usize = 4096;
// The current frozen mirror contains 185 archives; this allows more than 22x growth.
const MAX_PACKAGE_ARCHIVE_COUNT: usize = 4096;
// Bound traversal work even when a package tree contains many non-archive entries.
const MAX_PACKAGE_TREE_ENTRY_COUNT: usize = 4096;
// Win32 FILE_ATTRIBUTE_REPARSE_POINT from Microsoft's File Attribute Constants.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const STATIC_ASSET_FILES: [&str; 5] = [
    "CydiaIcon.png",
    "_config.yml",
    "index.html",
    "nepeta.png",
    "style.css",
];
const STATIC_ASSET_DIRS: [&str; 2] = ["depiction", "icons"];

fn digest(section: &str, data: &[u8]) -> Option<String> {
    match section {
        "MD5Sum" => Some(format!("{:x}", Md5::digest(data))),
        "SHA1" => Some(format!("{:x}", Sha1::digest(data))),
        "SHA256" => Some(format!("{:x}", Sha256::digest(data))),
        "SHA512" => Some(format!("{:x}", Sha512::digest(data))),
        _ => None,
    }
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn canonical_root(root: &Path) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(root).map_err(|e| format!("Cannot inspect mirror root: {e}"))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err("Mirror root is not a regular directory".into());
    }
    fs::canonicalize(root).map_err(|e| format!("Cannot resolve mirror root: {e}"))
}

fn safe_path_component(component: &str) -> bool {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.ends_with(['.', ' '])
        || !component.is_ascii()
        || component
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return false;
    }
    // Windows reserves DOS device names even with extensions. The ASCII-only
    // policy also rejects its superscript COM/LPT aliases.
    let device = component
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    let numbered_device = ["COM", "LPT"].iter().any(|prefix| {
        device
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
    });
    !numbered_device
        && !matches!(
            device.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
}

fn checked_relative_regular_file(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.is_empty() || relative.contains('\\') {
        return Err(format!("Invalid mirror file path: {relative:?}"));
    }
    let canonical_root = canonical_root(root)?;
    let components: Vec<&str> = relative.split('/').collect();
    if components
        .iter()
        .any(|component| !safe_path_component(component))
    {
        return Err(format!("Invalid mirror file path: {relative:?}"));
    }
    let mut path = canonical_root.clone();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata =
            fs::symlink_metadata(&path).map_err(|e| format!("Cannot inspect {relative:?}: {e}"))?;
        if is_link_or_reparse(&metadata) {
            return Err(format!("Linked mirror path is not allowed: {relative:?}"));
        }
        if index + 1 == components.len() {
            if !metadata.is_file() {
                return Err(format!("Mirror path is not a regular file: {relative:?}"));
            }
        } else if !metadata.is_dir() {
            return Err(format!("Mirror parent is not a directory: {relative:?}"));
        }
    }
    let resolved =
        fs::canonicalize(&path).map_err(|e| format!("Cannot resolve {relative:?}: {e}"))?;
    if resolved.strip_prefix(&canonical_root).is_err() {
        return Err(format!(
            "Mirror file resolves outside the repository: {relative:?}"
        ));
    }
    Ok(resolved)
}

fn checked_regular_file(root: &Path, name: &str) -> Result<PathBuf, String> {
    if name.contains('/') {
        return Err(format!("Invalid mirror file name: {name:?}"));
    }
    checked_relative_regular_file(root, name)
}

fn read_limited_file(root: &Path, name: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let path = checked_regular_file(root, name)?;
    let file = File::open(&path).map_err(|e| format!("Cannot read {name:?}: {e}"))?;
    let length = file
        .metadata()
        .map_err(|e| format!("Cannot inspect {name:?}: {e}"))?
        .len();
    if length > maximum {
        return Err(format!("{name:?} exceeds the allowed {maximum}-byte limit"));
    }
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| format!("Cannot bound {name:?}"))?;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read {name:?}: {e}"))?;
    if u64::try_from(bytes.len()).map_err(|_| format!("{name:?} is too large"))? > maximum {
        return Err(format!("{name:?} exceeds the allowed {maximum}-byte limit"));
    }
    Ok(bytes)
}

fn is_hex_digest(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_decimal_u64(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn verify_release(root: &Path) -> Result<(), String> {
    let release = String::from_utf8(read_limited_file(root, "Release", MAX_RELEASE_BYTES)?)
        .map_err(|_| "Release file is not UTF-8".to_string())?;
    let mut index_data = HashMap::<&str, Vec<u8>>::new();
    for name in INDEXES {
        index_data.insert(name, read_limited_file(root, name, MAX_INDEX_BYTES)?);
    }

    let mut seen_sections = HashSet::<String>::new();
    let mut section_files = HashMap::<String, HashSet<String>>::new();
    let mut active_section: Option<&str> = None;
    for line in release.lines() {
        if !line.is_empty() && !line.starts_with(char::is_whitespace) {
            active_section = None;
            if let Some((section, value)) = line.split_once(':') {
                if RELEASE_SECTIONS.contains(&section) {
                    if !value.trim().is_empty() {
                        return Err(format!("Invalid {section} section heading in Release"));
                    }
                    if !seen_sections.insert(section.to_string()) {
                        return Err(format!("Duplicate {section} section in Release"));
                    }
                    active_section = Some(section);
                }
            }
            continue;
        }
        let Some(section) = active_section else {
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 {
            return Err(format!("Invalid {section} record in Release"));
        }
        let (hash, length, filename) = (fields[0], fields[1], fields[2]);
        let hash_length = match section {
            "MD5Sum" => 32,
            "SHA1" => 40,
            "SHA256" => 64,
            "SHA512" => 128,
            _ => return Err("Unsupported checksum section in Release".into()),
        };
        if !is_hex_digest(hash, hash_length) {
            return Err(format!("Invalid {section} digest in Release"));
        }
        if !INDEXES.contains(&filename) {
            return Err(format!(
                "Unexpected path in Release {section} section: {filename:?}"
            ));
        }
        let length = parse_decimal_u64(length)
            .ok_or_else(|| format!("Invalid declared length in Release {section} section"))?;
        let bytes = index_data
            .get(filename)
            .ok_or_else(|| format!("Missing index data for {filename:?}"))?;
        let actual_hash = digest(section, bytes)
            .ok_or_else(|| format!("Unsupported checksum section: {section}"))?;
        if length != bytes.len() as u64 || !hash.eq_ignore_ascii_case(&actual_hash) {
            return Err(format!(
                "Invalid {section} digest or length for {filename:?}"
            ));
        }
        let entries = section_files.entry(section.to_string()).or_default();
        if !entries.insert(filename.to_string()) {
            return Err(format!(
                "Duplicate {section} entry in Release: {filename:?}"
            ));
        }
    }

    let expected_files: HashSet<String> = INDEXES.iter().map(|name| (*name).to_string()).collect();
    for section in RELEASE_SECTIONS {
        if !seen_sections.contains(section) {
            return Err(format!("Missing {section} section in Release"));
        }
        if section_files.get(section) != Some(&expected_files) {
            return Err(format!("Incomplete {section} section in Release"));
        }
    }
    Ok(())
}

fn decompressed_reader<R: Read>(
    name: &str,
    input: R,
    expected_size: usize,
    lzma_memory_limit: u64,
) -> Result<Vec<u8>, String> {
    if u64::try_from(expected_size).map_err(|_| format!("{name}: expected index is too large"))?
        > MAX_INDEX_BYTES
    {
        return Err(format!("{name}: expected index exceeds the size limit"));
    }
    let compressed_limit = MAX_INDEX_BYTES
        .checked_add(1)
        .ok_or_else(|| format!("{name}: cannot bound compressed index size"))?;
    let mut compressed = Vec::new();
    input
        .take(compressed_limit)
        .read_to_end(&mut compressed)
        .map_err(|e| format!("{name}: cannot read compressed index: {e}"))?;
    if compressed.len() as u64 > MAX_INDEX_BYTES {
        return Err(format!("{name} exceeds the allowed compressed-index limit"));
    }

    // Auto-decoding handles concatenated .xz streams. Decode legacy .lzma
    // members separately because liblzma's concatenation mode is XZ-specific.
    if name == "Packages.lzma" && !compressed.starts_with(b"\xfd7zXZ\0") {
        return decompressed_lzma_alone(&compressed, expected_size, lzma_memory_limit);
    }

    let reader: Box<dyn Read + '_> = match name {
        "Packages.bz2" => Box::new(MultiBzDecoder::new(compressed.as_slice())),
        "Packages.gz" => Box::new(MultiGzDecoder::new(compressed.as_slice())),
        "Packages.lzma" | "Packages.xz" => {
            let stream = Stream::new_auto_decoder(lzma_memory_limit, CONCATENATED)
                .map_err(|e| e.to_string())?;
            Box::new(XzDecoder::new_stream(compressed.as_slice(), stream))
        }
        _ => return Err(format!("Unknown index compression: {name}")),
    };
    let limit = u64::try_from(expected_size)
        .ok()
        .and_then(|size| size.checked_add(1))
        .ok_or_else(|| format!("{name}: cannot bound decompressed index size"))?;
    let mut output = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|e| format!("{name}: {e}"))?;
    if output.len() > expected_size {
        return Err(format!("{name} expands beyond the Packages index size"));
    }
    Ok(output)
}

fn decompressed_lzma_alone(
    input: &[u8],
    expected_size: usize,
    memory_limit: u64,
) -> Result<Vec<u8>, String> {
    let output_limit = expected_size
        .checked_add(1)
        .ok_or_else(|| "Packages.lzma: cannot bound decompressed index size".to_string())?;
    let mut output = Vec::new();
    let mut input_offset = 0usize;

    while input_offset < input.len() {
        let mut stream =
            Stream::new_lzma_decoder(memory_limit).map_err(|e| format!("Packages.lzma: {e}"))?;
        loop {
            let before_in = stream.total_in();
            let before_out = stream.total_out();
            let consumed = usize::try_from(before_in)
                .map_err(|_| "Packages.lzma: input offset overflow".to_string())?;
            let position = input_offset
                .checked_add(consumed)
                .ok_or_else(|| "Packages.lzma: input offset overflow".to_string())?;
            let remaining = output_limit.saturating_sub(output.len());
            if remaining == 0 {
                return Err("Packages.lzma expands beyond the Packages index size".into());
            }
            let mut buffer = [0u8; 8192];
            let buffer_length = remaining.min(buffer.len());
            let status = stream
                .process(
                    &input[position..],
                    &mut buffer[..buffer_length],
                    xz2::stream::Action::Finish,
                )
                .map_err(|e| format!("Packages.lzma: {e}"))?;
            let produced = usize::try_from(stream.total_out() - before_out)
                .map_err(|_| "Packages.lzma: output length overflow".to_string())?;
            output.extend_from_slice(&buffer[..produced]);
            if output.len() > expected_size {
                return Err("Packages.lzma expands beyond the Packages index size".into());
            }

            match status {
                xz2::stream::Status::StreamEnd => {
                    let consumed = usize::try_from(stream.total_in())
                        .map_err(|_| "Packages.lzma: input offset overflow".to_string())?;
                    if consumed == 0 {
                        return Err("Packages.lzma decoder made no input progress".into());
                    }
                    input_offset = input_offset
                        .checked_add(consumed)
                        .ok_or_else(|| "Packages.lzma: input offset overflow".to_string())?;
                    break;
                }
                _ if stream.total_in() == before_in && produced == 0 => {
                    return Err("Packages.lzma: truncated or invalid stream".into());
                }
                _ => {}
            }
        }
    }

    if output.len() != expected_size {
        return Err("Packages.lzma decompressed size does not match the Packages index".into());
    }
    Ok(output)
}

fn decompressed(root: &Path, name: &str, expected_size: usize) -> Result<Vec<u8>, String> {
    let path = checked_regular_file(root, name)?;
    let file = File::open(path).map_err(|e| format!("Cannot read {name}: {e}"))?;
    let length = file
        .metadata()
        .map_err(|e| format!("Cannot inspect {name}: {e}"))?
        .len();
    if length > MAX_INDEX_BYTES {
        return Err(format!("{name} exceeds the allowed compressed-index limit"));
    }
    decompressed_reader(name, file, expected_size, MAX_LZMA_MEMORY_BYTES)
}

fn verify_index_parity(root: &Path) -> Result<Vec<u8>, String> {
    let plain = read_limited_file(root, "Packages", MAX_INDEX_BYTES)?;
    for name in INDEXES.iter().skip(1) {
        if decompressed(root, name, plain.len())? != plain {
            return Err(format!("{name} does not decompress to the Packages index"));
        }
    }
    Ok(plain)
}

fn package_name_is_safe(filename: &str) -> bool {
    let Some(relative) = filename.strip_prefix("packages/") else {
        return false;
    };
    if relative.is_empty() || !relative.ends_with(".deb") || relative.contains(['\\', ':']) {
        return false;
    }
    relative.split('/').all(safe_path_component)
}

fn register_casefolded_package_path(
    filename: &str,
    paths: &mut HashMap<String, String>,
) -> Result<(), String> {
    let relative = filename
        .strip_prefix("packages/")
        .ok_or_else(|| format!("Unsafe package path: {filename:?}"))?;
    let mut exact = String::from("packages");
    let mut folded = String::from("packages");
    for component in relative.split('/') {
        exact.push('/');
        exact.push_str(component);
        folded.push('/');
        folded.push_str(&component.to_ascii_lowercase());
        match paths.get(&folded) {
            Some(previous) if previous != &exact => {
                return Err(format!(
                    "Case-insensitive package path collision: {previous:?} and {exact:?}"
                ));
            }
            Some(_) => {}
            None => {
                paths.insert(folded.clone(), exact.clone());
            }
        }
    }
    Ok(())
}

fn valid_field_name(name: &str) -> bool {
    let mut chars = name.bytes();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_package_name(value: &str) -> bool {
    let mut chars = value.bytes();
    value.len() >= 2
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
}

fn valid_version(value: &str) -> bool {
    let version = if let Some((epoch, remainder)) = value.split_once(':') {
        if epoch.is_empty()
            || !epoch.bytes().all(|byte| byte.is_ascii_digit())
            || remainder.contains(':')
        {
            return false;
        }
        remainder
    } else {
        value
    };
    let (upstream, revision) = match version.rsplit_once('-') {
        Some((upstream, revision)) => (upstream, Some(revision)),
        None => (version, None),
    };
    if upstream.is_empty() || !upstream.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    let allowed_upstream =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'~');
    if !upstream.bytes().all(allowed_upstream) {
        return false;
    }
    if let Some(revision) = revision {
        !revision.is_empty()
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'~'))
    } else {
        !version.contains('-')
    }
}

fn valid_architecture(value: &str) -> bool {
    let mut chars = value.bytes();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn package_root(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let canonical_root = canonical_root(root)?;
    let path = canonical_root.join("packages");
    let metadata =
        fs::symlink_metadata(&path).map_err(|e| format!("Cannot inspect packages/: {e}"))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err("packages/ is not a regular directory".into());
    }
    let resolved = fs::canonicalize(&path).map_err(|e| format!("Cannot resolve packages/: {e}"))?;
    if resolved.parent() != Some(canonical_root.as_path()) {
        return Err("packages/ resolves outside the mirror root".into());
    }
    Ok((canonical_root, resolved))
}

fn checked_package_file(package_root: &Path, filename: &str) -> Result<PathBuf, String> {
    if !package_name_is_safe(filename) {
        return Err(format!("Unsafe package path: {filename:?}"));
    }
    let repository_root = package_root
        .parent()
        .ok_or_else(|| "packages/ has no parent directory".to_string())?;
    let resolved = checked_relative_regular_file(repository_root, filename)?;
    if resolved.strip_prefix(package_root).is_err() {
        return Err(format!(
            "Package path resolves outside packages/: {filename:?}"
        ));
    }
    Ok(resolved)
}

fn check_site_reference(root: &Path, field: &str, value: &str) -> Result<(), String> {
    let relative = value
        .strip_prefix("./")
        .ok_or_else(|| format!("Invalid local {field} path: {value:?}"))?;
    let in_scope = match field {
        "Depiction" => relative.starts_with("depiction/"),
        "Icon" => relative == "CydiaIcon.png" || relative.starts_with("icons/"),
        _ => false,
    };
    if !in_scope {
        return Err(format!(
            "{field} path is outside the allowed asset directory: {value:?}"
        ));
    }
    checked_relative_regular_file(root, relative)?;
    Ok(())
}

fn hash_sha256_file(path: &Path, expected_size: u64, filename: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot read {filename:?}: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Cannot inspect {filename:?}: {e}"))?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(format!("File size mismatch: {filename:?}"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("Cannot read {filename:?}: {e}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| format!("File is too large: {filename:?}"))?;
        if total > expected_size {
            return Err(format!("File grew while being read: {filename:?}"));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(format!("File size mismatch: {filename:?}"));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn list_package_archives(package_root: &Path) -> Result<HashSet<String>, String> {
    let mut pending = vec![package_root.to_path_buf()];
    let mut found = HashSet::new();
    let mut visited_entries = 0usize;
    while let Some(directory) = pending.pop() {
        let entries =
            fs::read_dir(&directory).map_err(|e| format!("Cannot enumerate packages/: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Cannot enumerate packages/: {e}"))?;
            visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
                "Package directory entry count exceeds the configured limit".to_string()
            })?;
            if visited_entries > MAX_PACKAGE_TREE_ENTRY_COUNT {
                return Err("Package directory entry count exceeds the configured limit".into());
            }

            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|e| format!("Cannot inspect package entry: {e}"))?;
            if is_link_or_reparse(&metadata) {
                return Err("Linked entries are not allowed under packages/".into());
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err("Non-regular entry found under packages/".into());
            }

            let relative = path
                .strip_prefix(package_root)
                .map_err(|_| "Package entry escaped packages/".to_string())?;
            let relative = relative
                .to_str()
                .ok_or_else(|| "Package path is not valid UTF-8".to_string())?
                .replace('\\', "/");
            let filename = format!("packages/{relative}");
            if !package_name_is_safe(&filename) {
                return Err(format!("Unsafe package archive path: {filename:?}"));
            }
            found.insert(filename);
            if found.len() > MAX_PACKAGE_ARCHIVE_COUNT {
                return Err("Package archive count exceeds the configured limit".into());
            }
        }
    }
    Ok(found)
}

fn is_static_asset_path(path: &str) -> bool {
    STATIC_ASSET_FILES.contains(&path)
        || STATIC_ASSET_DIRS
            .iter()
            .any(|directory| path.starts_with(&format!("{directory}/")))
}

fn collect_static_asset_paths(root: &Path) -> Result<HashSet<String>, String> {
    let canonical_root = canonical_root(root)?;
    let mut found = HashSet::new();
    for name in STATIC_ASSET_FILES {
        let path = checked_regular_file(root, name)?;
        let length = fs::metadata(path)
            .map_err(|e| format!("Cannot inspect {name}: {e}"))?
            .len();
        if length > MAX_STATIC_ASSET_BYTES {
            return Err(format!("Static asset exceeds the size limit: {name}"));
        }
        found.insert(name.to_string());
    }

    for directory in STATIC_ASSET_DIRS {
        let path = canonical_root.join(directory);
        let metadata =
            fs::symlink_metadata(&path).map_err(|e| format!("Cannot inspect {directory}/: {e}"))?;
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(format!(
                "Static asset directory is not regular: {directory}/"
            ));
        }
        let resolved =
            fs::canonicalize(&path).map_err(|e| format!("Cannot resolve {directory}/: {e}"))?;
        if resolved.parent() != Some(canonical_root.as_path()) {
            return Err(format!(
                "Static asset directory escapes repository: {directory}/"
            ));
        }

        let mut pending = vec![resolved];
        while let Some(current) = pending.pop() {
            let entries = fs::read_dir(&current)
                .map_err(|e| format!("Cannot enumerate {directory}/: {e}"))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("Cannot enumerate {directory}/: {e}"))?;
                let asset = entry.path();
                let metadata = fs::symlink_metadata(&asset)
                    .map_err(|e| format!("Cannot inspect {directory} asset: {e}"))?;
                if is_link_or_reparse(&metadata) {
                    return Err(format!("Linked static asset is not allowed: {directory}/"));
                }
                if metadata.is_dir() {
                    pending.push(asset);
                    continue;
                }
                if !metadata.is_file() {
                    return Err(format!("Non-regular static asset under {directory}/"));
                }
                if metadata.len() > MAX_STATIC_ASSET_BYTES {
                    return Err(format!("Static asset exceeds the size limit: {directory}/"));
                }
                let relative = asset
                    .strip_prefix(&canonical_root)
                    .map_err(|_| format!("Static asset escapes repository: {directory}/"))?
                    .to_str()
                    .ok_or_else(|| "Static asset path is not valid UTF-8".to_string())?
                    .replace('\\', "/");
                if !is_static_asset_path(&relative)
                    || relative
                        .split('/')
                        .any(|component| !safe_path_component(component))
                {
                    return Err(format!("Invalid static asset path: {relative:?}"));
                }
                found.insert(relative);
                if found.len() > MAX_STATIC_ASSET_COUNT {
                    return Err("Static asset count exceeds the configured limit".into());
                }
            }
        }
    }
    Ok(found)
}

fn verify_static_assets(root: &Path) -> Result<(), String> {
    let manifest = String::from_utf8(read_limited_file(
        root,
        "MIRROR-ASSETS.tsv",
        MAX_ASSET_MANIFEST_BYTES,
    )?)
    .map_err(|_| "Static asset manifest is not UTF-8".to_string())?;
    let actual_paths = collect_static_asset_paths(root)?;
    let mut listed_paths = HashSet::new();
    for line in manifest.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err("Invalid static asset manifest row".into());
        }
        let (hash, size, path) = (fields[0], fields[1], fields[2]);
        if !is_hex_digest(hash, 64) || !is_static_asset_path(path) {
            return Err("Invalid static asset manifest entry".into());
        }
        if !actual_paths.contains(path) {
            return Err(format!("Unexpected static asset in manifest: {path:?}"));
        }
        if !listed_paths.insert(path.to_string()) {
            return Err(format!("Duplicate static asset manifest entry: {path:?}"));
        }
        let size = parse_decimal_u64(size)
            .ok_or_else(|| format!("Invalid static asset length: {path:?}"))?;
        if size > MAX_STATIC_ASSET_BYTES {
            return Err(format!("Static asset exceeds the size limit: {path:?}"));
        }
        let file = checked_relative_regular_file(root, path)?;
        let actual_hash = hash_sha256_file(&file, size, path)?;
        if !hash.eq_ignore_ascii_case(&actual_hash) {
            return Err(format!("Static asset checksum mismatch: {path:?}"));
        }
    }
    if listed_paths != actual_paths {
        return Err("Static asset manifest does not cover the exact on-disk asset set".into());
    }
    Ok(())
}

fn verify_packages(root: &Path, plain: &[u8]) -> Result<usize, String> {
    let text = std::str::from_utf8(plain)
        .map_err(|_| "Packages index is not UTF-8".to_string())?
        .replace("\r\n", "\n");
    let (_canonical_root, package_root) = package_root(root)?;
    let mut seen = HashSet::<String>::new();
    let mut casefolded_paths = HashMap::<String, String>::new();
    let mut count = 0usize;
    for entry in text.split("\n\n") {
        if entry.trim().is_empty() {
            continue;
        }
        let mut fields = HashMap::<String, String>::new();
        let mut previous_key: Option<String> = None;
        for line in entry.lines() {
            if line.starts_with([' ', '\t']) {
                let key = previous_key
                    .as_deref()
                    .ok_or_else(|| "Orphan continuation line in Packages index".to_string())?;
                if matches!(
                    key,
                    "package" | "version" | "architecture" | "filename" | "size" | "sha256"
                ) {
                    return Err(format!("Folded required Packages field: {key}"));
                }
                continue;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| "Malformed Packages control field".to_string())?;
            if !valid_field_name(key) {
                return Err("Invalid Packages control field name".into());
            }
            let key = key.to_ascii_lowercase();
            if fields
                .insert(key.clone(), value.trim().to_string())
                .is_some()
            {
                return Err(format!("Duplicate Packages control field: {key}"));
            }
            previous_key = Some(key);
        }

        let required = |key: &str| {
            fields
                .get(key)
                .filter(|value| !value.is_empty())
                .map(String::as_str)
                .ok_or_else(|| format!("Missing or empty {key} field"))
        };
        if let Some(depiction) = fields.get("depiction") {
            check_site_reference(root, "Depiction", depiction)?;
        }
        if let Some(icon) = fields.get("icon") {
            check_site_reference(root, "Icon", icon)?;
        }
        let package = required("package")?;
        if !valid_package_name(package) {
            return Err("Invalid Package field".into());
        }
        let version = required("version")?;
        if !valid_version(version) {
            return Err("Invalid Version field".into());
        }
        let architecture = required("architecture")?;
        if !valid_architecture(architecture) {
            return Err("Invalid Architecture field".into());
        }
        let filename = required("filename")?;
        if !package_name_is_safe(filename) {
            return Err(format!("Unsafe or missing package filename: {filename:?}"));
        }
        register_casefolded_package_path(filename, &mut casefolded_paths)?;
        if !seen.insert(filename.to_string()) {
            return Err(format!(
                "Repeated package filename in Packages: {filename:?}"
            ));
        }
        if seen.len() > MAX_PACKAGE_ARCHIVE_COUNT {
            return Err("Package archive count exceeds the configured limit".into());
        }
        let size =
            parse_decimal_u64(required("size")?).ok_or_else(|| "Invalid Size field".to_string())?;
        let expected = required("sha256")?;
        if !is_hex_digest(expected, 64) {
            return Err("Invalid SHA256 field".into());
        }
        let path = checked_package_file(&package_root, filename)?;
        if !expected.eq_ignore_ascii_case(&hash_sha256_file(&path, size, filename)?) {
            return Err(format!("Package checksum mismatch: {filename:?}"));
        }
        count += 1;
    }
    if count == 0 {
        return Err("Packages index is empty".into());
    }
    let actual = list_package_archives(&package_root)?;
    if let Some(orphan) = actual.difference(&seen).next() {
        return Err(format!("Unindexed package archive: {orphan:?}"));
    }
    if let Some(missing) = seen.difference(&actual).next() {
        return Err(format!("Indexed package archive is absent: {missing:?}"));
    }
    Ok(count)
}

fn verify(root: &Path) -> Result<usize, String> {
    for required in ["README.md", "index.html", "style.css"] {
        checked_regular_file(root, required)?;
    }
    verify_static_assets(root)?;
    verify_release(root)?;
    let plain = verify_index_parity(root)?;
    verify_packages(root, &plain)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn main() {
    match verify(&root()) {
        Ok(count) => println!(
            "Validated {} indexes and {count} package archives.",
            INDEXES.len()
        ),
        Err(error) => {
            eprintln!("Mirror verification failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    struct TestDir(PathBuf);

    impl TestDir {
        fn create(path: PathBuf) -> std::io::Result<Self> {
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder
            };
            #[cfg(not(unix))]
            let builder = fs::DirBuilder::new();
            builder.create(&path)?;
            Ok(Self(path))
        }

        fn new(prefix: &str) -> std::io::Result<Self> {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);
            for _ in 0..128 {
                let random = RandomState::new().build_hasher().finish();
                let counter = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "{prefix}-{}-{random:016x}-{counter}",
                    std::process::id()
                ));
                match Self::create(path) {
                    Ok(dir) => return Ok(dir),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate an isolated test directory",
            ))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn package_record(bytes: &[u8]) -> String {
        format!(
            "Package: example\nVersion: 1.0-1\nArchitecture: iphoneos-arm\nFilename: packages/example.deb\nSize: {}\nSHA256: {}\n",
            bytes.len(),
            digest("SHA256", bytes).unwrap()
        )
    }

    fn release_fixture(root: &Path, index_bytes: &[u8]) -> String {
        for name in INDEXES {
            fs::write(root.join(name), index_bytes).unwrap();
        }
        let mut release = String::from("Origin: fixture\n");
        for section in RELEASE_SECTIONS {
            release.push_str(&format!("{section}:\n"));
            for name in INDEXES {
                release.push_str(&format!(
                    " {} {} {}\n",
                    digest(section, index_bytes).unwrap(),
                    index_bytes.len(),
                    name
                ));
            }
        }
        fs::write(root.join("Release"), &release).unwrap();
        release
    }

    fn static_asset_fixture(root: &Path) {
        for name in STATIC_ASSET_FILES {
            fs::write(root.join(name), format!("fixture asset {name}")).unwrap();
        }
        fs::create_dir(root.join("depiction")).unwrap();
        fs::create_dir(root.join("icons")).unwrap();
        fs::create_dir(root.join("depiction/nested")).unwrap();
        fs::write(
            root.join("depiction/nested/sample.html"),
            b"sample depiction",
        )
        .unwrap();
        fs::write(root.join("icons/sample.png"), b"sample icon").unwrap();

        let mut paths: Vec<String> = collect_static_asset_paths(root)
            .unwrap()
            .into_iter()
            .collect();
        paths.sort();
        let mut manifest = String::new();
        for path in paths {
            let bytes = fs::read(root.join(&path)).unwrap();
            manifest.push_str(&format!(
                "{}\t{}\t{}\n",
                digest("SHA256", &bytes).unwrap(),
                bytes.len(),
                path
            ));
        }
        fs::write(root.join("MIRROR-ASSETS.tsv"), manifest).unwrap();
    }

    fn compress(name: &str, input: &[u8]) -> Vec<u8> {
        use std::io::Write;

        match name {
            "Packages.gz" => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(input).unwrap();
                encoder.finish().unwrap()
            }
            "Packages.bz2" => {
                let mut encoder =
                    bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                encoder.write_all(input).unwrap();
                encoder.finish().unwrap()
            }
            "Packages.xz" => {
                let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
                encoder.write_all(input).unwrap();
                encoder.finish().unwrap()
            }
            "Packages.lzma" => {
                let options = xz2::stream::LzmaOptions::new_preset(6).unwrap();
                let stream = Stream::new_lzma_encoder(&options).unwrap();
                let mut encoder = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
                encoder.write_all(input).unwrap();
                encoder.finish().unwrap()
            }
            _ => panic!("unknown test compression format"),
        }
    }

    #[test]
    fn casefolded_package_path_components_reject_directory_and_file_aliases() {
        let mut paths = HashMap::new();
        register_casefolded_package_path("packages/Case/one.deb", &mut paths).unwrap();
        let directory_error =
            register_casefolded_package_path("packages/case/two.deb", &mut paths).unwrap_err();
        assert!(directory_error.contains("collision"), "{directory_error}");

        let mut files = HashMap::new();
        register_casefolded_package_path("packages/example.deb", &mut files).unwrap();
        let file_error =
            register_casefolded_package_path("packages/EXAMPLE.deb", &mut files).unwrap_err();
        assert!(file_error.contains("collision"), "{file_error}");
    }

    #[cfg(unix)]
    #[test]
    fn case_colliding_package_directory_paths_are_rejected() {
        let root = TestDir::new("nepeta-package-case-alias").unwrap();
        let package_dir = root.path().join("packages");
        let upper_dir = package_dir.join("Case");
        let lower_dir = package_dir.join("case");
        fs::create_dir_all(&upper_dir).unwrap();
        fs::create_dir_all(&lower_dir).unwrap();

        let upper_bytes = b"synthetic uppercase path archive";
        let lower_bytes = b"synthetic lowercase path archive";
        fs::write(upper_dir.join("one.deb"), upper_bytes).unwrap();
        fs::write(lower_dir.join("two.deb"), lower_bytes).unwrap();
        let upper = package_record(upper_bytes)
            .replace("Package: example", "Package: upper")
            .replace("packages/example.deb", "packages/Case/one.deb");
        let lower = package_record(lower_bytes)
            .replace("Package: example", "Package: lower")
            .replace("packages/example.deb", "packages/case/two.deb");
        let index = format!("{upper}\n{lower}");

        let result = verify_packages(root.path(), index.as_bytes());
        assert!(
            result.is_err(),
            "case-colliding package path components were accepted: {result:?}"
        );
    }

    #[test]
    fn path_safety_rejects_cross_platform_aliases() {
        assert!(package_name_is_safe("packages/test.deb"));
        assert!(package_name_is_safe("packages/nested/test.deb"));
        for path in [
            "packages/../outside.deb",
            "packages/..\\..\\outside.deb",
            "packages/dir\\..\\outside.deb",
            "packages//test.deb",
            "packages/./test.deb",
            "packages/C:outside.deb",
            "packages/CON.deb",
            "packages/NUL.tar.gz.deb",
            "packages/CONIN$.deb",
            "packages/COM¹.deb",
            "packages/LPT³.deb",
            "packages/con .deb",
            "packages/trailing-dot..deb.",
            "packages/non-ascii-é.deb",
            "packages/bad\nname.deb",
            "packages/with\tTab.deb",
            "packages/bad?name.deb",
            "/packages/test.deb",
            "other/test.deb",
            "packages/test.zip",
        ] {
            assert!(
                !package_name_is_safe(path),
                "accepted unsafe path: {path:?}"
            );
        }
        for byte in (0u8..=0x1f).chain(std::iter::once(0x7f)) {
            let path = format!("packages/control{}character.deb", char::from(byte));
            assert!(
                !package_name_is_safe(&path),
                "accepted ASCII control byte 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn metadata_sizes_accept_only_unsigned_decimal_digits() {
        assert_eq!(parse_decimal_u64("0"), Some(0));
        assert_eq!(parse_decimal_u64("00123"), Some(123));
        for value in ["", "+1", "-1", "1.0", " 1", "1 ", "١"] {
            assert_eq!(parse_decimal_u64(value), None, "accepted size {value:?}");
        }
    }

    #[test]
    fn fixture_directory_creation_preserves_unowned_paths() {
        let parent = TestDir::new("nepeta-test-owner").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(parent.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let unowned = parent.path().join("already-exists");
        fs::create_dir(&unowned).unwrap();
        let marker = unowned.join("keep.txt");
        fs::write(&marker, b"preserve this unrelated file").unwrap();

        assert!(TestDir::create(unowned).is_err());
        assert_eq!(fs::read(marker).unwrap(), b"preserve this unrelated file");
    }

    #[test]
    fn decompression_matches_all_formats_and_caps_output() {
        use std::io::Cursor;

        let normal = b"Package: example\nVersion: 1.0-1\n";
        let expansion = vec![b'x'; 65_536];
        for name in INDEXES.iter().skip(1) {
            let encoded = compress(name, normal);
            let mut concatenated = compress(name, b"first");
            concatenated.extend(compress(name, b"second"));
            assert_eq!(
                decompressed_reader(
                    name,
                    Cursor::new(concatenated),
                    b"firstsecond".len(),
                    MAX_LZMA_MEMORY_BYTES,
                )
                .unwrap(),
                b"firstsecond",
                "did not consume concatenated {name} streams"
            );
            assert_eq!(
                decompressed_reader(
                    name,
                    Cursor::new(encoded.clone()),
                    normal.len(),
                    MAX_LZMA_MEMORY_BYTES,
                )
                .unwrap(),
                normal
            );
            let mut trailing_data = encoded.clone();
            trailing_data.extend_from_slice(b"trailing invalid bytes");
            assert!(
                decompressed_reader(
                    name,
                    Cursor::new(trailing_data),
                    normal.len(),
                    MAX_LZMA_MEMORY_BYTES,
                )
                .is_err(),
                "accepted trailing bytes after {name}"
            );
            let oversized = compress(name, &expansion);
            let error = decompressed_reader(name, Cursor::new(oversized), 8, MAX_LZMA_MEMORY_BYTES)
                .unwrap_err();
            assert!(error.contains("expands beyond"), "{name}: {error}");

            let mut truncated = encoded;
            truncated.pop();
            assert!(
                decompressed_reader(
                    name,
                    Cursor::new(truncated),
                    normal.len(),
                    MAX_LZMA_MEMORY_BYTES,
                )
                .is_err(),
                "accepted truncated {name} stream"
            );
            assert!(
                decompressed_reader(
                    name,
                    Cursor::new(b"malformed stream".to_vec()),
                    normal.len(),
                    MAX_LZMA_MEMORY_BYTES,
                )
                .is_err(),
                "accepted malformed {name} stream"
            );
        }
    }

    #[test]
    fn lzma_dictionary_memory_is_bounded() {
        use std::io::{Cursor, Write};

        let mut options = xz2::stream::LzmaOptions::new_preset(6).unwrap();
        options.dict_size(16 * 1024 * 1024);
        let stream = Stream::new_lzma_encoder(&options).unwrap();
        let mut encoder = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
        encoder.write_all(b"small synthetic LZMA payload").unwrap();
        let encoded = encoder.finish().unwrap();
        let error =
            decompressed_reader("Packages.lzma", Cursor::new(encoded), 1024, 8 * 1024 * 1024)
                .unwrap_err();
        assert!(error.to_ascii_lowercase().contains("memory"), "{error}");
    }

    #[test]
    fn compressed_stream_mutations_do_not_panic_or_exceed_output_bound() {
        use std::io::Cursor;
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let plain = b"small deterministic compression fixture";
        for name in INDEXES.iter().skip(1) {
            let encoded = compress(name, plain);
            for index in 0..encoded.len() {
                let mut mutated = encoded.clone();
                mutated[index] ^= 1 << (index % 8);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    decompressed_reader(
                        name,
                        Cursor::new(mutated),
                        plain.len(),
                        MAX_LZMA_MEMORY_BYTES,
                    )
                }));
                assert!(
                    result.is_ok(),
                    "{name} decoder panicked after byte {index} mutation"
                );
                if let Ok(Ok(output)) = result {
                    assert!(
                        output.len() <= plain.len(),
                        "{name} mutation exceeded the output bound"
                    );
                }
            }
        }
    }

    #[test]
    fn release_verifies_all_advertised_checksum_sections() {
        let root = TestDir::new("nepeta-release-checksums").unwrap();
        let good = release_fixture(root.path(), b"synthetic index");
        assert!(verify_release(root.path()).is_ok());

        for (section, zeros) in [("MD5Sum", 32), ("SHA1", 40), ("SHA512", 128)] {
            let bad = good.replace(
                &digest(section, b"synthetic index").unwrap(),
                &"0".repeat(zeros),
            );
            fs::write(root.path().join("Release"), bad).unwrap();
            assert!(
                verify_release(root.path()).is_err(),
                "accepted bad {section}"
            );
            fs::write(root.path().join("Release"), &good).unwrap();
        }

        let missing = good.replace("SHA512:\n", "");
        fs::write(root.path().join("Release"), missing).unwrap();
        assert!(verify_release(root.path()).is_err());

        let sha256 = digest("SHA256", b"synthetic index").unwrap();
        let correct_size = b"synthetic index".len();
        let correct_gzip_row = format!(" {sha256} {correct_size} Packages.gz\n");
        let missing_entry = good.replacen(&correct_gzip_row, "", 1);
        fs::write(root.path().join("Release"), missing_entry).unwrap();
        assert!(verify_release(root.path()).is_err());

        let wrong_size_row = format!(" {sha256} {} Packages.gz\n", correct_size + 1);
        let wrong_size = good.replacen(&correct_gzip_row, &wrong_size_row, 1);
        fs::write(root.path().join("Release"), wrong_size).unwrap();
        assert!(verify_release(root.path()).is_err());

        let duplicate = good.replace(
            "SHA1:\n",
            &format!(
                "SHA1:\n {} {} Packages\n",
                digest("SHA1", b"synthetic index").unwrap(),
                b"synthetic index".len()
            ),
        );
        fs::write(root.path().join("Release"), duplicate).unwrap();
        assert!(verify_release(root.path()).is_err());
    }

    #[test]
    fn package_records_validate_identity_fields_and_reject_duplicates() {
        let root = TestDir::new("nepeta-package-records").unwrap();
        fs::create_dir(root.path().join("packages")).unwrap();
        let bytes = b"fictional test archive";
        fs::write(root.path().join("packages/example.deb"), bytes).unwrap();
        let record = package_record(bytes);
        assert_eq!(verify_packages(root.path(), record.as_bytes()).unwrap(), 1);

        let mixed_case = record
            .replace("Package:", "pAcKaGe:")
            .replace("Version:", "vErSiOn:")
            .replace("Architecture:", "aRcHiTeCtUrE:")
            .replace("Filename:", "fIlEnAmE:")
            .replace("Size:", "sIzE:")
            .replace("SHA256:", "sha256:");
        assert_eq!(
            verify_packages(root.path(), mixed_case.as_bytes()).unwrap(),
            1
        );

        for invalid in [
            record.replace("Package: example\n", ""),
            record.replace("Version: 1.0-1\n", ""),
            record.replace("Architecture: iphoneos-arm\n", ""),
            record.replace("Package: example", "Package: "),
            record.replace("Version: 1.0-1", "Version: invalid"),
            record.replace("Architecture: iphoneos-arm", "Architecture: invalid/arch"),
            format!("{record}Filename: packages/example.deb\n"),
            format!("{record}fIlEnAmE: packages/example.deb\n"),
            record.replace(
                "Filename: packages/example.deb\n",
                "Filename: packages/example.deb\n packages/elsewhere.deb\n",
            ),
            format!("{record}not-a-control-field\n"),
            format!(" folded orphan\n{record}"),
            format!("{record}Depiction: ../outside.html\n"),
            format!("{record}Depiction: ./depiction/missing\n"),
            format!("{record}Icon: ./packages/example.deb\n"),
            format!("{record}Icon: ./icons/missing.png\n"),
        ] {
            assert!(verify_packages(root.path(), invalid.as_bytes()).is_err());
        }

        let description = format!("{record}Description: sample\n continued description\n");
        assert_eq!(
            verify_packages(root.path(), description.as_bytes()).unwrap(),
            1
        );

        let repeated = format!("{record}\n{record}");
        assert!(verify_packages(root.path(), repeated.as_bytes()).is_err());
        let tampered = record.replace(&digest("SHA256", bytes).unwrap(), &"0".repeat(64));
        assert!(verify_packages(root.path(), tampered.as_bytes()).is_err());
    }

    #[test]
    fn malformed_package_paths_cannot_inject_terminal_controls() {
        let root = TestDir::new("nepeta-terminal-controls").unwrap();
        fs::create_dir(root.path().join("packages")).unwrap();
        let bytes = b"fictional test archive";
        fs::write(root.path().join("packages/example.deb"), bytes).unwrap();
        let malicious =
            package_record(bytes).replace("packages/example.deb", "packages/\u{1b}[31mexample.deb");
        let error = verify_packages(root.path(), malicious.as_bytes()).unwrap_err();
        assert!(
            !error.contains('\u{1b}'),
            "raw terminal control in {error:?}"
        );
        assert!(
            error.contains("\\u{1b}"),
            "escape was not made visible: {error:?}"
        );
    }

    #[test]
    fn unindexed_and_missing_archives_fail_closed() {
        let root = TestDir::new("nepeta-package-set").unwrap();
        fs::create_dir(root.path().join("packages")).unwrap();
        let bytes = b"fictional test archive";
        fs::write(root.path().join("packages/example.deb"), bytes).unwrap();
        let record = package_record(bytes);
        fs::write(
            root.path().join("packages/orphan.deb"),
            b"unindexed synthetic archive",
        )
        .unwrap();
        assert!(verify_packages(root.path(), record.as_bytes())
            .unwrap_err()
            .contains("Unindexed package archive"));

        fs::remove_file(root.path().join("packages/orphan.deb")).unwrap();
        fs::write(
            root.path().join("packages/unindexed.DEB"),
            b"uppercase synthetic archive",
        )
        .unwrap();
        assert!(verify_packages(root.path(), record.as_bytes())
            .unwrap_err()
            .contains("Unsafe package archive path"));
        fs::remove_file(root.path().join("packages/unindexed.DEB")).unwrap();
        fs::remove_file(root.path().join("packages/example.deb")).unwrap();
        assert!(verify_packages(root.path(), record.as_bytes()).is_err());
    }

    #[test]
    fn hidden_dot_deb_cannot_escape_package_inventory() {
        let root = TestDir::new("nepeta-hidden-package-archive").unwrap();
        let package_dir = root.path().join("packages");
        fs::create_dir(&package_dir).unwrap();
        let bytes = b"fictional indexed archive";
        fs::write(package_dir.join("example.deb"), bytes).unwrap();
        let record = package_record(bytes);
        fs::write(
            package_dir.join(".deb"),
            b"unindexed hidden synthetic archive",
        )
        .unwrap();

        let error = verify_packages(root.path(), record.as_bytes()).unwrap_err();
        assert!(
            error.contains("Unindexed package archive"),
            "hidden archive was not included in the exact set check: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn trailing_dot_and_space_archives_cannot_escape_package_inventory() {
        for filename in ["orphan.deb.", "orphan.deb "] {
            let root = TestDir::new("nepeta-package-alias").unwrap();
            let package_dir = root.path().join("packages");
            fs::create_dir(&package_dir).unwrap();
            let bytes = b"fictional indexed archive";
            fs::write(package_dir.join("example.deb"), bytes).unwrap();
            let record = package_record(bytes);
            fs::write(
                package_dir.join(filename),
                b"unindexed alias synthetic archive",
            )
            .unwrap();

            let result = verify_packages(root.path(), record.as_bytes());
            assert!(
                result.is_err(),
                "unindexed filename alias {filename:?} escaped archive inventory"
            );
        }
    }

    #[test]
    fn package_tree_entry_limit_includes_directories() {
        let root = TestDir::new("nepeta-package-tree-limit").unwrap();
        let package_dir = root.path().join("packages");
        fs::create_dir(&package_dir).unwrap();
        let bytes = b"fictional indexed archive";
        fs::write(package_dir.join("example.deb"), bytes).unwrap();
        let record = package_record(bytes);

        for index in 0..MAX_PACKAGE_ARCHIVE_COUNT {
            fs::create_dir(package_dir.join(format!("empty-{index}"))).unwrap();
        }

        let error = verify_packages(root.path(), record.as_bytes()).unwrap_err();
        assert!(
            error.contains("Package directory entry count exceeds the configured limit"),
            "unexpected error for over-limit package tree: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_package_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new("nepeta-package-symlink").unwrap();
        fs::create_dir(root.path().join("packages")).unwrap();
        let bytes = b"synthetic fixture, not a real package";
        fs::write(root.path().join("outside.deb"), bytes).unwrap();
        symlink("../outside.deb", root.path().join("packages/linked.deb")).unwrap();
        let record = package_record(bytes).replace("packages/example.deb", "packages/linked.deb");
        assert!(verify_packages(root.path(), record.as_bytes()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_package_with_in_scope_target_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new("nepeta-package-internal-symlink").unwrap();
        let package_dir = root.path().join("packages");
        fs::create_dir(&package_dir).unwrap();
        let bytes = b"synthetic fixture, not a real package";
        fs::write(package_dir.join("real.deb"), bytes).unwrap();
        symlink("real.deb", package_dir.join("linked.deb")).unwrap();
        let record = package_record(bytes).replace("packages/example.deb", "packages/linked.deb");
        let error = verify_packages(root.path(), record.as_bytes()).unwrap_err();
        assert!(
            error.contains("Linked mirror path is not allowed"),
            "internal package symlink was not rejected explicitly: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_release_and_site_files_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new("nepeta-metadata-symlink").unwrap();
        fs::write(root.path().join("external-release"), "synthetic").unwrap();
        symlink("external-release", root.path().join("Release")).unwrap();
        assert!(verify_release(root.path()).is_err());

        fs::write(root.path().join("README.md"), "synthetic").unwrap();
        fs::write(root.path().join("outside-readme"), "synthetic").unwrap();
        fs::remove_file(root.path().join("README.md")).unwrap();
        symlink("outside-readme", root.path().join("README.md")).unwrap();
        assert!(checked_regular_file(root.path(), "README.md").is_err());
    }

    #[test]
    fn static_assets_require_exact_manifest_and_hashes() {
        let root = TestDir::new("nepeta-static-assets").unwrap();
        static_asset_fixture(root.path());
        assert!(verify_static_assets(root.path()).is_ok());

        fs::write(root.path().join("icons/sample.png"), b"tamper icon").unwrap();
        assert!(verify_static_assets(root.path())
            .unwrap_err()
            .contains("checksum mismatch"));

        fs::write(root.path().join("icons/sample.png"), b"sample icon").unwrap();

        fs::write(
            root.path().join("depiction/nested/sample.html"),
            b"tamper depiction",
        )
        .unwrap();
        assert!(verify_static_assets(root.path())
            .unwrap_err()
            .contains("checksum mismatch"));
        fs::write(
            root.path().join("depiction/nested/sample.html"),
            b"sample depiction",
        )
        .unwrap();

        fs::write(root.path().join("depiction/unlisted.html"), b"unlisted").unwrap();
        assert!(verify_static_assets(root.path())
            .unwrap_err()
            .contains("exact on-disk asset set"));

        fs::remove_file(root.path().join("depiction/unlisted.html")).unwrap();
        fs::remove_file(root.path().join("depiction/nested/sample.html")).unwrap();
        assert!(verify_static_assets(root.path())
            .unwrap_err()
            .contains("Unexpected static asset"));
        fs::write(
            root.path().join("depiction/nested/sample.html"),
            b"sample depiction",
        )
        .unwrap();
        fs::remove_file(root.path().join("icons/sample.png")).unwrap();
        assert!(verify_static_assets(root.path())
            .unwrap_err()
            .contains("Unexpected static asset"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_static_assets_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new("nepeta-static-symlink").unwrap();
        static_asset_fixture(root.path());
        fs::write(root.path().join("outside.png"), b"outside").unwrap();
        fs::remove_file(root.path().join("icons/sample.png")).unwrap();
        symlink("../outside.png", root.path().join("icons/linked.png")).unwrap();
        assert!(collect_static_asset_paths(root.path())
            .unwrap_err()
            .contains("Linked static asset"));
    }

    #[test]
    fn missing_root_files_fail_closed() {
        let parent = TestDir::new("nepeta-missing-root").unwrap();
        assert!(verify(&parent.path().join("missing")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn package_inventory_rejects_backslash_alias_of_nested_archive() {
        let root = TestDir::new("nepeta-package-backslash-alias").unwrap();
        let package_root = root.path().join("packages");
        let canonical_dir = package_root.join("nested");
        fs::create_dir_all(&canonical_dir).unwrap();

        let bytes = b"fictional indexed archive";
        fs::write(canonical_dir.join("alias.deb"), bytes).unwrap();
        fs::write(
            package_root.join(r"nested\alias.deb"),
            b"synthetic backslash alias",
        )
        .unwrap();
        let record =
            package_record(bytes).replace("packages/example.deb", "packages/nested/alias.deb");

        let error = verify_packages(root.path(), record.as_bytes()).unwrap_err();
        assert!(
            error.contains("Unsafe package archive path"),
            "backslash-containing archive alias was not rejected: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn static_asset_inventory_rejects_backslash_alias_of_nested_asset() {
        let root = TestDir::new("nepeta-static-backslash-alias").unwrap();
        static_asset_fixture(root.path());
        fs::write(
            root.path().join("depiction").join(r"nested\sample.html"),
            b"synthetic backslash alias",
        )
        .unwrap();

        let error = verify_static_assets(root.path()).unwrap_err();
        assert!(
            error.contains("Invalid static asset path"),
            "backslash-containing static asset alias was not rejected: {error}"
        );
    }

    #[test]
    fn live_repository_content_passes_all_checks() {
        let result = verify(&root());
        assert!(
            result.is_ok(),
            "live mirror verification failed: {result:?}"
        );
        assert_eq!(result.unwrap(), 185);
    }
}
