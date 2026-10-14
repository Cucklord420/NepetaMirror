#!/usr/bin/env python3
"""Verify the frozen Debian/Cydia mirror without changing its archives."""

import bz2
import gzip
import hashlib
import lzma
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INDEX_FILES = ("Packages", "Packages.bz2", "Packages.gz", "Packages.lzma", "Packages.xz")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_release() -> None:
    release = (ROOT / "Release").read_text(encoding="utf-8")
    in_section = False
    found: set[str] = set()
    for line in release.splitlines():
        if line == "SHA256:":
            in_section = True
            continue
        if line and not line[0].isspace():
            in_section = False
        if not in_section or not line.strip():
            continue

        fields = line.split()
        if len(fields) != 3:
            raise ValueError(f"Invalid SHA256 record in Release: {line!r}")
        digest, size, name = fields
        if name not in INDEX_FILES:
            raise ValueError(f"Unexpected path in Release SHA256 section: {name}")
        if name in found:
            raise ValueError(f"Duplicate Release SHA256 entry: {name}")
        contents = (ROOT / name).read_bytes()
        if int(size) != len(contents) or digest.lower() != sha256(contents):
            raise ValueError(f"Invalid Release SHA256 or length for {name}")
        found.add(name)

    if found != set(INDEX_FILES):
        raise ValueError(f"Incomplete Release SHA256 section: {sorted(set(INDEX_FILES) - found)}")


def verify_compressed_indexes() -> bytes:
    plain = (ROOT / "Packages").read_bytes()
    for name, decompress in (
        ("Packages.bz2", bz2.decompress),
        ("Packages.gz", gzip.decompress),
        ("Packages.lzma", lzma.decompress),
        ("Packages.xz", lzma.decompress),
    ):
        if decompress((ROOT / name).read_bytes()) != plain:
            raise ValueError(f"{name} does not decompress to the Packages index")
    return plain


def verify_packages(plain: bytes) -> int:
    count = 0
    seen: set[str] = set()
    for entry in plain.decode("utf-8").replace("\r\n", "\n").strip().split("\n\n"):
        if not entry.strip():
            continue
        fields = {}
        for line in entry.splitlines():
            if line.startswith((" ", "\t")):
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()

        path = fields.get("Filename", "")
        if (not path.startswith("packages/")
                or ".." in Path(path).parts
                or not path.endswith(".deb")
                or Path(path).is_absolute()):
            raise ValueError(f"Unsafe or missing package filename: {path!r}")
        if path in seen:
            raise ValueError(f"Repeated package filename in Packages: {path}")
        seen.add(path)

        data = (ROOT / path).read_bytes()
        if int(fields["Size"]) != len(data) or fields["SHA256"].lower() != sha256(data):
            raise ValueError(f"Package checksum or length mismatch: {path}")
        count += 1

    if not count:
        raise ValueError("Packages index is empty")
    return count


def main() -> None:
    for required in ("README.md", "index.html", "style.css"):
        if not (ROOT / required).is_file():
            raise ValueError(f"Missing static site file: {required}")
    verify_release()
    plain = verify_compressed_indexes()
    count = verify_packages(plain)
    print(f"Validated {len(INDEX_FILES)} indexes and {count} package archives.")


if __name__ == "__main__":
    main()
