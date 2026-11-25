#!/usr/bin/env python3
"""Restore and verify a Gitee candidate from downloaded release shards."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.verify_assets import verify as verify_assets


def safe_name(value):
    if not isinstance(value, str) or not value or Path(value).name != value or value in (".", ".."):
        raise ValueError(f"unsafe shard or file name: {value}")
    return value


def reassemble(manifest_path, shards_dir, output_dir, public_key):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != "1.0" or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid reassembly manifest")
    shards_dir = Path(shards_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    names = set()
    for item in manifest["files"]:
        name = safe_name(item["file"])
        if name in names:
            raise ValueError(f"duplicate file: {name}")
        names.add(name)
        temporary = output_dir / (name + ".partial")
        whole = hashlib.sha256()
        size = 0
        try:
            with temporary.open("wb") as target:
                for part in item["parts"]:
                    part_name = safe_name(part["name"])
                    source = shards_dir / part_name
                    part_hash = hashlib.sha256()
                    part_size = 0
                    with source.open("rb") as stream:
                        while chunk := stream.read(1024 * 1024):
                            target.write(chunk)
                            whole.update(chunk)
                            part_hash.update(chunk)
                            size += len(chunk)
                            part_size += len(chunk)
                    if part_size != part["bytes"] or part_hash.hexdigest() != part["sha256"]:
                        raise ValueError(f"part digest or size mismatch: {part_name}")
            if size != item["bytes"] or whole.hexdigest() != item["sha256"]:
                raise ValueError(f"file digest or size mismatch: {name}")
            temporary.replace(output_dir / name)
        finally:
            temporary.unlink(missing_ok=True)
    if "platform-development-release.json" not in names:
        raise ValueError("signed descriptor missing")
    verified = verify_assets(output_dir / "platform-development-release.json", output_dir, public_key)
    if verified != len(names) - 1:
        raise ValueError("manifest file set differs from signed descriptor")
    return len(names)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("shards_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--public-key", type=Path, default=Path("trust/platform-release-2026-11.pub"))
    args = parser.parse_args()
    print(f"PASS {reassemble(args.manifest, args.shards_dir, args.output_dir, args.public_key)} restored files")


if __name__ == "__main__":
    main()
