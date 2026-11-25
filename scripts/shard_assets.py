#!/usr/bin/env python3
"""Create a Gitee reassembly manifest and upload shards from signed assets."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from scripts.sign_descriptor import verify

CHUNK_SIZE = 24 * 1024 * 1024


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def shard(envelope_path, assets_dir, output_dir, tag, public_key):
    verify(envelope_path, public_key)
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    output_dir.mkdir(parents=True, exist_ok=False)
    inputs = [(Path(urlsplit(asset["url"]).path).name, asset["size"], asset["digest"][7:])
              for asset in envelope["descriptor"]["assets"]]
    inputs.append(("platform-development-release.json", envelope_path.stat().st_size, digest(envelope_path)))
    files = []
    bundles = []
    for name, expected_size, expected_digest in inputs:
        source = envelope_path if name == "platform-development-release.json" else assets_dir / name
        if source.stat().st_size != expected_size or digest(source) != expected_digest:
            raise ValueError(f"asset drift: {name}")
        parts = []
        with source.open("rb") as stream:
            index = 0
            while chunk := stream.read(CHUNK_SIZE):
                part_name = f"{name}.part{index:04d}"
                (output_dir / part_name).write_bytes(chunk)
                parts.append({"name": part_name, "bytes": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()})
                index += 1
        files.append({"file": name, "bytes": expected_size, "sha256": expected_digest, "parts": parts})
        bundles.append({"file": name, "bytes": expected_size, "sha256": expected_digest, "assets": parts})
    reassembly = {
        "schemaVersion": "1.0", "tag": tag,
        "assembly": "Concatenate each file's parts in listed order and verify bytes and SHA-256.",
        "files": files,
    }
    reassembly_path = output_dir / "reassembly.json"
    reassembly_path.write_text(json.dumps(reassembly, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    size = reassembly_path.stat().st_size
    checksum = digest(reassembly_path)
    bundles.append({"file": "reassembly.json", "bytes": size, "sha256": checksum,
                    "assets": [{"name": "reassembly.json", "bytes": size, "sha256": checksum}]})
    publish = {
        "schemaVersion": "1.0", "kind": "evoverse-platform-mirror-shards", "mirrorTag": tag,
        "sourceChannel": {"repository": "butonlyif/evoverse-rockchip-platform-release", "tag": tag},
        "assembly": reassembly["assembly"], "bundles": bundles,
    }
    (output_dir / "publish-manifest.json").write_text(
        json.dumps(publish, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return len(files), sum(len(item["parts"]) for item in files)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("envelope", type=Path)
    parser.add_argument("assets_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("tag")
    parser.add_argument("--public-key", type=Path, default=Path("trust/platform-release-2026-11.pub"))
    args = parser.parse_args()
    count, parts = shard(args.envelope, args.assets_dir, args.output_dir, args.tag, args.public_key)
    print(f"PASS {count} files, {parts} parts")


if __name__ == "__main__":
    main()
