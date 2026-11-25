#!/usr/bin/env python3
"""Create the small Gitee index-release upload promise from a signed descriptor."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.sign_descriptor import verify


def write_manifest(descriptor_path, tag, output_path, public_key):
    descriptor_path = Path(descriptor_path)
    verify(descriptor_path, Path(public_key))
    with descriptor_path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    asset = {"name": descriptor_path.name, "bytes": descriptor_path.stat().st_size, "sha256": digest}
    manifest = {
        "schemaVersion": "1.0",
        "kind": "evoverse-platform-index",
        "mirrorTag": tag,
        "bundles": [{"file": asset["name"], "bytes": asset["bytes"], "sha256": digest, "assets": [asset]}],
    }
    Path(output_path).write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("descriptor", type=Path)
    parser.add_argument("tag")
    parser.add_argument("output", type=Path)
    parser.add_argument("--public-key", type=Path, default=Path("trust/platform-release-2026-11.pub"))
    args = parser.parse_args()
    print(write_manifest(args.descriptor, args.tag, args.output, args.public_key))


if __name__ == "__main__":
    main()
