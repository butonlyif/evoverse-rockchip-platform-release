#!/usr/bin/env python3
"""Verify downloaded candidate asset bytes against the public descriptor."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from scripts.sign_descriptor import check_descriptor, verify as verify_signature


def verify(descriptor_path, assets_dir, public_key=Path("trust/platform-release-2026-11.pub")):
    document = json.loads(Path(descriptor_path).read_text(encoding="utf-8"))
    if "signature" in document:
        verify_signature(Path(descriptor_path), Path(public_key))
        descriptor = document["descriptor"]
    else:
        descriptor = document
    check_descriptor(descriptor)
    for asset in descriptor["assets"]:
        name = Path(urlsplit(asset["url"]).path).name
        path = Path(assets_dir) / name
        if not path.is_file() or path.stat().st_size != asset["size"]:
            raise ValueError(f"asset size mismatch: {asset['role']}")
        with path.open("rb") as stream:
            digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != asset["digest"]:
            raise ValueError(f"asset digest mismatch: {asset['role']}")
    return len(descriptor["assets"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("descriptor", type=Path)
    parser.add_argument("assets_dir", type=Path)
    parser.add_argument("--public-key", type=Path, default=Path("trust/platform-release-2026-11.pub"))
    args = parser.parse_args()
    print(f"PASS {verify(args.descriptor, args.assets_dir, args.public_key)} assets")


if __name__ == "__main__":
    main()
