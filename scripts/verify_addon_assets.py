#!/usr/bin/env python3
"""Verify downloaded Add-on draft assets against the assembly input manifest.

Checks, in order:
  1. every declared asset exists with the promised size and SHA-256;
  2. the descriptor cross-binds to the assets: the app-builder digest, the
     canonical profile-manifest digest and the capability-pack bundle digests
     all equal the values the signed descriptor will pin.
Any drift fails closed before the descriptor is signed.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

from scripts.sign_addon import canonical, check_descriptor

BUNDLE_SUFFIX = "-capability-pack.tar.gz"


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def verify(input_path: Path, assets_dir: Path) -> int:
    document = json.loads(input_path.read_text(encoding="utf-8"))
    if set(document) != {"descriptor", "assets"} or not isinstance(document["assets"], list):
        raise ValueError("addon input must carry descriptor and assets[]")
    check_descriptor(document["descriptor"])
    descriptor = document["descriptor"]

    by_name = {}
    for asset in document["assets"]:
        if set(asset) != {"role", "name", "url", "digest", "size"}:
            raise ValueError(f"asset entry fields are invalid: {asset.get('role', '?')}")
        if not asset["url"].startswith("https://"):
            raise ValueError("asset URL is not public HTTPS")
        if asset["name"] in by_name:
            raise ValueError(f"duplicate asset name: {asset['name']}")
        by_name[asset["name"]] = asset

    builder = by_name.get("app-builder.tar")
    profiles = by_name.get("profiles-manifest.json")
    pack_assets = [asset for name, asset in by_name.items() if name.endswith(BUNDLE_SUFFIX)]
    if builder is None or profiles is None or not pack_assets:
        raise ValueError("required addon asset missing (app-builder.tar / profiles-manifest.json / capability pack)")

    for asset in by_name.values():
        path = assets_dir / asset["name"]
        if not path.is_file() or path.stat().st_size != asset["size"]:
            raise ValueError(f"asset size mismatch: {asset['name']}")
        if file_digest(path) != asset["digest"]:
            raise ValueError(f"asset digest mismatch: {asset['name']}")

    if builder["digest"] != descriptor["appBuilderDigest"]:
        raise ValueError("descriptor app-builder digest does not pin the asset bytes")
    manifest_value = json.loads((assets_dir / profiles["name"]).read_text(encoding="utf-8"))
    canonical_profile_digest = "sha256:" + hashlib.sha256(canonical(manifest_value)).hexdigest()
    if canonical_profile_digest != descriptor["profileManifestDigest"]:
        raise ValueError("descriptor profile-manifest digest does not match the manifest content")
    bundle_digests = {asset["name"][: -len(BUNDLE_SUFFIX)]: asset["digest"] for asset in pack_assets}
    if bundle_digests != descriptor["capabilityPackDigests"]:
        raise ValueError("descriptor capability-pack digests do not pin the bundle bytes")
    return len(document["assets"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("assets_dir", type=Path)
    args = parser.parse_args()
    print(f"PASS {verify(args.input, args.assets_dir)} assets")


if __name__ == "__main__":
    main()
