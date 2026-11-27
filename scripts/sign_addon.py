#!/usr/bin/env python3
"""Sign or verify one Application Toolchain Add-on envelope.

The Add-on envelope shape is {"descriptor", "signature"} — no state field
(unlike the platform descriptor envelope). The signed payload is the
canonical JSON of {"descriptor": ...}; the key and keyId are the same
Platform release identity (PLATFORM_RELEASE_SIGN_KEY secret,
platform-release-2026-11).
"""

import argparse
import base64
import json
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_ID = "platform-release-2026-11"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
VERSION = re.compile(r"[0-9]{4}\.[0-9]{1,2}\.[0-9]+\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check_descriptor(descriptor):
    required = {"schemaVersion", "id", "version", "target", "platformDescriptorDigest",
                "sysrootDigest", "appBuilderDigest", "profileManifestDigest", "capabilityPackDigests"}
    if set(descriptor) != required:
        raise ValueError("addon descriptor fields are incomplete or unknown")
    if descriptor["schemaVersion"] != "1.0":
        raise ValueError("addon descriptor schema version is invalid")
    if not ID.fullmatch(descriptor["id"]) or not VERSION.fullmatch(descriptor["version"]):
        raise ValueError("addon id or version is invalid")
    target = descriptor["target"]
    if set(target) != {"moduleId", "carrierId", "boardRevision"}:
        raise ValueError("addon target fields are incomplete")
    if not all(ID.fullmatch(value) for value in target.values()):
        raise ValueError("addon target identity is invalid")
    for name in ("platformDescriptorDigest", "sysrootDigest", "appBuilderDigest", "profileManifestDigest"):
        if not DIGEST.fullmatch(descriptor[name]):
            raise ValueError(f"addon {name} is invalid")
    packs = descriptor["capabilityPackDigests"]
    if not isinstance(packs, dict):
        raise ValueError("addon capabilityPackDigests must be an object")
    if not all(ID.fullmatch(name) and DIGEST.fullmatch(digest) for name, digest in packs.items()):
        raise ValueError("addon capability pack digest entry is invalid")


def _load_key(public_path):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_path.read_text(encoding="ascii").strip()))


def sign(input_path: Path, output_path: Path, public_path: Path):
    document = json.loads(input_path.read_text(encoding="utf-8"))
    if set(document) != {"descriptor", "assets"}:
        raise ValueError("addon input must carry descriptor and assets")
    check_descriptor(document["descriptor"])
    seed = base64.b64decode(os.environ["PLATFORM_RELEASE_SIGN_KEY"], validate=True)
    if len(seed) != 32:
        raise ValueError("signing seed must contain 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    if key.public_key().public_bytes_raw() != bytes.fromhex(public_path.read_text(encoding="ascii").strip()):
        raise ValueError("signing key does not match trusted public key")
    descriptor = document["descriptor"]
    signature = key.sign(canonical({"descriptor": descriptor}))
    envelope = {"descriptor": descriptor,
                "signature": {"algorithm": "ed25519", "keyId": KEY_ID, "value": signature.hex()}}
    output_path.write_bytes(canonical(envelope) + b"\n")
    verify(output_path, public_path)


def verify(envelope_path: Path, public_path: Path):
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    if set(envelope) != {"descriptor", "signature"}:
        raise ValueError("signed addon envelope fields are invalid")
    check_descriptor(envelope["descriptor"])
    signature = envelope["signature"]
    if set(signature) != {"algorithm", "keyId", "value"}:
        raise ValueError("addon signature fields are invalid")
    if signature["algorithm"] != "ed25519" or signature["keyId"] != KEY_ID:
        raise ValueError("addon signature identity is invalid")
    _load_key(public_path).verify(bytes.fromhex(signature["value"]), canonical({"descriptor": envelope["descriptor"]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sign", "verify"))
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--public-key", type=Path, default=Path("trust/platform-release-2026-11.pub"))
    args = parser.parse_args()
    if args.mode == "sign":
        if args.output is None:
            parser.error("--output is required for sign")
        sign(args.input, args.output, args.public_key)
    else:
        verify(args.input, args.public_key)
    print("PASS")


if __name__ == "__main__":
    main()
