#!/usr/bin/env python3
"""Sign or verify one Platform Development release descriptor."""

import argparse
import base64
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_ID = "platform-release-2026-11"
REQUIRED_ROLES = {"firmware", "sysroot", "app-builder", "source-compliance"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check_descriptor(descriptor):
    if set(descriptor) != {"schemaVersion", "platform", "target", "rootfs", "compatibility", "qualification", "assets"}:
        raise ValueError("descriptor fields are incomplete or unknown")
    if descriptor["schemaVersion"] != "1.0":
        raise ValueError("descriptor schema version is invalid")
    qualification = descriptor["qualification"]
    if qualification != {"software": "PASS", "boot": "NOT_RUN", "hardware": "NOT_RUN", "reason": "NO_BOARD"}:
        raise ValueError("candidate must retain honest NO_BOARD qualification")
    roles = set()
    for asset in descriptor["assets"]:
        role = asset["role"]
        if role in roles:
            raise ValueError("duplicate asset role")
        roles.add(role)
        url = urlsplit(asset["url"])
        if (url.scheme != "https" or not url.netloc or url.username or url.password
                or url.hostname in {"localhost", "127.0.0.1"}):
            raise ValueError("asset URL is not public HTTPS")
        if not DIGEST.fullmatch(asset["digest"]) or type(asset["size"]) is not int or asset["size"] < 1:
            raise ValueError("asset digest or size is invalid")
    if not REQUIRED_ROLES <= roles:
        raise ValueError("required release asset missing")
    if not DIGEST.fullmatch(descriptor["rootfs"]["treeDigest"]):
        raise ValueError("rootfs digest is invalid")
    sysroot = next(asset for asset in descriptor["assets"] if asset["role"] == "sysroot")
    if sysroot.get("rootfsTreeDigest") != descriptor["rootfs"]["treeDigest"]:
        raise ValueError("sysroot is not bound to firmware rootfs")
    if not DIGEST.fullmatch(sysroot.get("sysrootTreeDigest", "")):
        raise ValueError("sysroot tree digest is invalid")


def sign(descriptor_path, output_path, public_path):
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    check_descriptor(descriptor)
    seed = base64.b64decode(os.environ["PLATFORM_RELEASE_SIGN_KEY"], validate=True)
    if len(seed) != 32:
        raise ValueError("signing seed must contain 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    trusted = bytes.fromhex(public_path.read_text(encoding="ascii").strip())
    if key.public_key().public_bytes_raw() != trusted:
        raise ValueError("signing key does not match trusted public key")
    envelope = {"descriptor": descriptor, "state": "UNQUALIFIED_NO_BOOT"}
    signature = key.sign(canonical(envelope))
    envelope["signature"] = {"algorithm": "ed25519", "keyId": KEY_ID, "value": signature.hex()}
    output_path.write_bytes(canonical(envelope) + b"\n")
    verify(output_path, public_path)


def verify(envelope_path, public_path):
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    if set(envelope) != {"descriptor", "state", "signature"}:
        raise ValueError("signed envelope fields are invalid")
    descriptor = envelope["descriptor"]
    check_descriptor(descriptor)
    if envelope["state"] != "UNQUALIFIED_NO_BOOT":
        raise ValueError("candidate state is invalid")
    signature = envelope["signature"]
    if set(signature) != {"algorithm", "keyId", "value"}:
        raise ValueError("signature fields are invalid")
    if signature["algorithm"] != "ed25519" or signature["keyId"] != KEY_ID:
        raise ValueError("signature identity is invalid")
    signed = {"descriptor": descriptor, "state": envelope["state"]}
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_path.read_text(encoding="ascii").strip()))
    public.verify(bytes.fromhex(signature["value"]), canonical(signed))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sign", "verify"))
    parser.add_argument("descriptor", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--public-key", type=Path, default=Path("trust/platform-release-2026-11.pub"))
    args = parser.parse_args()
    if args.mode == "sign":
        if args.output is None:
            parser.error("--output is required for sign")
        sign(args.descriptor, args.output, args.public_key)
    else:
        verify(args.descriptor, args.public_key)
    print("PASS")


if __name__ == "__main__":
    main()
