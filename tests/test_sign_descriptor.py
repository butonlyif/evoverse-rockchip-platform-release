import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from scripts.sign_descriptor import sign, verify


def candidate():
    rootfs_digest = "sha256:" + "a" * 64
    return {
        "schemaVersion": "1.0",
        "platform": {"id": "rk3588-platform-development", "version": "2026.11.24", "sourceRevision": "b" * 40},
        "target": {"moduleId": "ws-e2", "carrierId": "rk3588j-evm", "boardRevision": "1"},
        "rootfs": {"treeDigest": rootfs_digest, "abi": "aarch64-linux-gnu", "glibc": "2.44"},
        "compatibility": {"toolchain": "gcc-13", "rknnToolkit": "2.2.0", "rknnRuntime": "2.2.0", "rknpuDriver": "0.9.8", "npuPlatform": "rk3588"},
        "qualification": {"software": "PASS", "boot": "NOT_RUN", "hardware": "NOT_RUN", "reason": "NO_BOARD"},
        "assets": [
            {"role": role, "url": f"https://github.com/example/{role}", "digest": "sha256:" + "c" * 64, "size": 1,
             **({"rootfsTreeDigest": rootfs_digest, "sysrootTreeDigest": "sha256:" + "d" * 64} if role == "sysroot" else {})}
            for role in ("firmware", "sysroot", "app-builder", "source-compliance")
        ],
    }


def test_sign_round_trip_and_tamper_rejection(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    monkeypatch.setenv("PLATFORM_RELEASE_SIGN_KEY", base64.b64encode(seed).decode())
    public_path = tmp_path / "release.pub"
    public_path.write_text(key.public_key().public_bytes_raw().hex() + "\n")
    descriptor_path = tmp_path / "descriptor.json"
    descriptor_path.write_text(json.dumps(candidate()))
    envelope_path = tmp_path / "envelope.json"
    sign(descriptor_path, envelope_path, public_path)
    verify(envelope_path, public_path)
    envelope = json.loads(envelope_path.read_text())
    envelope["descriptor"]["assets"][0]["url"] += "-changed"
    envelope_path.write_text(json.dumps(envelope))
    with pytest.raises(InvalidSignature):
        verify(envelope_path, public_path)


def test_localhost_cannot_be_signed(tmp_path, monkeypatch):
    descriptor = candidate()
    descriptor["assets"][0]["url"] = "https://localhost/firmware.img"
    path = tmp_path / "descriptor.json"
    path.write_text(json.dumps(descriptor))
    monkeypatch.setenv("PLATFORM_RELEASE_SIGN_KEY", base64.b64encode(bytes(32)).decode())
    with pytest.raises(ValueError, match="public HTTPS"):
        sign(path, tmp_path / "signed.json", tmp_path / "missing.pub")
