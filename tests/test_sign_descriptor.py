import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from scripts.sign_descriptor import sign, verify
from scripts.verify_assets import verify as verify_assets
from scripts import shard_assets


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


def test_asset_redownload_digest_is_checked(tmp_path):
    descriptor = candidate()
    for asset in descriptor["assets"]:
        payload = asset["role"].encode()
        (tmp_path / asset["role"]).write_bytes(payload)
        asset["size"] = len(payload)
        asset["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    descriptor_path = tmp_path / "descriptor.json"
    descriptor_path.write_text(json.dumps(descriptor))
    assert verify_assets(descriptor_path, tmp_path) == 4
    (tmp_path / "firmware").write_bytes(b"changed")
    with pytest.raises(ValueError, match="size mismatch"):
        verify_assets(descriptor_path, tmp_path)


def test_gitee_shards_reassemble_to_signed_assets(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    monkeypatch.setenv("PLATFORM_RELEASE_SIGN_KEY", base64.b64encode(seed).decode())
    public_path = tmp_path / "release.pub"
    public_path.write_text(key.public_key().public_bytes_raw().hex() + "\n")
    descriptor = candidate()
    for asset in descriptor["assets"]:
        payload = (asset["role"] * 3).encode()
        (tmp_path / asset["role"]).write_bytes(payload)
        asset["size"] = len(payload)
        asset["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(descriptor))
    envelope = tmp_path / "signed.json"
    sign(raw, envelope, public_path)
    assert verify_assets(envelope, tmp_path, public_path) == 4
    monkeypatch.setattr(shard_assets, "CHUNK_SIZE", 7)
    output = tmp_path / "shards"
    count, parts = shard_assets.shard(envelope, tmp_path, output, "candidate.1", public_path)
    assert count == 5 and parts > count
    manifest = json.loads((output / "reassembly.json").read_text())
    for item in manifest["files"]:
        rebuilt = b"".join((output / part["name"]).read_bytes() for part in item["parts"])
        assert len(rebuilt) == item["bytes"]
        assert hashlib.sha256(rebuilt).hexdigest() == item["sha256"]
    publish = json.loads((output / "publish-manifest.json").read_text())
    assert publish["kind"] == "evoverse-platform-mirror-shards"
    assert publish["bundles"][-1]["file"] == "reassembly.json"
    env = dict(os.environ, GITEE_OWNER="but-only-if", GITEE_REPO="evoverse-rockchip-platform-release")
    result = subprocess.run([
        sys.executable, "scripts/publish_gitee_shards.py", "--shards-manifest",
        str(output / "publish-manifest.json"), "--assets-dir", str(output), "--tag", "candidate.1",
    ], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "dry-run closure PASS" in result.stdout
