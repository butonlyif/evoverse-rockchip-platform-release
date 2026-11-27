import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import reassemble
from scripts import shard_addon_assets
from scripts.sign_addon import check_descriptor, sign, verify
from scripts.verify_addon_assets import verify as verify_addon_assets

D = lambda seed: "sha256:" + seed * 64  # deterministic pseudo digest (hex seed char)
TARGET = {"moduleId": "ws-e2", "carrierId": "rk3588j-evm", "boardRevision": "1"}
sha256 = lambda payload: "sha256:" + hashlib.sha256(payload).hexdigest()


def profiles_manifest():
    return {
        "schemaVersion": "1.0", "target": TARGET, "platformDescriptorDigest": D("a"),
        "profiles": [{
            "id": "generic-cli", "integration": "built-in", "languages": ["C"], "buildSystem": "cmake",
            "requiredMaterials": [], "requiredTargetCapabilities": [], "requiredTargetServices": [],
            "availableApis": ["posix-math"], "evidence": ["software qualification PASS"],
        }],
    }


def addon_assets(tmp_path):
    """Write real asset bytes and a descriptor that pins their real digests."""
    builder_payload = b"docker-archive" * 64
    bundle_payload = b"pack-bundle" * 32
    manifest_payload = json.dumps(profiles_manifest()).encode()
    profile_canonical = json.dumps(profiles_manifest(), sort_keys=True, separators=(",", ":")).encode()
    (tmp_path / "app-builder.tar").write_bytes(builder_payload)
    (tmp_path / "zlib-capability-pack.tar.gz").write_bytes(bundle_payload)
    (tmp_path / "profiles-manifest.json").write_bytes(manifest_payload)
    descriptor = {
        "schemaVersion": "1.0", "id": "rk3588-app-toolchain", "version": "2026.11.1",
        "target": TARGET, "platformDescriptorDigest": D("a"), "sysrootDigest": D("b"),
        "appBuilderDigest": sha256(builder_payload), "profileManifestDigest": sha256(profile_canonical),
        "capabilityPackDigests": {"zlib": sha256(bundle_payload)},
    }
    url = "https://github.com/example/release/download/tag.1"
    assets = [
        {"role": "app-builder", "name": "app-builder.tar", "url": f"{url}/app-builder.tar",
         "digest": sha256(builder_payload), "size": len(builder_payload)},
        {"role": "profiles-manifest", "name": "profiles-manifest.json", "url": f"{url}/profiles-manifest.json",
         "digest": sha256(manifest_payload), "size": len(manifest_payload)},
        {"role": "capability-pack", "name": "zlib-capability-pack.tar.gz",
         "url": f"{url}/zlib-capability-pack.tar.gz",
         "digest": sha256(bundle_payload), "size": len(bundle_payload)},
    ]
    document = {"descriptor": descriptor, "assets": assets}
    (tmp_path / "application-toolchain-addon-input.json").write_text(json.dumps(document))
    return document


def _rewrite_input(tmp_path, mutate):
    document = json.loads((tmp_path / "application-toolchain-addon-input.json").read_text())
    mutate(document)
    (tmp_path / "application-toolchain-addon-input.json").write_text(json.dumps(document))


def _signing_key(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    monkeypatch.setenv("PLATFORM_RELEASE_SIGN_KEY", base64.b64encode(seed).decode())
    public_path = tmp_path / "release.pub"
    public_path.write_text(key.public_key().public_bytes_raw().hex() + "\n")
    return public_path


def test_descriptor_checks():
    good = addon_assets.__globals__  # noqa: F841  (keeps helpers importable; real check below)
    document = {
        "schemaVersion": "1.0", "id": "rk3588-app-toolchain", "version": "2026.11.1",
        "target": TARGET, "platformDescriptorDigest": D("a"), "sysrootDigest": D("b"),
        "appBuilderDigest": D("c"), "profileManifestDigest": D("d"),
        "capabilityPackDigests": {"zlib": D("e")},
    }
    check_descriptor(dict(document))
    cases = [
        (lambda d: d.pop("sysrootDigest") or d, "incomplete"),
        (lambda d: d.update(extra=1) or d, "incomplete or unknown"),
        (lambda d: d.update(version="26.1.1") or d, "version is invalid"),
        (lambda d: d.update(appBuilderDigest="sha256:" + "g" * 64) or d, "appBuilderDigest is invalid"),
        (lambda d: d.update(capabilityPackDigests={"Zlib": D("e")}) or d, "capability pack digest entry is invalid"),
    ]
    for mutate, message in cases:
        with pytest.raises(ValueError, match=message):
            check_descriptor(mutate(dict(document)))


def test_sign_round_trip_and_tamper_rejection(tmp_path, monkeypatch):
    addon_assets(tmp_path)
    public_path = _signing_key(tmp_path, monkeypatch)
    input_path = tmp_path / "application-toolchain-addon-input.json"
    envelope_path = tmp_path / "application-toolchain-addon.json"
    sign(input_path, envelope_path, public_path)
    verify(envelope_path, public_path)
    envelope = json.loads(envelope_path.read_text())
    assert set(envelope) == {"descriptor", "signature"}
    envelope["descriptor"]["capabilityPackDigests"]["zlib"] = D("f")
    envelope_path.write_text(json.dumps(envelope))
    with pytest.raises(InvalidSignature):
        verify(envelope_path, public_path)


def test_verify_assets_cross_bindings(tmp_path, monkeypatch):
    addon_assets(tmp_path)
    assert verify_addon_assets(tmp_path / "application-toolchain-addon-input.json", tmp_path) == 3
    # The descriptor pins the CANONICAL digest of the profiles manifest, not the file digest.
    canonical = json.dumps(profiles_manifest(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert json.loads((tmp_path / "application-toolchain-addon-input.json").read_text())[
        "descriptor"]["profileManifestDigest"] == sha256(canonical)
    _rewrite_input(tmp_path, lambda d: d["descriptor"].update(profileManifestDigest=D("f")))
    with pytest.raises(ValueError, match="profile-manifest digest"):
        verify_addon_assets(tmp_path / "application-toolchain-addon-input.json", tmp_path)
    addon_assets(tmp_path)
    _rewrite_input(tmp_path, lambda d: d["descriptor"].update(capabilityPackDigests={"zlib": D("f")}))
    with pytest.raises(ValueError, match="capability-pack digests"):
        verify_addon_assets(tmp_path / "application-toolchain-addon-input.json", tmp_path)
    addon_assets(tmp_path)
    _rewrite_input(tmp_path, lambda d: d["assets"][1].update(size=1))
    with pytest.raises(ValueError, match="size mismatch"):
        verify_addon_assets(tmp_path / "application-toolchain-addon-input.json", tmp_path)


def test_gitee_shards_reassemble_to_signed_addon(tmp_path, monkeypatch):
    addon_assets(tmp_path)
    public_path = _signing_key(tmp_path, monkeypatch)
    envelope = tmp_path / "application-toolchain-addon.json"
    sign(tmp_path / "application-toolchain-addon-input.json", envelope, public_path)
    monkeypatch.setattr(shard_addon_assets, "CHUNK_SIZE", 7)
    output = tmp_path / "shards"
    count, parts = shard_addon_assets.shard(envelope, tmp_path, output, "addon.1", public_path)
    assert count == 4 and parts > count
    manifest = json.loads((output / "reassembly.json").read_text())
    for item in manifest["files"]:
        rebuilt = b"".join((output / part["name"]).read_bytes() for part in item["parts"])
        assert hashlib.sha256(rebuilt).hexdigest() == item["sha256"]
    restored = tmp_path / "restored"
    from scripts.sign_addon import verify as verify_signed_addon
    assert reassemble.reassemble(output / "reassembly.json", output, restored, public_path,
                                 envelope_name="application-toolchain-addon.json",
                                 verify_restored=lambda out, key: verify_signed_addon(
                                     out / "application-toolchain-addon.json", key)) == 4
    publish = json.loads((output / "publish-manifest.json").read_text())
    assert publish["kind"] == "evoverse-platform-mirror-shards"
    env = dict(os.environ, GITEE_OWNER="but-only-if", GITEE_REPO="evoverse-rockchip-platform-release")
    result = subprocess.run([
        sys.executable, "scripts/publish_gitee_shards.py", "--shards-manifest",
        str(output / "publish-manifest.json"), "--assets-dir", str(output), "--tag", "addon.1",
    ], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "dry-run closure PASS" in result.stdout
