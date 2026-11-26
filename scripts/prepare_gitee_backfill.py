#!/usr/bin/env python3
"""Prepare verified SDK/Catalog GitHub release assets for the existing Gitee uploader."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

CHUNK = 24 * 1024 * 1024


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(product: str, tag: str, assets_dir: Path, github_json: Path, out: Path) -> None:
    if product == "sdk":
        version = tag.removeprefix("v")
        names = [f"EvoVerse-SDK-v{version}-Customer-Package.tar.gz",
                 f"EvoVerse-SDK-v{version}-Customer-Package-EN.tar.gz",
                 f"SHA256SUMS-v{version}.txt"]
        github_repo, gitee_repo = "evoverse-sdk-releases", "evoverse-sdk-releases"
    else:
        names = [f"{tag}.zip", f"{tag}.zip.sha256"]
        github_repo, gitee_repo = "evoverse-catalog-release", "evoverse-catalog-release"
    published = {a["name"]: a for a in json.loads(github_json.read_text(encoding="utf-8"))["assets"]}
    if out.exists():
        raise ValueError(f"output already exists: {out}")
    out.mkdir(parents=True)
    bundles = []
    reassembly = []
    for name in names:
        source = assets_dir / name
        if name not in published or not source.is_file():
            raise ValueError(f"missing GitHub release asset: {name}")
        size, sha = source.stat().st_size, digest(source)
        if size != published[name]["size"] or published[name]["digest"] != "sha256:" + sha:
            raise ValueError(f"GitHub asset digest drift: {name}")
        parts = []
        if size > CHUNK:
            with source.open("rb") as stream:
                index = 0
                while data := stream.read(CHUNK):
                    part_name = f"{name}.part{index:04d}"
                    (out / part_name).write_bytes(data)
                    parts.append({"name": part_name, "bytes": len(data),
                                  "sha256": hashlib.sha256(data).hexdigest()})
                    index += 1
            reassembly.append({"file": name, "bytes": size, "sha256": sha, "parts": parts})
        else:
            shutil.copyfile(source, out / name)
            parts = [{"name": name, "bytes": size, "sha256": sha}]
        bundles.append({"file": name, "bytes": size, "sha256": sha, "assets": parts})
    if reassembly:
        reassembly_path = out / "reassembly.json"
        reassembly_path.write_text(json.dumps({"schemaVersion": "1.0", "files": reassembly},
                                              sort_keys=True) + "\n", encoding="utf-8")
        size, sha = reassembly_path.stat().st_size, digest(reassembly_path)
        bundles.append({"file": "reassembly.json", "bytes": size, "sha256": sha,
                        "assets": [{"name": "reassembly.json", "bytes": size, "sha256": sha}]})
    github_url = f"https://github.com/butonlyif/{github_repo}/releases/tag/{tag}"
    gitee_url = f"https://gitee.com/but-only-if/{gitee_repo}/releases/tag/{tag}"
    if product == "catalog":
        body = (f"EvoVerse Catalog {tag}. Gitee assets contain the ZIP in ordered 24 MiB parts. "
                "Download all parts and reassembly.json, concatenate the listed parts in order, "
                f"then verify the ZIP SHA-256 recorded in reassembly.json. Direct ZIP: {github_url}. "
                f"Catalog {tag} is also available from the signed SDK catalog sync route.")
    else:
        body = (f"EvoVerse SDK {tag}. Download one language package and verify it with "
                f"SHA256SUMS-{tag}.txt. Matching GitHub release: {github_url}. "
                "Platform hardware flashing and NPU execution remain unqualified without a board.")
    manifest = {"schemaVersion": "1.0", "kind": "evoverse-public-release-assets",
                "mirrorTag": tag, "sourceChannel": {"repository": f"butonlyif/{github_repo}", "tag": tag},
                "releaseName": f"EvoVerse {'SDK' if product == 'sdk' else 'Catalog'} {tag}",
                "releaseBody": body, "prerelease": False, "bundles": bundles}
    (out / "publish-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    print(f"prepared {product} {tag}: {sum(len(b['assets']) for b in bundles)} upload assets -> {gitee_url}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("product", choices=("sdk", "catalog"))
    parser.add_argument("tag")
    parser.add_argument("assets_dir", type=Path)
    parser.add_argument("github_json", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    prepare(args.product, args.tag, args.assets_dir, args.github_json, args.out)


if __name__ == "__main__":
    main()
