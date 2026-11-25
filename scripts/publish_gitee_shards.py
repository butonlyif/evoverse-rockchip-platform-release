#!/usr/bin/env python3
"""Publish Platform Development release assets as verified Gitee shards.

把「分片清单 + 本地分片文件」以 publish-gitee.sh 同款语义（幂等 / 不可变 /
失败回滚 / 创建即公开）发布为一个 Gitee release。为 BSP 镜像而建（docs/
release.md §1 L2 + §2 R1 升级：实测单附件上限 32 MiB，>上限对象必须分片），
对任意「清单驱动资产集」通用。

清单（--shards-manifest）schema（本工具消费的权威输入）：

    {
      "schemaVersion": "1.0",
      "kind": "evoverse-bsp-mirror-shards",
      "mirrorTag": "<release tag>",
      "sourceChannel": {...},
      "assembly": "concatenate bundles[].assets[] in order; sha256(concat) == bundles[].sha256; do not trust filenames",
      "bundles": [
        {"file": "kernel.bundle", "bytes": N, "sha256": "<64hex>",
         "assets": [{"name": "<upload name>", "bytes": N, "sha256": "<64hex>"}, ...]}
      ]
    }

上传承诺集合 = ∪ bundles[].assets[].name ∪ {"SHA256SUMS"}（本工具生成、
扁平名版；不含自身条目）。

语义（与 scripts/publish-gitee.sh 一致，契约基础 = 实测 F1–F10）：
  本地闭包先行：逐资产重算 sha256 与清单比对，任一不符 → 网络之前 fail
        closed（exit 1，远端零写入）。
  创建即公开：Gitee v5 无 draft（F2）——POST /releases 需 target_commitish
        （F1：显式 --target-commitish 或 GET /repos default_branch）。
  幂等：同 tag 已存在 → 逐资产 token 下载比对（同字节 skip；异字节 fail
        closed 绝不替换——F4 同名重传并存且服务首传字节）。
  不可变：任何「同名异字节」绝不替换；身份是 sha256 digest，不是文件名。
  失败即回滚：仅回滚**本运行创建的** release（DELETE + 公开列表复核）；
        tag 残留记 TAG_CLEANUP_REQUIRED（F9：API 删不掉 tag）。
  终态互等：远端资产名多重集合 == 上传承诺集合 ∪ {<tag>.zip, <tag>.tar.gz}
        （恰这两个自动源码归档豁免，F3）。
  逐资产回下载校验：每个本运行上传的资产，token 下载（302 跟随且**不带**
        凭据访问签名 URL）后 bytes + sha256 双比对。

证据：--evidence JSON（原子写；token 只记 sha256 前 12 位指纹，全文 scrub）。

退出码：0 成功；1 fail-closed（含回滚）；2 usage。
边界：本地 fixture 测试只证明工具行为契约，不构成新的真实 Gitee 证据。
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

API_DEFAULT = "https://gitee.com/api/v5"
PROBE_EVIDENCE_REF = "Linux Dev Gitee API probe, 2026-11-14"
CHUNK = 1024 * 1024


def die(msg, code=2):
    print("publish-gitee-shards: %s" % msg, file=sys.stderr)
    sys.exit(code)


def parse_args(argv):
    opts = {"manifest": None, "assets_dir": None, "tag": None, "yes": False,
            "target_commitish": None, "no_rollback": False, "evidence": None}
    it = iter(argv)
    for a in it:
        if a == "--shards-manifest":
            opts["manifest"] = next(it, None)
        elif a == "--assets-dir":
            opts["assets_dir"] = next(it, None)
        elif a == "--tag":
            opts["tag"] = next(it, None)
        elif a == "--yes":
            opts["yes"] = True
        elif a == "--target-commitish":
            opts["target_commitish"] = next(it, None)
        elif a == "--no-rollback":
            opts["no_rollback"] = True
        elif a == "--evidence":
            opts["evidence"] = next(it, None)
        else:
            usage()
    for k in ("manifest", "assets_dir", "tag"):
        if not opts.get(k):
            usage()
    return opts


def usage():
    sys.stderr.write(
        "usage: GITEE_TOKEN=<token> GITEE_OWNER=<o> GITEE_REPO=<r> \\\n"
        "  scripts/publish_gitee_shards.py --shards-manifest <json> \\\n"
        "    --assets-dir <dir> --tag <tag> [--yes]\n"
        "    [--target-commitish <ref>|GITEE_TARGET_COMMITISH]\n"
        "    [--no-rollback] [--evidence <path.json>]\n"
        "  dry-run (no --yes): closure check only, zero network writes.\n"
        "  exit: 0 ok, 1 fail-closed, 2 usage\n")
    sys.exit(2)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path):
    try:
        m = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as e:
        die("cannot read shards manifest %s: %s" % (path, e), 1)
    if m.get("kind") != "evoverse-platform-mirror-shards":
        die("manifest kind must be evoverse-platform-mirror-shards", 1)
    if not isinstance(m.get("bundles"), list) or not m["bundles"]:
        die("manifest bundles[] missing/empty", 1)
    for b in m["bundles"]:
        for k in ("file", "bytes", "sha256", "assets"):
            if k not in b:
                die("bundle entry missing %s" % k, 1)
        if not b["assets"]:
            die("bundle %s has no assets" % b["file"], 1)
    names = [a["name"] for b in m["bundles"] for a in b["assets"]]
    if len(set(names)) != len(names):
        die("duplicate asset names in manifest", 1)
    return m


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable urllib's auto-follow: real gitee serves a TWO-hop 302 chain
    (browser_download_url -> attach_files/<id>/download/<name> HTML hop ->
    foruda signed URL). Auto-follow stops at the HTML hop and hands back the
    wrong bytes; manual hop-by-hop (below) matches `curl -L` semantics and
    lets download_follow decide where credentials travel."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self, base, token, timeout=600):
        self.base = base.rstrip("/")
        self.root = re.sub(r"/api/v5$", "", self.base)
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect())

    def request(self, method, url, headers=None, data=None, auth=True,
                max_redirect=3):
        h = dict(headers or {})
        # gitee's WAF gates asset downloads by User-Agent (measured matrix
        # 2026-11-14: curl UA -> 302 chain works; Mozilla / product /
        # python-urllib UA -> flat 403 on the same URL+token). Send curl UA.
        h.setdefault("User-Agent", "curl/8.5.0")
        if auth and self.token:
            h["Authorization"] = "token %s" % self.token
        for _ in range(max_redirect + 1):
            req = urllib.request.Request(url, data=data, headers=h,
                                         method=method)
            try:
                resp = self.opener.open(req, timeout=self.timeout)
                return resp.status, dict(resp.headers), resp.read()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers or {}), e.read()
            except urllib.error.URLError as e:
                return 0, {}, str(e.reason).encode()

    def download_follow(self, url):
        # Real gitee (measured 2026-11-14): browser_download_url -> 302 ->
        # attach_files/<id>/download/<name> (SAME host, still needs auth on a
        # private repo) -> 302 -> foruda signed URL (cross-host, no auth
        # needed). Follow hop-by-hop: keep credentials on same-host hops,
        # strip them on cross-host hops; never trust the final URL bytes
        # without the digest check.
        status, headers, body = self.request("GET", url, auth=True)
        hops = 0
        cur = url
        while status in (301, 302, 303, 307, 308) and hops < 4:
            loc = headers.get("Location") or ""
            if not loc:
                break
            if loc.startswith("/"):
                m = re.match(r"^[a-z]+://[^/]+", cur)
                loc = m.group(0) + loc if m else loc
            same_host = urlparse(loc).netloc == urlparse(cur).netloc
            status, headers, body = self.request("GET", loc, auth=same_host)
            hops += 1
            cur = loc
        return status, body


def multipart(field, filename, content, boundary):
    parts = [
        ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
         "Content-Type: application/octet-stream\r\n\r\n" % (boundary, field, filename)).encode(),
        content,
        ("\r\n--%s--\r\n" % boundary).encode(),
    ]
    return b"".join(parts)


def main():
    opts = parse_args(sys.argv[1:])
    owner = os.environ.get("GITEE_OWNER", "")
    repo = os.environ.get("GITEE_REPO", "")
    token = os.environ.get("GITEE_TOKEN", "")
    api_base = os.environ.get("GITEE_API_BASE", API_DEFAULT)
    if not owner or not repo:
        die("GITEE_OWNER / GITEE_REPO required", 2)
    if opts["yes"] and not token:
        die("--yes requires GITEE_TOKEN (downloads/uploads need an identity, F5)", 2)

    manifest = load_manifest(opts["manifest"])
    assets_dir = opts["assets_dir"]
    tag = opts["tag"]

    upload = []  # [(name, path, bytes, sha256)] in manifest order
    failures = []
    for b in manifest["bundles"]:
        for a in b["assets"]:
            p = os.path.join(assets_dir, a["name"])
            if not os.path.isfile(p):
                failures.append({"asset": a["name"], "problem": "missing local file"})
                continue
            size = os.path.getsize(p)
            if size != a["bytes"]:
                failures.append({"asset": a["name"],
                                 "problem": "size mismatch (manifest %d, local %d)" % (a["bytes"], size)})
                continue
            d = sha256_file(p)
            if d != a["sha256"]:
                failures.append({"asset": a["name"],
                                 "problem": "sha256 mismatch (manifest %s, local %s)" % (a["sha256"], d)})
                continue
            upload.append((a["name"], p, size, d))
    if failures:
        write_evidence(opts, owner, repo, tag, token, api_base, "FAIL", False,
                       0, 0, 0, failures, [], {"attempted": False, "releaseDeleted": False})
        for f in failures:
            print("publish-gitee-shards: closure FAIL: %s: %s" % (f["asset"], f["problem"]),
                  file=sys.stderr)
        die("local closure failed before any network request (fail closed)", 1)

    sha_names = sorted(u[0] for u in upload)
    sha_body = "".join("%s  %s\n" % (u[3], u[0]) for u in sorted(upload, key=lambda x: x[0]))
    upload_names = sha_names + ["SHA256SUMS"]

    if not opts["yes"]:
        write_evidence(opts, owner, repo, tag, token, api_base, "PASS", False,
                       0, 0, 0, [], [], {"attempted": False, "releaseDeleted": False})
        print("publish-gitee-shards: dry-run closure PASS (%d assets planned, "
              "zero network writes)" % (len(upload) + 1))
        return

    api = Api(api_base, token)
    fp = hashlib.sha256(token.encode()).hexdigest()[:12] if token else None
    created_here = False
    release = None
    rollback = {"attempted": False, "releaseDeleted": False}
    uploaded = preexisting = verified = 0
    blockers = []

    def try_rollback(rel):
        if opts["no_rollback"] or rel is None:
            return
        rollback["attempted"] = True
        st, _, _ = api.request("DELETE", "%s/repos/%s/%s/releases/%s"
                               % (api.base, owner, repo, rel["id"]))
        rollback["releaseDeleted"] = 200 <= st < 300
        if not rollback["releaseDeleted"]:
            blockers.append("rollback DELETE failed with HTTP %s" % st)

    # --- locate or create the release (create is public immediately, F2) ----
    # Real Gitee: 404 for a missing tag. The local fixture (fake-gitee-api.py)
    # returns 200 with a JSON null body instead — both shapes mean "not found".
    st, _, body = api.request("GET", "%s/repos/%s/%s/releases/tags/%s"
                              % (api.base, owner, repo, tag))
    release = None
    if 200 <= st < 300:
        try:
            release = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            release = None
    if st == 404 or (200 <= st < 300 and not isinstance(release, dict)):
        tc = opts["target_commitish"] or os.environ.get("GITEE_TARGET_COMMITISH") or ""
        if not tc:
            st2, _, body2 = api.request("GET", "%s/repos/%s/%s" % (api.base, owner, repo))
            try:
                tc = json.loads(body2.decode("utf-8", "replace")).get("default_branch") or ""
            except ValueError:
                tc = ""
            if st2 != 200 or not tc:
                write_evidence(opts, owner, repo, tag, token, api_base, "PASS", False,
                               0, 0, 0, [], ["cannot resolve default_branch; pass --target-commitish"],
                               rollback)
                die("cannot resolve default_branch (HTTP %s); pass --target-commitish" % st2, 1)
        data = json.dumps({"tag_name": tag, "name": tag,
                           "body": "EvoVerse Platform Development candidate mirror (UNQUALIFIED_NO_BOOT). "
                                   "Reassemble shards and verify the signed descriptor; no board boot or NPU execution was tested.",
                           "prerelease": True, "target_commitish": tc}).encode()
        st, _, body = api.request("POST", "%s/repos/%s/%s/releases" % (api.base, owner, repo),
                                  headers={"Content-Type": "application/json"}, data=data)
        if not (200 <= st < 300):
            write_evidence(opts, owner, repo, tag, token, api_base, "PASS", False,
                           0, 0, 0, [], ["release creation failed with HTTP %s" % st], rollback)
            die("release creation failed with HTTP %s" % st, 1)
        created_here = True
        release = json.loads(body.decode("utf-8", "replace"))
    elif 200 <= st < 300:
        names = [a["name"] for a in (release.get("assets") or [])]
        if len(names) != len(set(names)):
            write_evidence(opts, owner, repo, tag, token, api_base, "PASS", True,
                           0, 0, 0, [], ["duplicate asset entries already present (F4 pollution)"],
                           rollback)
            die("release already has duplicate asset names (fail closed)", 1)
    else:
        write_evidence(opts, owner, repo, tag, token, api_base, "PASS", False,
                       0, 0, 0, [], ["GET /releases/tags failed with HTTP %s" % st], rollback)
        die("cannot locate release by tag (HTTP %s)" % st, 1)

    rel_id = release["id"]
    remote = {a["name"]: a for a in (release.get("assets") or [])}

    boundary = "evoverseshards%s" % hashlib.sha256(tag.encode()).hexdigest()[:16]

    def finish_fail(msg, name=None):
        if name:
            failures.append({"asset": name, "problem": msg})
        else:
            blockers.append(msg)
        try_rollback(release)
        write_evidence(opts, owner, repo, tag, token, api_base, "PASS", False,
                       uploaded, preexisting, verified, failures, blockers, rollback)
        die(msg, 1)

    # --- per-asset attach / idempotent skip ---------------------------------
    for name, path, size, digest in upload + [("SHA256SUMS", None, 0, "")]:
        if name == "SHA256SUMS":
            if name in remote:
                st, body = api.download_follow(remote[name]["browser_download_url"])
                got = body.decode("utf-8", "replace") if st == 200 else ""
                if st == 200 and got.strip() == sha_body.strip():
                    preexisting += 1
                    continue
                finish_fail("SHA256SUMS exists remotely with different content", name)
            data = multipart("file", name, sha_body.encode(), boundary)
        else:
            if name in remote:
                st, body = api.download_follow(remote[name]["browser_download_url"])
                if st == 200 and len(body) == size and hashlib.sha256(body).hexdigest() == digest:
                    preexisting += 1
                    continue
                finish_fail("remote asset %s differs from local bytes (immutable; "
                            "never re-upload same name)" % name, name)
            with open(path, "rb") as fh:
                content = fh.read()
            data = multipart("file", name, content, boundary)
        st, _, body = api.request(
            "POST", "%s/repos/%s/%s/releases/%s/attach_files" % (api.base, owner, repo, rel_id),
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
            data=data)
        if not (200 <= st < 300):
            finish_fail("attach_files failed for %s with HTTP %s" % (name, st), name)
        uploaded += 1

    # --- re-fetch release; per-asset download verification ------------------
    st, _, body = api.request("GET", "%s/repos/%s/%s/releases/%s" % (api.base, owner, repo, rel_id))
    if not (200 <= st < 300):
        finish_fail("GET release after upload failed with HTTP %s" % st)
    remote = json.loads(body.decode("utf-8", "replace")).get("assets") or []
    for a in remote:
        if a["name"] == "SHA256SUMS":
            continue
        local = next((u for u in upload if u[0] == a["name"]), None)
        if local is None:
            continue  # auto archives (F3) or SHA256SUMS — checked below
        st, rbody = api.download_follow(a["browser_download_url"])
        if st != 200 or len(rbody) != local[2] or hashlib.sha256(rbody).hexdigest() != local[3]:
            finish_fail("post-upload verification failed for %s" % a["name"], a["name"])
        verified += 1

    # --- end-state set equality (auto archives exempt, F3) ------------------
    names = [a["name"] for a in remote]
    expected = set(upload_names) | {"%s.zip" % tag, "%s.tar.gz" % tag}
    extra = sorted(set(names) - expected)
    missing = sorted(expected - set(names))
    dupes = sorted({n for n in names if names.count(n) > 1})
    if extra or missing or dupes:
        finish_fail("end-state mismatch; extra=%s missing=%s duplicates=%s"
                    % (extra, missing, dupes))

    write_evidence(opts, owner, repo, tag, token, api_base, "PASS", True,
                   uploaded, preexisting, verified, failures, blockers, rollback)
    print("publish-gitee-shards: release %s published: %d uploaded, %d preexisting, "
          "%d verified" % (tag, uploaded, preexisting, verified))


def write_evidence(opts, owner, repo, tag, token, api_base, closure, ok,
                   uploaded, preexisting, verified, failures, blockers, rollback):
    if not opts["evidence"]:
        return
    fp = hashlib.sha256(token.encode()).hexdigest()[:12] if token else None
    ev = {
        "schemaVersion": "1.0",
        "tool": {"name": "publish-gitee-shards", "kind": "sharded-l2-release-publisher"},
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": {"dryRun": not opts["yes"]},
        "target": {"apiBase": api_base, "owner": owner, "repo": repo, "tag": tag},
        "tokenFingerprint": {"sha256Prefix": fp, "lengthChars": len(token)} if token else None,
        "closure": closure,
        "ok": ok,
        "uploaded": uploaded,
        "preexisting": preexisting,
        "verified": verified,
        "failures": failures,
        "blockers": blockers,
        "rollback": rollback,
        "contractBasis": "measured",
        "probeEvidenceRef": PROBE_EVIDENCE_REF,
        "note": "sharded L2 for objects above the measured 32 MiB single-asset "
                "ceiling (docs/release.md §1 L2, §2 R1 escalation 2026-11-14); "
                "local fixture runs are not new real-Gitee evidence.",
    }

    def scrub(node):
        if isinstance(node, str):
            node = re.sub(r"access_token=[^&\"'\s]+", "access_token=[REDACTED]", node)
            if token:
                node = node.replace(token, "[REDACTED]")
            return node
        if isinstance(node, list):
            return [scrub(x) for x in node]
        if isinstance(node, dict):
            return {k: scrub(v) for k, v in node.items()}
        return node

    ev = scrub(ev)
    path = opts["evidence"]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(ev, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


if __name__ == "__main__":
    main()
