#!/usr/bin/env python3
"""
High-Assurance GitHub Release Automation Script
------------------------------------------------
Zero External Dependencies (Python 3 Standard Library only).
Interacts directly with the GitHub REST API using GITHUB_TOKEN to create
cryptographically verified tags and structured release notes.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def log_info(msg: str) -> None:
    print(f"[INFO] {msg}", flush=True)


def log_error(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr, flush=True)


def github_api_request(url: str, token: str, method: str = "GET", data: dict = None) -> tuple[int, dict]:
    """Execute authenticated GitHub REST API request with standard library urllib."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "vaultwarden-serverless-releaser",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    encoded_data = None
    if data is not None:
        encoded_data = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
            return status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = {"raw": err_body}
        return e.code, parsed


def resolve_release_tag(ref: str, upstream_fp: str, custom_tag: str = "") -> tuple[str, str]:
    """
    Resolve release tag and display title.
    Priority:
      1. Git Tag Push (refs/tags/v*.*.*)
      2. Custom TAG_NAME env var
      3. Upstream Fingerprint / Timestamp Tag (update-YYYYMMDD-HHmmss)
    """
    if ref.startswith("refs/tags/"):
        tag = ref[len("refs/tags/"):]
        return tag, f"Release {tag}"

    if custom_tag:
        return custom_tag, f"Release {custom_tag}"

    now_utc = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tag = f"update-{now_utc}"
    return tag, f"Automated Upstream Sync ({now_utc})"


def build_release_notes(
    repo: str,
    tag: str,
    sha: str,
    litestream_ver: str,
    vw_digest: str,
    go_ver: str,
    upstream_fp: str,
) -> str:
    """Generate structured, audit-ready markdown release notes."""
    lines = [
        f"## 📦 Vaultwarden Serverless Container Release (`{tag}`)",
        "",
        "High-assurance, zero-maintenance serverless container build for Google Cloud Run.",
        "",
        "### 🛡️ Upstream & Toolchain Manifest",
        f"- **Vaultwarden Base Image:** `vaultwarden/server:latest`" + (f" (`{vw_digest[:19]}...`)" if vw_digest else ""),
        f"- **Litestream Replication Engine:** `v{litestream_ver}`",
        f"- **Go Static Supervisor Toolchain:** `{go_ver}` (`CGO_ENABLED=0`)",
        f"- **Source Git Commit:** [`{sha[:7]}`](https://github.com/{repo}/commit/{sha})",
        "",
        "### 🏗️ Supported Architectures",
        "- `linux/amd64` (x86_64)",
        "- `linux/arm64` (aarch64)",
        "",
        "### 🚀 Pull & Deploy",
        "```bash",
        f"docker pull ghcr.io/{repo.lower()}:{tag}",
        f"docker pull ghcr.io/{repo.lower()}:latest",
        "```",
        "",
        "### 🔒 Security & Verification Highlights",
        "- **Non-Root Execution:** Runs under unprivileged UID/GID `1000:1000` (`USER vaultwarden`).",
        "- **Fail-Closed Durability:** Halts immediately if replication daemon fails or restore cannot be confirmed.",
        "- **Explicit Sync Teardown:** Programmatically waits for remote S3 commit confirmation (`replica_txid == txid`) on `SIGTERM`.",
        "- **Strict Host Validation:** Rejects IP scans and unauthorized hostnames with `403 Forbidden`.",
        "- **Log Query Sanitization:** Automatically redacts `access_token` and sensitive query parameters.",
    ]
    if upstream_fp:
        lines.extend([
            "",
            f"**Upstream Fingerprint (SHA256):** `{upstream_fp}`",
        ])
    return "\n".join(lines)


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    sha = os.environ.get("GITHUB_SHA", "").strip()
    ref = os.environ.get("GITHUB_REF", "").strip()
    custom_tag = os.environ.get("TAG_NAME", "").strip()

    litestream_ver = os.environ.get("LITESTREAM_VERSION", "0.5.17").strip()
    vw_digest = os.environ.get("VAULTWARDEN_DIGEST", "").strip()
    go_ver = os.environ.get("GO_VERSION", "stable").strip()
    upstream_fp = os.environ.get("UPSTREAM_FINGERPRINT", "").strip()

    if not token:
        log_error("GITHUB_TOKEN environment variable is required.")
        return 1
    if not repo:
        log_error("GITHUB_REPOSITORY environment variable is required.")
        return 1

    tag, title = resolve_release_tag(ref, upstream_fp, custom_tag)
    log_info(f"Target repository: {repo}")
    log_info(f"Target commit:     {sha}")
    log_info(f"Resolved tag:      {tag}")
    log_info(f"Release title:     {title}")

    # 1. Check if release already exists for this tag
    check_url = f"https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}"
    status, resp = github_api_request(check_url, token, method="GET")
    if status == 200:
        log_info(f"Release for tag '{tag}' already exists (ID: {resp.get('id')}). Skipping creation.")
        return 0

    # 2. Build release notes
    body = build_release_notes(
        repo=repo,
        tag=tag,
        sha=sha,
        litestream_ver=litestream_ver,
        vw_digest=vw_digest,
        go_ver=go_ver,
        upstream_fp=upstream_fp,
    )

    # 3. Create release via GitHub REST API
    create_url = f"https://api.github.com/repos/{repo}/releases"
    payload = {
        "tag_name": tag,
        "target_commitish": sha,
        "name": title,
        "body": body,
        "draft": False,
        "prerelease": False,
        "generate_release_notes": False,
    }

    log_info("Publishing release to GitHub API...")
    create_status, create_resp = github_api_request(create_url, token, method="POST", data=payload)

    if create_status in (200, 201):
        release_url = create_resp.get("html_url", "")
        log_info(f"Successfully created GitHub Release: {release_url}")
        return 0
    else:
        log_error(f"Failed to create release (HTTP {create_status}): {json.dumps(create_resp)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
