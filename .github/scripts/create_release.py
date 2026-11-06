#!/usr/bin/env python3
"""
GitHub Release Automation Script
--------------------------------
Zero External Dependencies (Python 3 Standard Library only).
Interacts directly with the GitHub REST API using GITHUB_TOKEN to create
releases with accurate change summaries, repository commit logs, and
upstream (Vaultwarden / Litestream) release notes.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional


VAULTWARDEN_REPO = "dani-garcia/vaultwarden"
LITESTREAM_REPO = "benbjohnson/litestream"
METADATA_COMMENT_RE = re.compile(r"<!--\s*release-metadata:\s*(\{.*?\})\s*-->", re.DOTALL)


def log_info(msg: str) -> None:
    print(f"[INFO] {msg}", flush=True)


def log_warn(msg: str) -> None:
    print(f"[WARN] {msg}", flush=True)


def log_error(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr, flush=True)


def github_api_request(
    url: str,
    token: str = "",
    method: str = "GET",
    data: Optional[dict[str, Any]] = None,
) -> tuple[int, Any]:
    """Execute GitHub REST API request with standard library urllib."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vaultwarden-serverless-releaser",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

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
    except Exception as e:
        return 0, {"error": str(e)}


def sanitize_mentions(text: str) -> str:
    """Wrap @username mentions in backticks to avoid pinging external GitHub users."""
    return re.sub(r"(?<![`\w])@([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})\b", r"`@\1`", text)


def digests_match(d1: str, d2: str) -> bool:
    """
    Compare two container digests, supporting legacy truncated digests
    (e.g. 'sha256:4fe17f415f90...' vs full 'sha256:4fe17f415f90...').
    """
    c1 = d1.strip().removesuffix("...")
    c2 = d2.strip().removesuffix("...")
    if not c1 or not c2:
        return False
    if c1 == c2:
        return True
    min_len = min(len(c1), len(c2))
    if min_len >= 19 and (c1.startswith(c2) or c2.startswith(c1)):
        return True
    return False


def short_digest(digest: str) -> str:
    """Format a sha256 digest concisely for display."""
    clean = digest.strip().removesuffix("...")
    if not clean:
        return ""
    return f"{clean[:19]}..." if len(clean) > 19 else clean


def parse_release_metadata(release: dict[str, Any]) -> dict[str, str]:
    """
    Extract component versions and commit metadata from a previous GitHub Release object.
    Supports both embedded JSON metadata comments and legacy markdown formats.
    """
    tag = str(release.get("tag_name", "") or "").strip()
    body = str(release.get("body", "") or "")
    target_commitish = str(release.get("target_commitish", "") or "").strip()

    meta: dict[str, str] = {
        "tag": tag,
        "sha": "",
        "vw_version": "",
        "vw_digest": "",
        "litestream_version": "",
        "go_version": "",
        "fingerprint": "",
    }

    # 1. Check structured metadata comment
    m_comment = METADATA_COMMENT_RE.search(body)
    if m_comment:
        try:
            parsed = json.loads(m_comment.group(1))
            if isinstance(parsed, dict):
                for key in ("sha", "vw_version", "vw_digest", "litestream_version", "go_version", "fingerprint"):
                    val = str(parsed.get(key, "") or "").strip()
                    if val:
                        meta[key] = val
        except Exception:
            pass

    # 2. Fallback regex extraction for legacy release bodies
    if not meta["vw_digest"]:
        m_vw_dig = re.search(r"(sha256:[0-9a-fA-F]{12,64})(?:\.\.\.)?", body)
        if m_vw_dig:
            meta["vw_digest"] = m_vw_dig.group(1)

    if not meta["vw_version"]:
        m_vw_ver = re.search(
            r"dani-garcia/vaultwarden/releases/tag/v?([0-9]+\.[0-9]+\.[0-9]+)",
            body,
        )
        if m_vw_ver:
            meta["vw_version"] = m_vw_ver.group(1)

    if not meta["litestream_version"]:
        m_ls = re.search(r"Litestream(?:\s+Replication\s+Engine)?[^`\n]*`v?([0-9]+\.[0-9]+\.[0-9]+[^`]*)`", body)
        if not m_ls:
            m_ls = re.search(r"benbjohnson/litestream/releases/tag/v?([0-9]+\.[0-9]+\.[0-9]+)", body)
        if m_ls:
            meta["litestream_version"] = m_ls.group(1).lstrip("v")

    if not meta["go_version"]:
        m_go = re.search(r"Go(?:\s+Static\s+Supervisor)?\s+Toolchain[^`\n]*`(go[0-9]+\.[0-9]+(?:\.[0-9]+)?)`", body)
        if m_go:
            meta["go_version"] = m_go.group(1)

    if not meta["sha"]:
        m_sha = re.search(r"/commit/([0-9a-fA-F]{7,40})", body)
        if m_sha:
            meta["sha"] = m_sha.group(1)
        elif re.fullmatch(r"[0-9a-fA-F]{7,40}", target_commitish):
            meta["sha"] = target_commitish

    if not meta["fingerprint"]:
        m_fp = re.search(r"Upstream Fingerprint \(SHA256\):\*\*\s*`([0-9a-fA-F]{64})`", body)
        if m_fp:
            meta["fingerprint"] = m_fp.group(1)

    return meta


def fetch_previous_release(repo: str, token: str, current_tag: str) -> Optional[dict[str, str]]:
    """Fetch the most recent published release prior to current_tag."""
    url = f"https://api.github.com/repos/{repo}/releases?per_page=10"
    status, resp = github_api_request(url, token, method="GET")
    if status != 200 or not isinstance(resp, list):
        log_warn(f"Could not fetch previous releases (HTTP {status}).")
        return None

    for rel in resp:
        if not isinstance(rel, dict):
            continue
        if rel.get("draft"):
            continue
        tag_name = str(rel.get("tag_name", "") or "").strip()
        if tag_name and tag_name != current_tag:
            return parse_release_metadata(rel)
    return None


def fetch_upstream_release(upstream_repo: str, token: str, version: str = "") -> dict[str, str]:
    """
    Fetch upstream release metadata and body from GitHub Releases API.
    Tries specific version tag first (with and without 'v' prefix), then falls back to /releases/latest.
    """
    clean_ver = version.strip().lstrip("v")
    candidate_urls: list[str] = []
    if clean_ver:
        candidate_urls.append(f"https://api.github.com/repos/{upstream_repo}/releases/tags/{clean_ver}")
        candidate_urls.append(f"https://api.github.com/repos/{upstream_repo}/releases/tags/v{clean_ver}")
    candidate_urls.append(f"https://api.github.com/repos/{upstream_repo}/releases/latest")

    for url in candidate_urls:
        status, resp = github_api_request(url, token, method="GET")
        if status == 200 and isinstance(resp, dict) and resp.get("tag_name"):
            raw_tag = str(resp.get("tag_name", "")).strip()
            return {
                "tag_name": raw_tag,
                "version": raw_tag.lstrip("v"),
                "name": str(resp.get("name", "") or raw_tag).strip(),
                "html_url": str(resp.get("html_url", "") or f"https://github.com/{upstream_repo}/releases/tag/{raw_tag}"),
                "published_at": str(resp.get("published_at", "") or "").strip(),
                "body": str(resp.get("body", "") or ""),
            }

    fallback_tag = f"v{clean_ver}" if clean_ver else "latest"
    return {
        "tag_name": fallback_tag,
        "version": clean_ver,
        "name": fallback_tag,
        "html_url": f"https://github.com/{upstream_repo}/releases",
        "published_at": "",
        "body": "",
    }


def format_vaultwarden_notes(raw_body: str) -> str:
    """
    Clean and format upstream Vaultwarden release notes:
    - Strip 'New Contributors' section
    - Demote markdown headings so they nest cleanly
    - Sanitize @username mentions to prevent notification spam
    """
    if not raw_body or not raw_body.strip():
        return ""

    text = raw_body.replace("\r\n", "\n").replace("\r", "\n")

    # Remove "## New Contributors" section up to next heading or "**Full Changelog**"
    text = re.sub(
        r"(?m)^##+\s+New Contributors\s*\n(?:.*?\n)*?(?=^##+\s+|\*\*Full Changelog\*\*|\Z)",
        "",
        text,
    )

    lines: list[str] = []
    for line in text.split("\n"):
        # Demote ## headings to #### for clean nesting
        m_heading = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m_heading:
            lines.append(f"#### {m_heading.group(2).strip()}")
        else:
            lines.append(line)

    cleaned = "\n".join(lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return sanitize_mentions(cleaned)


def format_litestream_notes(raw_body: str, repo: str = LITESTREAM_REPO) -> str:
    """
    Extract and format the Changelog section from upstream Litestream release notes,
    omitting generic OS package installation and platform support boilerplate.
    Links commit hashes and PR numbers to the upstream repository.
    """
    if not raw_body or not raw_body.strip():
        return ""

    text = raw_body.replace("\r\n", "\n").replace("\r", "\n")

    # Extract "## Changelog" section if present
    m_changelog = re.search(r"(?m)^##+\s+Changelog\s*\n(.*)$", text, re.DOTALL)
    if m_changelog:
        text = m_changelog.group(1).strip()

    formatted_lines: list[str] = []
    commit_line_re = re.compile(r"^\s*[\*\-]\s+([0-9a-fA-F]{40})\s+(.*)$")

    for line in text.split("\n"):
        m_commit = commit_line_re.match(line)
        if m_commit:
            full_sha = m_commit.group(1)
            msg = m_commit.group(2).strip()
            # Link (#123) PR references
            msg = re.sub(
                r"\(#([0-9]+)\)",
                rf"([#\1](https://github.com/{repo}/pull/\1))",
                msg,
            )
            formatted_lines.append(
                f"- [`{full_sha[:7]}`](https://github.com/{repo}/commit/{full_sha}) {msg}"
            )
        else:
            m_heading = re.match(r"^(#{1,4})\s+(.*)$", line)
            if m_heading:
                formatted_lines.append(f"#### {m_heading.group(2).strip()}")
            else:
                formatted_lines.append(line)

    cleaned = "\n".join(formatted_lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return sanitize_mentions(cleaned)


def fetch_repo_commits(repo: str, token: str, base_sha: str, head_sha: str) -> list[dict[str, str]]:
    """
    Fetch commits between base_sha and head_sha for this repository.
    Uses GitHub Compare API first, with fallback to local git log.
    """
    if not base_sha or not head_sha:
        return []
    if base_sha == head_sha or head_sha.startswith(base_sha) or base_sha.startswith(head_sha):
        return []

    url = f"https://api.github.com/repos/{repo}/compare/{urllib.parse.quote(base_sha)}...{urllib.parse.quote(head_sha)}"
    status, resp = github_api_request(url, token, method="GET")
    commits: list[dict[str, str]] = []

    if status == 200 and isinstance(resp, dict) and isinstance(resp.get("commits"), list):
        for c in resp["commits"]:
            if not isinstance(c, dict):
                continue
            c_sha = str(c.get("sha", "") or "").strip()
            commit_obj = c.get("commit") or {}
            msg = str(commit_obj.get("message", "") or "").strip()
            if not c_sha or not msg:
                continue
            lines = [ln.rstrip() for ln in msg.replace("\r\n", "\n").split("\n")]
            subject = lines[0].strip()
            body = "\n".join(lines[1:]).strip()
            commits.append({
                "sha": c_sha,
                "subject": subject,
                "body": body,
                "url": str(c.get("html_url", "") or f"https://github.com/{repo}/commit/{c_sha}"),
            })
        return commits

    # Fallback to local git log if available
    try:
        out = subprocess.check_output(
            ["git", "log", "--reverse", "--format=%H%x1f%s%x1f%b%x1e", f"{base_sha}..{head_sha}"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for entry in out.split("\x1e"):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split("\x1f")
            if len(parts) >= 2:
                c_sha = parts[0].strip()
                subject = parts[1].strip()
                body = parts[2].strip() if len(parts) > 2 else ""
                commits.append({
                    "sha": c_sha,
                    "subject": subject,
                    "body": body,
                    "url": f"https://github.com/{repo}/commit/{c_sha}",
                })
    except Exception:
        pass

    return commits


def compute_changes(
    current: dict[str, str],
    previous: Optional[dict[str, str]],
    repo_commits: list[dict[str, str]],
) -> dict[str, Any]:
    """Determine which components changed compared to the previous release."""
    curr_vw_ver = current.get("vw_version", "")
    curr_vw_dig = current.get("vw_digest", "")
    curr_ls_ver = current.get("litestream_version", "")
    curr_go_ver = current.get("go_version", "")
    curr_sha = current.get("sha", "")

    if not previous:
        return {
            "has_previous": False,
            "vw_updated": True,
            "ls_updated": True,
            "go_updated": False,
            "code_updated": bool(repo_commits),
            "prev_vw_display": "—",
            "prev_ls_display": "—",
            "prev_go_display": "—",
            "prev_sha_display": "—",
        }

    prev_vw_ver = previous.get("vw_version", "")
    prev_vw_dig = previous.get("vw_digest", "")
    prev_ls_ver = previous.get("litestream_version", "")
    prev_go_ver = previous.get("go_version", "")
    prev_sha = previous.get("sha", "")

    # Vaultwarden change check
    if prev_vw_dig and curr_vw_dig:
        vw_updated = not digests_match(prev_vw_dig, curr_vw_dig)
    elif prev_vw_ver and curr_vw_ver:
        vw_updated = prev_vw_ver != curr_vw_ver
    else:
        vw_updated = False

    # If Vaultwarden digest did not change and legacy release lacked vw_version, infer same version
    if not vw_updated and not prev_vw_ver and curr_vw_ver:
        prev_vw_ver = curr_vw_ver

    ls_updated = bool(prev_ls_ver and curr_ls_ver and prev_ls_ver != curr_ls_ver)
    go_updated = bool(prev_go_ver and curr_go_ver and prev_go_ver != curr_go_ver)

    if prev_sha and curr_sha:
        code_updated = not (
            prev_sha == curr_sha
            or curr_sha.startswith(prev_sha)
            or prev_sha.startswith(curr_sha)
        )
    else:
        code_updated = bool(repo_commits)

    prev_vw_parts: list[str] = []
    if prev_vw_ver:
        prev_vw_parts.append(f"`v{prev_vw_ver}`")
    if prev_vw_dig:
        prev_vw_parts.append(f"(`{short_digest(prev_vw_dig)}`)")
    prev_vw_display = " ".join(prev_vw_parts) if prev_vw_parts else "—"

    prev_ls_display = f"`v{prev_ls_ver}`" if prev_ls_ver else "—"
    prev_go_display = f"`{prev_go_ver}`" if prev_go_ver else "—"
    prev_sha_display = f"`{prev_sha[:7]}`" if prev_sha else "—"

    return {
        "has_previous": True,
        "prev_tag": previous.get("tag", ""),
        "prev_vw_ver": prev_vw_ver,
        "prev_ls_ver": prev_ls_ver,
        "prev_go_ver": prev_go_ver,
        "prev_sha": prev_sha,
        "vw_updated": vw_updated,
        "ls_updated": ls_updated,
        "go_updated": go_updated,
        "code_updated": code_updated,
        "prev_vw_display": prev_vw_display,
        "prev_ls_display": prev_ls_display,
        "prev_go_display": prev_go_display,
        "prev_sha_display": prev_sha_display,
    }


def resolve_release_tag(ref: str, custom_tag: str = "", now: Optional[datetime] = None) -> str:
    """
    Resolve release tag.
    Priority:
      1. Git Tag Push (refs/tags/v*.*.*)
      2. Custom TAG_NAME env var
      3. UTC Timestamp Tag (update-YYYYMMDD-HHmmss)
    """
    if ref.startswith("refs/tags/"):
        return ref[len("refs/tags/"):]
    if custom_tag:
        return custom_tag
    dt = now or datetime.now(timezone.utc)
    return f"update-{dt.strftime('%Y%m%d-%H%M%S')}"


def build_release_title(
    tag: str,
    current: dict[str, str],
    changes: dict[str, Any],
    repo_commits: list[dict[str, str]],
) -> str:
    """
    Build a concise, informative release title reflecting what actually changed.
    """
    vw_ver = current.get("vw_version", "")
    ls_ver = current.get("litestream_version", "")
    go_ver = current.get("go_version", "")

    summary_parts: list[str] = []

    if changes.get("has_previous"):
        if changes.get("vw_updated"):
            prev_vw = changes.get("prev_vw_ver", "")
            if prev_vw and vw_ver and prev_vw != vw_ver:
                summary_parts.append(f"Vaultwarden v{prev_vw} → v{vw_ver}")
            elif vw_ver:
                summary_parts.append(f"Vaultwarden v{vw_ver} (image update)")
            else:
                summary_parts.append("Vaultwarden image update")

        if changes.get("ls_updated"):
            prev_ls = changes.get("prev_ls_ver", "")
            if prev_ls and ls_ver and prev_ls != ls_ver:
                summary_parts.append(f"Litestream v{prev_ls} → v{ls_ver}")
            elif ls_ver:
                summary_parts.append(f"Litestream v{ls_ver}")

        if changes.get("go_updated"):
            prev_go = changes.get("prev_go_ver", "")
            if prev_go and go_ver and prev_go != go_ver:
                summary_parts.append(f"Go {prev_go} → {go_ver}")
            elif go_ver:
                summary_parts.append(f"Go {go_ver}")

        if changes.get("code_updated"):
            if len(repo_commits) == 1:
                summary_parts.append(repo_commits[0]["subject"])
            elif len(repo_commits) > 1:
                summary_parts.append(f"{repo_commits[-1]['subject']} (+{len(repo_commits) - 1} commits)")
            else:
                summary_parts.append(f"Source update ({current.get('sha', '')[:7]})")

    if not summary_parts:
        base_parts: list[str] = []
        if vw_ver:
            base_parts.append(f"Vaultwarden v{vw_ver}")
        if ls_ver:
            base_parts.append(f"Litestream v{ls_ver}")
        if base_parts:
            summary_parts.append(" / ".join(base_parts))

    if summary_parts:
        return f"{tag}: {', '.join(summary_parts)}"
    return f"Release {tag}"


def build_release_notes(
    repo: str,
    tag: str,
    current: dict[str, str],
    changes: dict[str, Any],
    repo_commits: list[dict[str, str]],
    vw_release: dict[str, str],
    ls_release: dict[str, str],
) -> str:
    """
    Generate focused, high-signal markdown release notes containing:
    1. Component version manifest & diff against previous release
    2. Repository commits (when code changed)
    3. Upstream Vaultwarden & Litestream release notes
    """
    sha = current.get("sha", "")
    vw_ver = current.get("vw_version", "") or vw_release.get("version", "")
    vw_digest = current.get("vw_digest", "")
    ls_ver = current.get("litestream_version", "") or ls_release.get("version", "")
    go_ver = current.get("go_version", "")
    upstream_fp = current.get("fingerprint", "")

    vw_url = vw_release.get("html_url") or f"https://github.com/{VAULTWARDEN_REPO}/releases"
    ls_url = ls_release.get("html_url") or f"https://github.com/{LITESTREAM_REPO}/releases"

    vw_current_cell = f"[`v{vw_ver}`]({vw_url})" if vw_ver else "`vaultwarden/server:latest`"
    if vw_digest:
        vw_current_cell += f" (`{short_digest(vw_digest)}`)"

    ls_current_cell = f"[`v{ls_ver}`]({ls_url})" if ls_ver else "—"
    go_current_cell = f"`{go_ver}`" if go_ver else "—"
    sha_current_cell = f"[`{sha[:7]}`](https://github.com/{repo}/commit/{sha})" if sha else "—"

    has_prev = bool(changes.get("has_previous"))
    prev_tag = changes.get("prev_tag", "")
    prev_col_header = f"Previous (`{prev_tag}`)" if prev_tag else "Previous"

    def status_badge(updated: bool, label_updated: str = "⬆️ Updated") -> str:
        if not has_prev:
            return "🆕 Initial"
        return label_updated if updated else "✅ Unchanged"

    code_status = status_badge(
        bool(changes.get("code_updated")),
        f"⬆️ {len(repo_commits)} commit(s)" if repo_commits else "⬆️ Updated",
    )

    lines: list[str] = [
        "### 📋 Component Manifest",
        "",
        f"| Component | Current | {prev_col_header} | Status |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Vaultwarden** | {vw_current_cell} | {changes.get('prev_vw_display', '—')} | {status_badge(bool(changes.get('vw_updated')))} |",
        f"| **Litestream** | {ls_current_cell} | {changes.get('prev_ls_display', '—')} | {status_badge(bool(changes.get('ls_updated')))} |",
        f"| **Go Toolchain** | {go_current_cell} | {changes.get('prev_go_display', '—')} | {status_badge(bool(changes.get('go_updated')))} |",
        f"| **Supervisor Commit** | {sha_current_cell} | {changes.get('prev_sha_display', '—')} | {code_status} |",
        "",
        "```bash",
        f"docker pull ghcr.io/{repo.lower()}:{tag}",
        "```",
    ]

    # Repository commits section (when repository code changed)
    if changes.get("code_updated") and repo_commits:
        lines.extend([
            "",
            f"### 🛠️ Repository Changes (`{repo}`)",
            "",
        ])
        for c in repo_commits:
            c_sha = c["sha"][:7]
            c_url = c["url"]
            c_subj = sanitize_mentions(c["subject"])
            lines.append(f"- [`{c_sha}`]({c_url}) {c_subj}")
            if c.get("body"):
                for b_line in c["body"].split("\n"):
                    b_stripped = b_line.strip()
                    if b_stripped:
                        b_clean = sanitize_mentions(b_stripped.lstrip("-* ").strip())
                        lines.append(f"  - {b_clean}")

        if prev_tag:
            lines.extend([
                "",
                f"**Full Diff:** [`{prev_tag}...{tag}`](https://github.com/{repo}/compare/{prev_tag}...{tag})",
            ])

    # Upstream Vaultwarden Release Notes
    vw_notes = format_vaultwarden_notes(vw_release.get("body", ""))
    if vw_notes:
        vw_heading = f"Vaultwarden `v{vw_ver}`" if vw_ver else "Vaultwarden"
        lines.extend([
            "",
            f"### 🔐 Upstream Release Notes — [{vw_heading}]({vw_url})",
            "",
        ])
        if not has_prev or changes.get("vw_updated"):
            lines.append(vw_notes)
        else:
            lines.extend([
                f"<details><summary>View {vw_heading} release notes (unchanged in this build)</summary>",
                "",
                vw_notes,
                "",
                "</details>",
            ])

    # Upstream Litestream Release Notes
    ls_notes = format_litestream_notes(ls_release.get("body", ""))
    if ls_notes:
        ls_heading = f"Litestream `v{ls_ver}`" if ls_ver else "Litestream"
        lines.extend([
            "",
            f"### 🔄 Upstream Release Notes — [{ls_heading}]({ls_url})",
            "",
        ])
        if not has_prev or changes.get("ls_updated"):
            lines.append(ls_notes)
        else:
            lines.extend([
                f"<details><summary>View {ls_heading} changelog (unchanged in this build)</summary>",
                "",
                ls_notes,
                "",
                "</details>",
            ])

    # Machine-readable metadata comment for future releases
    metadata_payload = {
        "tag": tag,
        "sha": sha,
        "vw_version": vw_ver,
        "vw_digest": vw_digest,
        "litestream_version": ls_ver,
        "go_version": go_ver,
        "fingerprint": upstream_fp,
    }
    lines.extend([
        "",
        f"<!-- release-metadata: {json.dumps(metadata_payload, sort_keys=True)} -->",
    ])

    return "\n".join(lines)


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    sha = os.environ.get("GITHUB_SHA", "").strip()
    ref = os.environ.get("GITHUB_REF", "").strip()
    custom_tag = os.environ.get("TAG_NAME", "").strip()

    litestream_ver = os.environ.get("LITESTREAM_VERSION", "0.5.17").strip().lstrip("v")
    vw_version = os.environ.get("VAULTWARDEN_VERSION", "").strip().lstrip("v")
    vw_digest = os.environ.get("VAULTWARDEN_DIGEST", "").strip()
    go_ver = os.environ.get("GO_VERSION", "stable").strip()
    upstream_fp = os.environ.get("UPSTREAM_FINGERPRINT", "").strip()

    if not token:
        log_error("GITHUB_TOKEN environment variable is required.")
        return 1
    if not repo:
        log_error("GITHUB_REPOSITORY environment variable is required.")
        return 1

    tag = resolve_release_tag(ref, custom_tag)
    log_info(f"Target repository: {repo}")
    log_info(f"Target commit:     {sha}")
    log_info(f"Resolved tag:      {tag}")

    # 1. Check if release already exists for this tag
    check_url = f"https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}"
    status, resp = github_api_request(check_url, token, method="GET")
    if status == 200 and isinstance(resp, dict):
        log_info(f"Release for tag '{tag}' already exists (ID: {resp.get('id')}). Skipping creation.")
        return 0

    # 2. Fetch upstream release notes (and resolve Vaultwarden version if not provided)
    log_info("Fetching upstream Vaultwarden release notes...")
    vw_release = fetch_upstream_release(VAULTWARDEN_REPO, token, vw_version)
    if not vw_version and vw_release.get("version"):
        vw_version = vw_release["version"]

    log_info(f"Fetching upstream Litestream release notes (v{litestream_ver})...")
    ls_release = fetch_upstream_release(LITESTREAM_REPO, token, litestream_ver)
    if not litestream_ver and ls_release.get("version"):
        litestream_ver = ls_release["version"]

    current_meta = {
        "sha": sha,
        "vw_version": vw_version,
        "vw_digest": vw_digest,
        "litestream_version": litestream_ver,
        "go_version": go_ver,
        "fingerprint": upstream_fp,
    }

    # 3. Fetch previous release and repository commits since previous release
    log_info("Inspecting previous release for change comparison...")
    prev_meta = fetch_previous_release(repo, token, tag)
    repo_commits: list[dict[str, str]] = []
    if prev_meta and prev_meta.get("sha"):
        log_info(f"Previous release: {prev_meta.get('tag')} (commit {prev_meta['sha'][:7]})")
        repo_commits = fetch_repo_commits(repo, token, prev_meta["sha"], sha)
    else:
        log_info("No previous release found; generating initial release notes.")

    changes = compute_changes(current_meta, prev_meta, repo_commits)
    title = build_release_title(tag, current_meta, changes, repo_commits)
    log_info(f"Release title:     {title}")

    # 4. Build release notes
    body = build_release_notes(
        repo=repo,
        tag=tag,
        current=current_meta,
        changes=changes,
        repo_commits=repo_commits,
        vw_release=vw_release,
        ls_release=ls_release,
    )

    # 5. Create release via GitHub REST API
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

    if create_status in (200, 201) and isinstance(create_resp, dict):
        release_url = create_resp.get("html_url", "")
        log_info(f"Successfully created GitHub Release: {release_url}")
        return 0
    else:
        log_error(f"Failed to create release (HTTP {create_status}): {json.dumps(create_resp)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
