#!/usr/bin/env python3
"""Unit tests for .github/scripts/create_release.py."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import create_release as cr  # noqa: E402


class TestCreateRelease(unittest.TestCase):
    def test_sanitize_mentions(self):
        raw = "Fixed by @dani-garcia and @benbjohnson in PR #123 (email test@example.com)."
        sanitized = cr.sanitize_mentions(raw)
        self.assertIn("`@dani-garcia`", sanitized)
        self.assertIn("`@benbjohnson`", sanitized)
        self.assertIn("test@example.com", sanitized)

    def test_digests_match_legacy_truncated(self):
        full = "sha256:4fe17f415f90abcdef1234567890abcdef1234567890abcdef1234567890abcd"
        truncated = "sha256:4fe17f415f90..."
        other = "sha256:efb3cde96201..."
        self.assertTrue(cr.digests_match(full, truncated))
        self.assertTrue(cr.digests_match(truncated, full))
        self.assertFalse(cr.digests_match(full, other))

    def test_parse_legacy_release_metadata(self):
        legacy_release = {
            "tag_name": "update-20261103-184637",
            "target_commitish": "a880bc4ee1f0490297a132e6cba1e77357b4a952",
            "body": (
                "## 📦 Vaultwarden Serverless Container Release (`update-20261103-184637`)\n\n"
                "### 🛡️ Upstream & Toolchain Manifest\n"
                "- **Vaultwarden Base Image:** `vaultwarden/server:latest` (`sha256:4fe17f415f90...`)\n"
                "- **Litestream Replication Engine:** `v0.5.18`\n"
                "- **Go Static Supervisor Toolchain:** `go1.27.3` (`CGO_ENABLED=0`)\n"
                "- **Source Git Commit:** [`a880bc4`](https://github.com/kdh-rsch/vaultwarden-serverless/commit/a880bc4ee1f0490297a132e6cba1e77357b4a952)\n\n"
                "**Upstream Fingerprint (SHA256):** `395112cb53a70e42e8542c00766ed279ecd12c1feb62f98f9419a72259e913ee`"
            ),
        }
        meta = cr.parse_release_metadata(legacy_release)
        self.assertEqual(meta["tag"], "update-20261103-184637")
        self.assertEqual(meta["vw_digest"], "sha256:4fe17f415f90")
        self.assertEqual(meta["litestream_version"], "0.5.18")
        self.assertEqual(meta["go_version"], "go1.27.3")
        self.assertEqual(meta["sha"], "a880bc4ee1f0490297a132e6cba1e77357b4a952")
        self.assertEqual(
            meta["fingerprint"],
            "395112cb53a70e42e8542c00766ed279ecd12c1feb62f98f9419a72259e913ee",
        )

    def test_parse_structured_comment_metadata(self):
        rel = {
            "tag_name": "update-20261105-120000",
            "body": (
                "Some markdown\n"
                '<!-- release-metadata: {"fingerprint": "abc", "go_version": "go1.27.4", '
                '"litestream_version": "0.5.19", "sha": "1234567890abcdef", '
                '"vw_digest": "sha256:999999999999", "vw_version": "1.38.0"} -->'
            ),
        }
        meta = cr.parse_release_metadata(rel)
        self.assertEqual(meta["vw_version"], "1.38.0")
        self.assertEqual(meta["vw_digest"], "sha256:999999999999")
        self.assertEqual(meta["litestream_version"], "0.5.19")
        self.assertEqual(meta["go_version"], "go1.27.4")
        self.assertEqual(meta["sha"], "1234567890abcdef")

    def test_format_vaultwarden_notes_strips_new_contributors(self):
        raw = (
            "## Security Fixes\r\n"
            "- Advisory 1\r\n\r\n"
            "## What's Changed\r\n"
            "* Fix bug by @alice in https://github.com/dani-garcia/vaultwarden/pull/1\r\n\r\n"
            "## New Contributors\r\n"
            "* @alice made their first contribution in https://github.com/dani-garcia/vaultwarden/pull/1\r\n\r\n"
            "**Full Changelog**: https://github.com/dani-garcia/vaultwarden/compare/1.37.4...1.37.5"
        )
        formatted = cr.format_vaultwarden_notes(raw)
        self.assertIn("#### Security Fixes", formatted)
        self.assertIn("#### What's Changed", formatted)
        self.assertNotIn("New Contributors", formatted)
        self.assertIn("`@alice`", formatted)
        self.assertIn("**Full Changelog**", formatted)

    def test_format_litestream_notes_extracts_changelog(self):
        raw = (
            "## Platform Support\nWindows notice\n\n"
            "## Installation\nbrew install litestream\n\n"
            "## Changelog\n"
            "* daf7646a3760f3df5de6099586fff4ea76609888 [metrics] expose replica validation results (#1535)\n"
            "* e393ab4fbaa67ad33e5c7e739144c507ddf9227a feat(s3): add Neon Object Storage (#1582)\n"
        )
        formatted = cr.format_litestream_notes(raw)
        self.assertNotIn("Platform Support", formatted)
        self.assertNotIn("brew install", formatted)
        self.assertIn(
            "- [`daf7646`](https://github.com/benbjohnson/litestream/commit/daf7646a3760f3df5de6099586fff4ea76609888)",
            formatted,
        )
        self.assertIn(
            "([#1535](https://github.com/benbjohnson/litestream/pull/1535))",
            formatted,
        )

    def test_compute_changes_and_build_release_notes(self):
        prev = {
            "tag": "update-20261102-031228",
            "sha": "a880bc4ee1f0490297a132e6cba1e77357b4a952",
            "vw_version": "",
            "vw_digest": "sha256:4fe17f415f90",
            "litestream_version": "0.5.17",
            "go_version": "go1.27.3",
            "fingerprint": "oldfp",
        }
        curr = {
            "sha": "b991cd5ff2f0490297a132e6cba1e77357b4a952",
            "vw_version": "1.37.5",
            "vw_digest": "sha256:4fe17f415f90abcdef1234567890",
            "litestream_version": "0.5.18",
            "go_version": "go1.27.3",
            "fingerprint": "newfp",
        }
        commits = [
            {
                "sha": "b991cd5ff2f0490297a132e6cba1e77357b4a952",
                "subject": "feat(release): include upstream release notes in GitHub releases",
                "body": "- Add Vaultwarden and Litestream release note sections",
                "url": "https://github.com/kdh-rsch/vaultwarden-serverless/commit/b991cd5ff2f0490297a132e6cba1e77357b4a952",
            }
        ]
        changes = cr.compute_changes(curr, prev, commits)
        self.assertFalse(changes["vw_updated"])
        self.assertTrue(changes["ls_updated"])
        self.assertFalse(changes["go_updated"])
        self.assertTrue(changes["code_updated"])

        title = cr.build_release_title("update-20261105-193500", curr, changes, commits)
        self.assertIn("Litestream v0.5.17 → v0.5.18", title)
        self.assertIn("feat(release): include upstream release notes in GitHub releases", title)

        vw_rel = {
            "version": "1.37.5",
            "html_url": "https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.5",
            "body": "## Security Fixes\n- Fixed icon issue",
        }
        ls_rel = {
            "version": "0.5.18",
            "html_url": "https://github.com/benbjohnson/litestream/releases/tag/v0.5.18",
            "body": "## Changelog\n* daf7646a3760f3df5de6099586fff4ea76609888 fix(s3): retry throttling (#1609)",
        }

        notes = cr.build_release_notes(
            repo="kdh-rsch/vaultwarden-serverless",
            tag="update-20261105-193500",
            current=curr,
            changes=changes,
            repo_commits=commits,
            vw_release=vw_rel,
            ls_release=ls_rel,
        )
        # Should contain component table, repo commits, and upstream notes
        self.assertIn("### 📋 Component Manifest", notes)
        self.assertIn("### 🛠️ Repository Changes (`kdh-rsch/vaultwarden-serverless`)", notes)
        self.assertIn("feat(release): include upstream release notes in GitHub releases", notes)
        self.assertIn("### 🔐 Upstream Release Notes — [Vaultwarden `v1.37.5`]", notes)
        # Vaultwarden was unchanged so it should be wrapped in <details>
        self.assertIn("<details><summary>View Vaultwarden `v1.37.5` release notes (unchanged in this build)</summary>", notes)
        # Litestream was updated so it should be expanded directly
        self.assertIn("### 🔄 Upstream Release Notes — [Litestream `v0.5.18`]", notes)
        self.assertNotIn("<details><summary>View Litestream", notes)
        # Should NOT contain redundant README security/architecture boilerplate
        self.assertNotIn("Security & Verification Highlights", notes)
        self.assertNotIn("Supported Architectures", notes)


if __name__ == "__main__":
    unittest.main()
