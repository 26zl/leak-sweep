import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sweep
from leak_sweep_reporting import mask, md_code, render_md


class EmptyAnalyzer:
    def analyze(self, **_kwargs):
        return []


class SweepRegressionTests(unittest.TestCase):
    def test_fast_scan_also_runs_for_prose_with_presidio_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "identity.md").write_text("ID: 15108695088\n", encoding="utf-8")
            result = sweep.empty_result({"name": "fixture", "isPrivate": True})

            sweep.scan_tree(root, result, None, [], EmptyAnalyzer(),
                            use_gitleaks=False, regions=["NO"])

            hits = [(p["entity"], p["value"], p.get("country")) for p in result["pii"]]
            self.assertIn(("NATIONAL_ID", "15108695088", "NO"), hits)

    def test_no_regions_means_no_national_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "id.md").write_text("15108695088\n", encoding="utf-8")
            result = sweep.empty_result({"name": "fixture", "isPrivate": True})
            sweep.scan_tree(root, result, None, [], None, use_gitleaks=False, regions=[])
            self.assertFalse(any(p["entity"] == "NATIONAL_ID" for p in result["pii"]))

    def test_split_gitleaks_routes_national_id_with_country(self):
        findings = [
            {"RuleID": "national-id-NO", "Secret": "15108695088", "File": "a"},
            {"RuleID": "national-id-NO", "Secret": "12345678901", "File": "b"},  # invalid → dropped
            {"RuleID": "generic-api-key", "Secret": "AKIA", "File": "c"},
        ]
        secrets, watch, ids = sweep.split_gitleaks(findings, [], ["NO"])
        self.assertEqual(len(ids), 1)
        self.assertEqual((ids[0]["country"], ids[0]["type"]), ("NO", "fødselsnummer"))
        self.assertEqual(len(secrets), 1)

    def test_gitleaks_config_includes_national_id_rule(self):
        config = sweep.gitleaks_config_text(["Ola"], ["NO"])
        self.assertIn('id = "national-id-NO"', config)
        self.assertIn("secretGroup = 2", config)
        self.assertEqual(sweep.gitleaks_config_text([], []).count("national-id"), 0)

    def test_json_redaction_removes_secondary_secret_fields_and_masks_extras(self):
        result = sweep.empty_result({"name": "fixture", "isPrivate": True})
        secret = "abcd1234" + "SECRET5678"
        result["secrets"] = [
            {
                "RuleID": "generic",
                "Secret": secret,
                "Match": f"credential={secret}",
                "Line": f"credential={secret}",
                "Message": f"remove {secret} from the fixture",
            }
        ]
        result["national_id_history"] = [
            {
                "Secret": "15108695088", "country": "NO", "type": "fødselsnummer",
                "Match": "id=15108695088", "Line": "id=15108695088",
                "Message": "remove 15108695088 from the fixture",
            }
        ]
        result["exif"] = [
            {"field": "GPS", "file": "photo.jpg", "value": "59.9,10.7"}
        ]
        extras = {
            "gists": [
                {
                    "hits": [
                        {"entity": "CREDIT_CARD", "value": "4111111111111111"},
                        {"entity": "NATIONAL_ID", "value": "15108695088"},
                    ]
                }
            ]
        }

        payload = {
            "results": sweep.redact_results([result], raw=False),
            "extras": sweep.redact_extras(extras, raw=False),
        }
        serialized = json.dumps(payload, ensure_ascii=False)

        self.assertNotIn(secret, serialized)
        self.assertNotIn("15108695088", serialized)
        self.assertNotIn("4111111111111111", serialized)
        self.assertNotIn("59.9,10.7", serialized)
        self.assertNotIn("Match", serialized)
        self.assertNotIn("Line", serialized)

    def test_national_id_is_masked_and_labelled_in_report(self):
        result = sweep.empty_result({"name": "R", "isPrivate": False})
        result["pii"] = [{"entity": "NATIONAL_ID", "value": "15108695088",
                          "country": "NO", "type": "fødselsnummer", "file": "f", "line": 1}]
        meta = {"when": "now", "user": "u", "terms": 0, "presidio": False}
        report = render_md([result], meta)
        self.assertNotIn("15108695088", report)
        self.assertIn("NO", report)
        masked = sweep.redact_results([result], raw=False)[0]["pii"][0]["value"]
        self.assertNotEqual(masked, "15108695088")

    def test_secret_mask_does_not_reveal_short_secret_characters(self):
        secret = "shortpass"

        self.assertEqual(mask(secret), "•" * len(secret))

    def test_invalid_gitleaks_json_is_an_incomplete_scan_error(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)

            def fake_run(command, **_kwargs):
                report_path = Path(command[command.index("--report-path") + 1])
                report_path.write_text("{invalid", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch.object(sweep, "WORK", work), patch.object(
                sweep, "_GITLEAKS_MODERN", True
            ), patch.object(sweep, "run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
                    sweep.gitleaks_scan(work, work / "config.toml", "fixture")

            self.assertFalse((work / "fixture.gitleaks.json").exists())

    def test_file_read_errors_mark_result_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "unreadable.txt").write_text("content", encoding="utf-8")
            result = sweep.empty_result({"name": "fixture", "isPrivate": True})

            with patch.object(sweep, "has_commits", return_value=False), patch.object(
                Path, "read_text", side_effect=OSError("denied")
            ):
                sweep.scan_tree(root, result, None, [], None, use_gitleaks=False)

            self.assertEqual(result["stats"]["file_errors"], 1)
            self.assertIn("incomplete", sweep.oneline(result))
            report = render_md(
                [result],
                {"when": "now", "user": "u", "terms": 0, "presidio": False},
            )
            self.assertIn("1 file errors", report)

    def test_exiftool_failure_marks_optional_scan_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result = sweep.empty_result({"name": "fixture", "isPrivate": True})

            with patch.object(sweep, "has_commits", return_value=False), patch.object(
                sweep, "binary_metadata_hits", side_effect=RuntimeError("failed")
            ):
                sweep.scan_tree(
                    root, result, None, [], None, use_gitleaks=False, exif=True
                )

            self.assertEqual(len(result["deep_errors"]), 1)
            self.assertIn("exif", result["deep_errors"][0])
            self.assertEqual(sweep.scan_error_count(result), 1)

    def test_enabled_wiki_clone_failure_is_not_silently_ignored(self):
        repo = {
            "name": "fixture",
            "nameWithOwner": "owner/fixture",
            "hasWikiEnabled": True,
        }
        failed = subprocess.CompletedProcess([], 1, "", "")

        with tempfile.TemporaryDirectory() as td, patch.object(
            sweep, "WORK", Path(td)
        ), patch.object(sweep.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "enabled wiki"):
                sweep.scan_wiki(repo, None, [], None, "NO", [], False)

        repo["hasWikiEnabled"] = False
        self.assertIsNone(sweep.scan_wiki(repo, None, [], None, "NO", [], False))

    def test_repo_listing_cap_is_reported_as_truncated(self):
        listed = [
            {
                "name": f"repo-{index}",
                "nameWithOwner": f"owner/repo-{index}",
                "isPrivate": True,
                "isFork": False,
            }
            for index in range(1000)
        ]
        completed = subprocess.CompletedProcess([], 0, json.dumps(listed), "")
        args = SimpleNamespace(owner=None, repo=None, include_forks=False)

        with patch.object(sweep, "run", return_value=completed), patch.object(
            sweep, "_self_repo", return_value="different/repo"
        ), redirect_stdout(io.StringIO()):
            repos, truncated = sweep.list_repos(args)

        self.assertEqual(len(repos), 1000)
        self.assertTrue(truncated)

    def test_search_response_without_total_is_marked_failed(self):
        completed = subprocess.CompletedProcess([], 0, "unexpected output", "")

        with patch.object(sweep.subprocess, "run", return_value=completed):
            total, items = sweep._gh_search("/search/code", "term", ".path")

        self.assertEqual((total, items), (-1, []))

    def test_invalid_actions_log_archive_is_not_silently_ignored(self):
        repo = {"nameWithOwner": "owner/fixture"}
        runs = subprocess.CompletedProcess([], 0, "123\n", "")
        invalid_zip = subprocess.CompletedProcess([], 0, b"not a zip", b"")

        with patch.object(sweep, "run", return_value=runs), patch.object(
            sweep.subprocess, "run", return_value=invalid_zip
        ):
            with self.assertRaisesRegex(RuntimeError, "valid ZIP"):
                sweep.scan_actions(repo, ["watch term"])

    def test_reports_are_private_and_names_do_not_collide(self):
        with tempfile.TemporaryDirectory() as td:
            reports = Path(td) / "reports"
            result = sweep.empty_result({"name": "fixture", "isPrivate": True})
            meta = {"when": "now", "user": "u", "terms": 0, "presidio": False}

            with patch.object(sweep, "REPORTS", reports):
                first = sweep.write_reports([result], meta, raw=False)
                second = sweep.write_reports([result], meta, raw=False)

            self.assertNotEqual(first, second)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(reports.stat().st_mode), 0o700)
                for report in reports.iterdir():
                    self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

    def test_windows_private_acl_uses_current_user_sid(self):
        with tempfile.TemporaryDirectory() as td:
            private_dir = Path(td) / "private"
            private_dir.mkdir()
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch.object(sweep.os, "name", "nt"), patch.object(
                sweep, "_windows_user_sid", return_value="S-1-5-21-1234"
            ), patch.object(sweep.subprocess, "run", return_value=completed) as run_mock:
                sweep.restrict_private_path(private_dir, directory=True)

            command = run_mock.call_args.args[0]
            self.assertEqual(command[0], "icacls.exe")
            self.assertIn("/inheritance:r", command)
            self.assertIn("*S-1-5-21-1234:(OI)(CI)F", command)

    def test_watchlist_toml_does_not_drop_triple_quote_terms(self):
        config = sweep.gitleaks_config_text(["name'''suffix"])

        self.assertIn('id = "watchlist-0"', config)
        self.assertIn("name'''suffix", config)

    def test_repo_storage_uses_owner_to_avoid_name_collisions(self):
        first = sweep.repo_storage_name(
            {"name": "shared", "nameWithOwner": "first/shared"}
        )
        second = sweep.repo_storage_name(
            {"name": "shared", "nameWithOwner": "second/shared"}
        )

        self.assertNotEqual(first, second)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_existing_clone_switches_to_updated_default_branch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source"
            remote = root / "remote.git"
            work = root / "work"
            source.mkdir()
            for args in (
                ("init", "-q"),
                ("branch", "-M", "main"),
                ("config", "user.email", "test@example.invalid"),
                ("config", "user.name", "Test User"),
            ):
                subprocess.run(("git", "-C", source, *args), check=True)
            tracked = source / "tracked.txt"
            tracked.write_text("one\n", encoding="utf-8")
            subprocess.run(("git", "-C", source, "add", "-A"), check=True)
            subprocess.run(
                ("git", "-C", source, "commit", "-q", "--no-gpg-sign", "-m", "one"),
                check=True,
            )
            subprocess.run(("git", "clone", "-q", "--bare", source, remote), check=True)

            repo = {
                "name": "project",
                "nameWithOwner": "owner/project",
                "defaultBranchRef": {"name": "main"},
            }
            clone = work / sweep.repo_storage_name(repo)
            work.mkdir()
            subprocess.run(("git", "clone", "-q", remote, clone), check=True)

            tracked.write_text("two\n", encoding="utf-8")
            subprocess.run(("git", "-C", source, "add", "-A"), check=True)
            subprocess.run(
                ("git", "-C", source, "commit", "-q", "--no-gpg-sign", "-m", "two"),
                check=True,
            )
            subprocess.run(("git", "-C", source, "push", "-q", remote, "main"), check=True)

            with patch.object(sweep, "WORK", work), patch.object(
                sweep, "_github_repo_from_url", return_value="owner/project"
            ):
                updated = sweep.clone_or_update(repo)

            branch = subprocess.run(
                ("git", "-C", updated, "branch", "--show-current"),
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            self.assertEqual(branch, "")
            self.assertEqual((updated / "tracked.txt").read_text(encoding="utf-8"), "two\n")

    def test_installed_data_root_is_private_home_directory(self):
        with tempfile.TemporaryDirectory() as td:
            module_root = Path(td) / "site-packages"
            home = Path(td) / "home"
            with patch.dict(os.environ, {"LEAK_SWEEP_HOME": str(Path(td) / "unsafe")}), \
                    patch.object(sweep, "MODULE_ROOT", module_root), \
                    patch.object(Path, "home", return_value=home):
                self.assertEqual(sweep._data_root(), (home / ".leak-sweep").resolve())

    def test_ensure_private_dirs_bootstraps_missing_installed_data_root(self):
        with tempfile.TemporaryDirectory() as td:
            module_root = Path(td) / "site-packages"
            home = Path(td) / "home"
            home.mkdir()  # Path.home() always exists; only .leak-sweep is missing
            root = home / ".leak-sweep"
            with patch.object(sweep, "MODULE_ROOT", module_root), \
                    patch.object(sweep, "ROOT", root), \
                    patch.object(sweep, "WORK", root / "work"), \
                    patch.object(sweep, "REPORTS", root / "reports"):
                sweep.ensure_private_dirs()

                self.assertTrue((root / "work").is_dir())
                self.assertTrue((root / "reports").is_dir())
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_ensure_private_dirs_leaves_source_checkout_root_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "checkout"
            root.mkdir()
            if os.name != "nt":
                os.chmod(root, 0o755)
            with patch.object(sweep, "MODULE_ROOT", root), \
                    patch.object(sweep, "ROOT", root), \
                    patch.object(sweep, "WORK", root / "work"), \
                    patch.object(sweep, "REPORTS", root / "reports"):
                sweep.ensure_private_dirs()

                self.assertTrue((root / "work").is_dir())
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)

    def test_known_region_flags_unknown_iso_codes(self):
        self.assertTrue(sweep.known_region("NO"))
        self.assertTrue(sweep.known_region("gb"))  # case-insensitive
        self.assertFalse(sweep.known_region("ZZ"))

    def test_markdown_code_spans_cannot_be_closed_by_untrusted_text(self):
        value = "path` ![remote](https://example.invalid/pixel)"

        rendered = md_code(value)

        self.assertTrue(rendered.startswith("`` "))
        self.assertTrue(rendered.endswith(" ``"))
        self.assertIn(value, rendered)

    def test_report_wraps_untrusted_scan_errors_in_code(self):
        value = "![remote](https://example.invalid/pixel)"
        result = sweep.empty_result({"name": "fixture", "isPrivate": True})
        result["error"] = value

        report = render_md(
            [result],
            {"when": "now", "user": "u", "terms": 0, "presidio": False},
        )

        self.assertIn(f"⚠ {md_code(value)}", report)


if __name__ == "__main__":
    unittest.main()
