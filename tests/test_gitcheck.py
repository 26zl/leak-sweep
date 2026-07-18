import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import gitcheck


class GitcheckSecurityTests(unittest.TestCase):
    def test_sanitize_url_removes_embedded_credentials_and_query(self):
        remote = "https://" + "user:token@" + "example.com/owner/repo.git?key=secret"
        sanitized = gitcheck.sanitize_url(remote)

        self.assertNotIn("user", sanitized)
        self.assertNotIn("token", sanitized)
        self.assertNotIn("secret", sanitized)
        self.assertIn("example.com/owner/repo.git", sanitized)

    def test_sanitize_url_redacts_nonstandard_scp_username(self):
        sanitized = gitcheck.sanitize_url("private-user@github.com:owner/repo.git")

        self.assertEqual(sanitized, "***@github.com:owner/repo.git")

    def test_sanitize_remote_error_replaces_credentialed_url(self):
        remote = "https://" + "token@" + "example.com/owner/repo.git"
        error = f"fatal: unable to access '{remote}'"

        sanitized = gitcheck.sanitize_remote_error(error, remote)

        self.assertNotIn("token", sanitized)
        self.assertIn("https://***@example.com/owner/repo.git", sanitized)

    def test_github_slug_supports_https_and_ssh_remotes(self):
        self.assertEqual(
            gitcheck.github_slug("https://token@github.com/owner/repo.git"),
            "owner/repo",
        )
        self.assertEqual(
            gitcheck.github_slug("git@github.com:owner/repo.git"),
            "owner/repo",
        )

    def test_git_bool_accepts_git_boolean_spellings(self):
        for value in ("true", "yes", "on", "1"):
            self.assertIs(gitcheck.git_bool(value), True)
        for value in ("false", "no", "off", "0"):
            self.assertIs(gitcheck.git_bool(value), False)
        self.assertIsNone(gitcheck.git_bool("sometimes"))

    def test_windows_install_hints_use_exact_winget_ids(self):
        with patch.object(gitcheck.sys, "platform", "win32"):
            self.assertEqual(
                gitcheck.install_hint("git"),
                "winget install --id Git.Git -e",
            )
            self.assertEqual(
                gitcheck.install_hint("gh"),
                "winget install --id GitHub.cli -e",
            )

    def test_github_desktop_is_detected_on_windows(self):
        with tempfile.TemporaryDirectory() as td:
            local = Path(td) / "Local"
            (local / "GitHubDesktop").mkdir(parents=True)
            with patch.object(gitcheck.sys, "platform", "win32"), patch.dict(
                os.environ,
                {"LOCALAPPDATA": str(local), "PROGRAMFILES": str(Path(td) / "Program Files")},
                clear=False,
            ):
                self.assertTrue(gitcheck.github_desktop_installed())

    def test_git_behavior_accepts_documented_boolean_aliases(self):
        values = {
            "user.useConfigOnly": "yes",
            "init.defaultBranch": "main",
            "pull.rebase": "on",
            "pull.ff": "",
            "push.default": "simple",
            "fetch.prune": "1",
            "core.autocrlf": "off",
            "protocol.file.allow": "user",
            "core.hooksPath": "",
        }
        gitcheck.results.clear()
        with patch.object(gitcheck, "gitconf", side_effect=lambda key, *_: values[key]), \
                patch.object(gitcheck, "gitconf_all", return_value=[]), \
                patch.object(gitcheck, "run", return_value=(0, "", "")), \
                patch.object(gitcheck.sys, "platform", "darwin"), \
                redirect_stdout(io.StringIO()):
            gitcheck.check_git_behavior()

        self.assertNotIn(gitcheck.FAIL, gitcheck.results)
        gitcheck.results.clear()


if __name__ == "__main__":
    unittest.main()
