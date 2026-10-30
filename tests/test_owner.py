"""Tests for owner.py: own origins and client roots come from the config dir, nothing is hard-coded.

usage: python3 -m unittest tests.test_owner -v      (from the repo root)
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from review_loop import deps, eot, owner  # noqa: E402 - needs the sys.path entry above


class OwnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = self.tmp / "config"
        self.cfg.mkdir()
        patcher = mock.patch.object(owner, "CONFIG_DIR", self.cfg)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_config_only_repos_without_a_remote_are_own(self):
        self.assertTrue(deps.is_online(None))
        self.assertFalse(deps.is_online("git@github.com:someone/app.git"))
        self.assertEqual(owner.client_roots(), [])

    def test_own_origin_prefixes_match_ssh_and_https(self):
        (self.cfg / "owner-origins.txt").write_text("# mine\ngithub.com/me/\n\n")
        for url in ("git@github.com:me/app.git", "https://github.com/me/app", "ssh://git@github.com/me/app.git",
                    "https://user@github.com/me/app.git"):
            self.assertTrue(deps.is_online(url), url)
        for url in ("git@github.com:meme/app.git", "https://github.com/someone/me/app", "https://dev.azure.com/me/x"):
            self.assertFalse(deps.is_online(url), url)

    def test_client_roots_expand_home_and_mark_repos_sensitive(self):
        clients = self.tmp / "clients"
        (clients / "acme").mkdir(parents=True)
        (self.cfg / "client-roots.txt").write_text(f"{clients}\n~/does-not-exist-review-loop\n")
        self.assertIn(clients.resolve(), owner.client_roots())
        self.assertTrue(owner.in_client_root(str(clients / "acme")))
        self.assertFalse(owner.in_client_root(str(self.tmp)))
        with mock.patch.object(eot, "git") as git:
            git.return_value.stdout = b"false\n"
            self.assertTrue(eot.sensitive(str(clients / "acme")))
            self.assertFalse(eot.sensitive(str(self.tmp)))


if __name__ == "__main__":
    unittest.main()
