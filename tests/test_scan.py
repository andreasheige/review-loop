"""Fixture tests for `review-loop scan` (D1 secrets, D2 hidden Unicode, D3 lockfiles, tool pinning).

usage: python3 -m unittest tests.test_scan -v      (from the repo root)

Every case builds a throwaway git repo with GIT_CONFIG_GLOBAL=/dev/null, so no global hook or config runs.
Canary and test secrets are generated at runtime and never written to this file. D3 uses a fake network.
"""
import json
import os
import secrets
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin/review-loop"
sys.path.insert(0, str(ROOT))
from review_loop import scan  # noqa: E402 - needs the sys.path entry above

REAL_LOCK = Path.home() / ".config/review-loop/tools.lock"


def locked_row(tool):
    if not REAL_LOCK.is_file():
        return None
    return next((l for l in REAL_LOCK.read_text().splitlines() if l.split("\t")[0] == tool), None)


GITLEAKS_ROW = locked_row("gitleaks")


def canary():
    return "REVIEWLOOP_CANARY_" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(20))


def entropy_value():
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))


class FakeNet:
    """OSV + registry stand-in: names starting evil- are MAL, ghost- do not exist, slow- time out."""

    def __init__(self):
        self.calls = []

    def request(self, url, body=None, timeout=3.0):
        name = body["package"]["name"] if body else url
        self.calls.append(name)
        if "slow-" in name:
            raise socket.timeout("timed out")
        if body:
            return 200, {"vulns": [{"id": "MAL-2026-0001"}]} if name.startswith("evil-") else {}
        return (404, None) if "ghost-" in url else (200, {})


def npm_lock(pkgs):
    packages = {"": {"name": "app", "version": "1.0.0"}}
    for name, version in pkgs:
        packages[f"node_modules/{name}"] = {"version": version,
                                            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"}
    return json.dumps({"name": "app", "lockfileVersion": 3, "requires": True, "packages": packages}, indent=2) + "\n"


def uv_lock(pkgs):
    out = "version = 1\nrequires-python = \">=3.11\"\n"
    for name, version in pkgs:
        out += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
    return out


@unittest.skipUnless(GITLEAKS_ROW, "gitleaks not pinned in ~/.config/review-loop/tools.lock")
class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-test-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.lock = self.tmp / "tools.lock"
        self.lock.write_text(GITLEAKS_ROW + "\n")
        (self.tmp / "osvdb").mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                        REVIEW_LOOP_TOOLS_LOCK=str(self.lock), REVIEW_LOOP_STATE_DIR=str(self.tmp / "state"),
                        OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(self.tmp / "osvdb"),
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.secrets = []
        self.git("init", "-q", "-b", "main")
        self.write("README.md", "# fixture\n")
        self.commit("init")

    # helpers
    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env, check=True, capture_output=True, text=True).stdout

    def write(self, path, text):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        self.git("add", path)

    def commit(self, msg):
        self.git("commit", "-q", "-m", msg)

    def scan(self, *args, env=None):
        p = subprocess.run([str(BIN), "scan", *args], cwd=self.repo, env={**self.env, **(env or {})},
                           capture_output=True, text=True)
        for s in self.secrets:
            self.assertNotIn(s, p.stdout + p.stderr, "secret value leaked into output")
        out = json.loads(p.stdout)
        self.assertEqual(p.returncode, out["exit_code"])
        return p.returncode, out

    def scan_inproc(self, net, staged=True):
        with mock.patch.dict(os.environ, self.env, clear=True):
            return scan.run(str(self.repo), staged, net=net)

    def add_canary(self, path="src/x.ts"):
        c = canary()
        self.secrets.append(c)
        body = "".join(f"export const v{i} = {i};\n" for i in range(20))
        self.write(path, body + f'export const t = "{c}";\n')
        return c

    # D1
    def test_canary_is_hard(self):
        self.add_canary()
        rc, out = self.scan("--staged")
        self.assertEqual(rc, 1)
        [f] = [f for f in out["findings"] if f["evidence"]["ref"].endswith(":reviewloop-canary")]
        self.assertEqual((f["status"], f["rule_class"], f["reasoning"]), ("hard", "secret", "reviewloop-canary"))
        self.assertEqual(f["sites"], [{"path": "src/x.ts", "start_line": 21, "end_line": 21}])
        self.assertRegex(f["id"], r"^sec-gitleaks-[0-9a-f]{12}$")
        self.assertEqual(os.stat(self.tmp / "state/hmac.key").st_mode & 0o777, 0o600)

    def test_generic_entropy_is_needs_human(self):
        v = entropy_value()
        self.secrets.append(v)
        self.write("src/config.ts", f'const api_key = "{v}";\n')
        rc, out = self.scan("--staged")
        self.assertEqual(rc, 2, out)
        self.assertEqual([(f["status"], f["reasoning"]) for f in out["findings"]], [("needs_human", "generic-api-key")])

    def test_clean_diff_passes(self):
        self.write("src/ok.py", "def add(a, b):\n    return a + b\n")
        rc, out = self.scan("--staged")
        self.assertEqual((rc, out["summary"], out["findings"]), (0, "no_findings_reported (unverified)", []))

    def test_same_id_across_staged_range_and_rebase(self):
        self.write("src/x.ts", "".join(f"export const v{i} = {i};\n" for i in range(20)))
        self.commit("base")
        self.git("checkout", "-q", "-b", "feature")
        self.add_canary()
        hard = lambda out: [f for f in out["findings"] if f["status"] == "hard"]  # noqa: E731
        [staged] = hard(self.scan("--staged")[1])
        self.commit("add token")
        [ranged] = hard(self.scan("--range", "main..feature")[1])
        self.git("checkout", "-q", "main")
        self.write("src/x.ts", "// header\n" * 7 + (self.repo / "src/x.ts").read_text())
        self.commit("shift lines on main")
        self.git("checkout", "-q", "feature")
        self.git("rebase", "-q", "main")
        [rebased] = hard(self.scan("--range", "main..feature")[1])
        self.assertEqual(staged["id"], ranged["id"])
        self.assertEqual(staged["id"], rebased["id"])
        self.assertNotEqual(ranged["sites"], rebased["sites"], "rebase should have shifted the line")

    def test_sarif_written(self):
        self.add_canary()
        sarif = self.tmp / "out.sarif"
        self.scan("--staged", "--sarif", str(sarif))
        doc = json.loads(sarif.read_text())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["results"][0]["ruleId"], "reviewloop-canary")
        self.assertNotIn(self.secrets[0], sarif.read_text())

    # D2
    def test_bidi_and_zero_width_in_python_are_hard(self):
        self.write("src/a.py", "ok = 1\naccess = 'user\u202e \u2066// admin\u2069\u2066'\n")
        self.write("src/b.py", "is\u200badmin = False\n")
        rc, out = self.scan("--staged")
        self.assertEqual(rc, 1)
        got = sorted((f["sites"][0]["path"], f["sites"][0]["start_line"], f["status"], f["rule_class"], f["title"]) for f in out["findings"])
        self.assertEqual(got, [
            ("src/a.py", 2, "hard", "unicode", "Hidden Unicode (bidi: U+202E, U+2066, U+2069) added in src/a.py"),
            ("src/b.py", 1, "hard", "unicode", "Hidden Unicode (zero-width: U+200B) added in src/b.py"),
        ])
        self.assertTrue(all(f["id"].startswith("sec-unicode-") for f in out["findings"]))
        self.assertTrue(all(ord(c) < 0x2000 for c in json.dumps(out, ensure_ascii=False)))

    def test_emoji_zwj_allowed_in_readme_not_in_agents_md(self):
        line = "Built by a \U0001F468\u200d\U0001F4BB with ❤\ufe0f\n"
        self.write("README.md", "\ufeff# fixture\n" + line)
        self.assertEqual(self.scan("--staged")[0], 0)
        self.write("AGENTS.md", line)
        rc, out = self.scan("--staged")
        self.assertEqual(rc, 1)
        self.assertEqual({(f["sites"][0]["path"], f["surface"]) for f in out["findings"]}, {("AGENTS.md", "agent-config")})
        self.assertEqual(sorted(f["title"].split("(")[1].split(":")[0] for f in out["findings"]), ["variation-selector", "zero-width"])

    # pinning / fail closed
    def test_hash_mismatch_fails_closed(self):
        tool, version, path, _ = GITLEAKS_ROW.split("\t")
        self.lock.write_text(f"{tool}\t{version}\t{path}\t{'0' * 64}\n")
        self.add_canary()
        rc, out = self.scan("--staged")
        self.assertEqual((rc, out["summary"]), (3, "error"))
        self.assertIn("sha256 mismatch", out["error"])

    def test_missing_gitleaks_fails_closed(self):
        tool, version, _, digest = GITLEAKS_ROW.split("\t")
        self.lock.write_text(f"{tool}\t{version}\t{self.tmp / 'nope/gitleaks'}\t{digest}\n")
        self.write("src/ok.py", "x = 1\n")
        self.assertEqual(self.scan("--staged")[0], 3)
        self.lock.write_text("# empty lock\n")
        self.assertEqual(self.scan("--staged")[0], 3)

    def test_path_stub_ignored_and_stub_at_locked_path_fails_closed(self):
        stubs = self.tmp / "stubs"
        stubs.mkdir()
        stub = stubs / "gitleaks"
        stub.write_text("#!/bin/sh\necho '[]'\nexit 0\n")
        stub.chmod(0o755)
        self.add_canary()
        rc, _ = self.scan("--staged", env={"PATH": f"{stubs}:{self.env['PATH']}"})
        self.assertEqual(rc, 1, "PATH stub must not replace the pinned gitleaks")
        tool, version, _, digest = GITLEAKS_ROW.split("\t")
        self.lock.write_text(f"{tool}\t{version}\t{stub}\t{digest}\n")
        self.assertEqual(self.scan("--staged")[0], 3)

    # D3
    def test_deps_online_mal_nonexistent_timeout(self):
        self.write("package-lock.json", npm_lock([("left-pad", "1.3.0")]))
        self.commit("lock")
        self.write("package-lock.json", npm_lock([("left-pad", "1.3.0"), ("evil-pkg", "1.0.0"), ("ghost-pkg", "9.9.9"), ("slow-pkg", "1.0.0")]))
        self.write("uv.lock", uv_lock([("ghost-py", "0.0.1")]))
        net = FakeNet()
        out = self.scan_inproc(net)
        self.assertEqual(out["exit_code"], 1)
        got = sorted((f["title"], f["status"], f["rule_class"], f["sites"][0]["path"]) for f in out["findings"])
        self.assertEqual(got, [
            ("Malicious package evil-pkg@1.0.0 (MAL-2026-0001)", "hard", "dep-mal", "package-lock.json"),
            ("OSV lookup failed for slow-pkg@1.0.0", "needs_human", "dep-mal", "package-lock.json"),
            ("Registry lookup failed for slow-pkg@1.0.0", "needs_human", "dep-nonexistent", "package-lock.json"),
            ("ghost-pkg@9.9.9 does not exist in the npm registry", "hard", "dep-nonexistent", "package-lock.json"),
            ("ghost-py@0.0.1 does not exist in the PyPI registry", "hard", "dep-nonexistent", "uv.lock"),
        ])
        self.assertNotIn("left-pad", " ".join(net.calls), "unchanged versions are not looked up")
        line = next(f for f in out["findings"] if "evil-pkg" in f["title"])["sites"][0]["start_line"]
        self.assertIn('"node_modules/evil-pkg"', (self.repo / "package-lock.json").read_text().split("\n")[line - 1])

    def test_deps_timeout_alone_is_needs_human(self):
        self.write("package-lock.json", npm_lock([("slow-pkg", "2.0.0")]))
        out = self.scan_inproc(FakeNet())
        self.assertEqual((out["exit_code"], {f["status"] for f in out["findings"]}), (2, {"needs_human"}))

    def test_client_origin_makes_no_network_call(self):
        self.git("remote", "add", "origin", "git@github.com:someclient/app.git")
        self.write("package-lock.json", npm_lock([("evil-pkg", "1.0.0")]))
        net = FakeNet()
        out = self.scan_inproc(net)
        self.assertEqual(net.calls, [])
        self.assertEqual(out["exit_code"], 2)
        [f] = out["findings"]
        self.assertEqual((f["status"], f["reasoning"]), ("needs_human", "Dependency not verified offline: no local OSV database."))

    # contract
    def test_output_validates_against_contract(self):
        uv = shutil.which("uv")
        if not uv:
            self.skipTest("uv not installed")
        probe = subprocess.run([uv, "run", "--offline", "--with", "jsonschema==4.26.0", "python", "-c", "import jsonschema"],
                               capture_output=True, cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest("jsonschema 4.26.0 not in the uv cache")
        v = entropy_value()
        self.secrets.append(v)
        self.add_canary()
        self.write("src/config.ts", f'const api_key = "{v}";\n')
        self.write("AGENTS.md", "x\u200by\n")
        self.write("package-lock.json", npm_lock([("evil-pkg", "1.0.0"), ("ghost-pkg", "1.0.0"), ("slow-pkg", "1.0.0")]))
        outputs = [self.scan("--staged")[1], self.scan_inproc(FakeNet())]
        self.git("remote", "add", "origin", "https://gitlab.example.invalid/client/app.git")
        outputs.append(self.scan_inproc(FakeNet()))
        self.lock.write_text("")
        outputs.append(self.scan("--staged")[1])
        statuses = {f["status"] for o in outputs for f in o["findings"]}
        self.assertEqual(statuses, {"hard", "needs_human"})
        data = self.tmp / "outputs.json"
        data.write_text(json.dumps(outputs))
        checker = (
            "import json,sys\n"
            "from jsonschema import Draft202012Validator\n"
            "fs=json.load(open('contract/finding.schema.json')); rs=json.load(open('contract/record.schema.json'))\n"
            "fv=Draft202012Validator(fs); ov=Draft202012Validator(rs['properties']['outcome'])\n"
            "bad=0\n"
            "for o in json.load(open(sys.argv[1])):\n"
            "    for e in ov.iter_errors({k: o[k] for k in ('exit_code','summary','error') if k in o}): print('outcome', e.message); bad+=1\n"
            "    for f in o['findings']:\n"
            "        for e in fv.iter_errors(f): print(f['id'], e.message); bad+=1\n"
            "sys.exit(1 if bad else 0)\n"
        )
        p = subprocess.run([uv, "run", "--offline", "--with", "jsonschema==4.26.0", "python", "-c", checker, str(data)],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    # budget
    def test_staged_timing_small_diff(self):
        self.write("src/a.py", "".join(f"x{i} = {i}\n" for i in range(50)))
        self.write("docs/b.md", "hello\n" * 30)
        self.scan("--staged")  # warm
        t0 = time.perf_counter()
        rc, _ = self.scan("--staged")
        wall = time.perf_counter() - t0
        sys.stderr.write(f"\n  review-loop scan --staged on a small diff: {wall * 1000:.0f} ms\n")
        self.assertEqual(rc, 0)
        self.assertLess(wall, 1.0)


if __name__ == "__main__":
    unittest.main()
