"""D1: gitleaks on the reviewed diff, report kept in memory, ids keyed by HMAC(local key, secret).

Provider-specific rules and the canary are hard; generic/entropy rules are needs_human. The secret value is
never written anywhere: the report goes to our stdout pipe, K is computed, and only rule id + path + lines
leave this module. Any gitleaks failure raises ToolError (fail closed).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from pathlib import Path

from .normalise import finding
from .tools import SAFE_PATH, ToolError, resolve

CANARY_RULE = "reviewloop-canary"
CONFIG = f"""[extend]
useDefault = true

[[rules]]
id = "{CANARY_RULE}"
description = "review-loop canary"
regex = '''REVIEWLOOP_CANARY_[A-Z0-9]{{20}}'''
"""
TIMEOUT = 60


def state_dir() -> Path:
    return Path(os.environ.get("REVIEW_LOOP_STATE_DIR") or Path.home() / ".config/review-loop/state")


def hmac_key() -> bytes:
    """32 random bytes, created once with mode 0600."""
    path = state_dir() / "hmac.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(os.urandom(32))
        except FileExistsError:
            pass  # another scan created it first
    key = path.read_bytes()
    if len(key) != 32:
        raise ToolError(f"hmac key at {path} is not 32 bytes")
    return key


def is_generic(rule: str) -> bool:
    return rule.startswith("generic")


class Gitleaks:
    """Started before the Unicode pass so both run concurrently; collect() waits and normalises."""

    def __init__(self, repo: str, staged: bool, base: str | None, head: str | None):
        self.exe, self.version = resolve("gitleaks")
        self.key = hmac_key()
        fd, self.config = tempfile.mkstemp(prefix="review-loop-gitleaks-", suffix=".toml")
        with os.fdopen(fd, "w") as f:
            f.write(CONFIG)
        # an empty dir as --gitleaks-ignore-path: a repo's .gitleaksignore is a suppression, not ours to honour
        self.ignore_dir = tempfile.mkdtemp(prefix="review-loop-gl-ignore-")
        mode = ["--staged"] if staged else ["--log-opts", f"{base}..{head}"]
        cmd = [self.exe, "git", *mode, "--no-banner", "--log-level", "error", "--config", self.config,
               "--report-format", "json", "--report-path", "-", "--exit-code", "0", "--ignore-gitleaks-allow",
               "--gitleaks-ignore-path", self.ignore_dir, repo]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}
        env["PATH"] = SAFE_PATH
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)

    def collect(self) -> list[dict]:
        try:
            out, _ = self.proc.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise ToolError("gitleaks timed out")
        finally:
            os.unlink(self.config)
            os.rmdir(self.ignore_dir)
        if self.proc.returncode != 0:
            raise ToolError(f"gitleaks exited {self.proc.returncode}")
        return to_findings(out, self.key, self.version)


def to_findings(out: bytes, key: bytes, version: str, path: str | None = None) -> list[dict]:
    """gitleaks JSON report → findings; the secret only goes into the HMAC. path overrides the reported file."""
    try:
        hits = json.loads(out)
        assert isinstance(hits, list)
    except (ValueError, AssertionError):
        raise ToolError("gitleaks output is not a JSON list")
    findings = []
    for h in hits:
        rule, where = h["RuleID"], path or h["File"]
        secret = "".join((h.get("Secret") or h.get("Match") or "").split())
        k = hmac.new(key, secret.encode(), hashlib.sha256).hexdigest()
        generic = is_generic(rule)
        findings.append(finding(
            tool="gitleaks", rule=rule, path=where, k=k, lines=(h["StartLine"], h["EndLine"]),
            status="needs_human" if generic else "hard", rule_class="secret", surface="secret",
            title=f"{'Possible secret' if generic else 'Secret'} ({rule}) added in {where}",
            reasoning=rule, ref=f"gitleaks@{version}:{rule}",
        ))
    return findings


def scan_text(text: str, label: str) -> list[dict]:
    """D1 on text that is not in the diff (ticket, --intent, commit messages), via `gitleaks stdin` with the same
    pinned binary and rules. label names the source in the finding's path; the text is never stored."""
    exe, version = resolve("gitleaks")
    fd, config = tempfile.mkstemp(prefix="review-loop-gitleaks-", suffix=".toml")
    with os.fdopen(fd, "w") as f:
        f.write(CONFIG)
    ignore_dir = tempfile.mkdtemp(prefix="review-loop-gl-ignore-")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}
    env["PATH"] = SAFE_PATH
    try:
        p = subprocess.run([exe, "stdin", "--no-banner", "--log-level", "error", "--config", config,
                            "--report-format", "json", "--report-path", "-", "--exit-code", "0",
                            "--ignore-gitleaks-allow", "--gitleaks-ignore-path", ignore_dir],
                           input=text.encode("utf-8", "replace"), capture_output=True, env=env, cwd=ignore_dir,
                           timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ToolError("gitleaks timed out")
    finally:
        os.unlink(config)
        os.rmdir(ignore_dir)
    if p.returncode != 0:
        raise ToolError(f"gitleaks exited {p.returncode}")
    return to_findings(p.stdout, hmac_key(), version, path=label)
