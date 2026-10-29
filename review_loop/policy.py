"""NEEDS_HUMAN (control-weakening): changes that move the goalposts rather than the code. Never hard, never cleared
by a model; a human decides, or records a time-limited `review-loop accept`.

- config: agent instructions, CI workflows, scanner and git-hook config, `.review-loop.toml` — added, changed or
  deleted
- suppression: an added line with a lint/type/scanner suppression comment
- skipped-test: an added skip/only/xfail/ignore marker in a test file
- deleted-assertion: a removed assertion in a test file (a renamed-away test counts as removed)
- symlink / submodule: an added or changed symlink or gitlink (a symlink can point agent config elsewhere)

Diff lines are read as text whatever .gitattributes says (a committed `-diff` must not hide a file).

Runs only when asked (`scan --policy`, eot, recheck): the pre-commit hook keeps its D1–D3 scan.
"""
from __future__ import annotations

import fnmatch
import re

from . import gitdiff, normalise

D = r"(/|$)"  # a directory name, or the name alone (a symlink to a directory shows as a file path)
CONFIG = (  # case-insensitive: claude.md loads as CLAUDE.md on APFS
    ("agent-config", re.compile(r"(^|/)(AGENTS|CLAUDE|GEMINI)[^/]*\.md$|(^|/)\.(claude|codex|cursor|gemini|agents?|"
                                r"windsurf[^/]*|continue|clinerules|pi)" + D + r"|(^|/)\.mcp\.json$|copilot-instructions\.md$|"
                                r"(^|/)\.cursorrules$|(^|/)\.github/(instructions|prompts|agents)" + D +
                                r"|(^|/)\.vscode/(mcp|settings)\.json$", re.I)),
    ("ci-config", re.compile(r"(^|/)\.github/(workflows|actions)" + D + r"|(^|/)azure-pipelines[^/]*\.ya?ml$|"
                             r"(^|/)\.azure-?pipelines?" + D + r"|(^|/)\.gitlab-ci\.ya?ml$|(^|/)\.(circleci|buildkite)" + D +
                             r"|(^|/)Jenkinsfile$|(^|/)bitbucket-pipelines\.ya?ml$", re.I)),
    ("scanner-config", re.compile(r"(^|/)\.gitleaks(\.toml|ignore)$|(^|/)\.semgrep(ignore|\.ya?ml)?" + D +
                                  r"|(^|/)\.?trivy(ignore|\.ya?ml)$|(^|/)\.?osv-scanner\.toml$|(^|/)\.snyk$|"
                                  r"(^|/)\.github/dependabot\.ya?ml$|(^|/)CODEOWNERS$|(^|/)\.gitattributes$|(^|/)\.gitmodules$|"
                                  r"(^|/)\.(npmrc|yarnrc(\.yml)?)$|(^|/)pip\.conf$", re.I)),
    ("git-hooks", re.compile(r"(^|/)\.(husky|githooks)" + D + r"|(^|/)lefthook\.ya?ml$|(^|/)\.pre-commit-config\.ya?ml$",
                             re.I)),
    ("review-loop-config", re.compile(r"(^|/)\.review-loop\.toml$", re.I)),
)
SURFACE = {"agent-config": "agent-config", "ci-config": "workflow"}
SUPPRESSION = re.compile(r"eslint-disable|biome-ignore|@ts-(ignore|nocheck|expect-error)|#\s*(ruff:\s*)?noqa\b|"
                         r"#\s*(type|pyright):\s*ignore|#\s*mypy:|#\s*nosec\b|nosemgrep|gitleaks:allow|trufflehog:ignore|"
                         r"pragma:\s*(allowlist\s+secret|no\s+cover)|NOSONAR|#pragma\s+warning\s+disable|SuppressMessage|"
                         r"ReSharper\s+disable|<NoWarn>|pylint:\s*disable|rubocop:\s*disable|//\s*nolint|lint:ignore|"
                         r"@SuppressWarnings|#!?\[allow\(|(istanbul|c8|v8)\s+ignore|phpcs:ignore|@phpstan-ignore|"
                         r"shellcheck\s+disable|checkov:skip|tfsec:ignore|trivy:ignore|hadolint\s+ignore", re.I)
ASSERTION = re.compile(r"\bassert|\bexpect\s*\(|\.should\b|\bAssert\.|assertThat|\bverify\s*\(|XCTAssert|"
                       r"pytest\.raises|\bt\.(Error|Fatal)|\brequire\.", re.I)
SKIP_TEST = re.compile(r"@pytest\.mark\.(skip|xfail)|\b(it|describe|test)\.(skip|only|todo)\b|\bx(it|describe)\s*\(|"
                       r"\[Ignore\b|@Disabled\b|@Ignore\b|\bt\.Skip(Now|f)?\(|unittest\.skip|\bpending\s*\(")
TEST_FILES = ("tests/*", "test/*", "*/tests/*", "*/test/*", "*/__tests__/*", "spec/*", "*/spec/*", "*/Tests/*",
              "test_*.py", "*/test_*.py", "*_test.*", "*.test.*", "*.spec.*", "*_spec.rb", "*Tests.cs", "*Test.java",
              "*Test.kt", "*Tests.swift")


def hit(rule: str, path: str, line: int, title: str, k: str, surface: str = "code") -> dict:
    return normalise.finding(tool="reviewloop", rule=rule, path=path, k=k, lines=(line, line), status="needs_human",
                             rule_class="control-weakening", surface=surface, title=title, reasoning=rule,
                             ref=f"review-loop:{rule}")


def changed(repo: str, staged: bool, base: str | None, head: str | None) -> list[tuple[str, str, str, str]]:
    """(path, new mode, status, new object id) for every change, renames split into delete + add."""
    out = gitdiff.git(repo, "diff", "--raw", "-z", "--no-renames", "--no-abbrev",
                      *gitdiff.diff_args(staged, base, head)).stdout.decode("utf-8", "replace").split("\0")
    res = []
    for meta, path in zip(out[0::2], out[1::2]):
        parts = meta.lstrip(":").split()
        if len(parts) >= 5:
            res.append((path, parts[1], parts[4][:1], parts[3]))
    return res


def changed_paths(repo: str, staged: bool, base: str | None, head: str | None) -> list[str]:
    return [c[0] for c in changed(repo, staged, base, head)]


def is_test(path: str) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in TEST_FILES)


def text_lines(repo: str, staged: bool, base: str | None, head: str | None, removed: bool) -> dict[str, dict[int, str]]:
    """Diff lines read as text whatever .gitattributes says, minus files that really are binary."""
    lines = (gitdiff.removed_lines if removed else gitdiff.added_lines)(repo, staged, base, head, text=True)
    side = (base if removed else head) if not staged else ("HEAD" if removed else "")
    return {p: v for p, v in lines.items() if not gitdiff.is_binary(repo, f"{side}:{p}")}


def scan(repo: str, staged: bool, base: str | None, head: str | None) -> list[dict]:
    out = []
    side = "" if staged else head
    for path, mode, status, oid in changed(repo, staged, base, head):
        # keyed on the target blob / commit, so an accept doesn't cover a later repoint
        if status != "D" and mode == "120000":
            out.append(hit("symlink", path, 1, f"Symlink added or changed: {path}", oid))
        elif status != "D" and mode == "160000":
            out.append(hit("submodule", path, 1, f"Submodule pointer added or changed: {path}", oid))
        for rule, rx in CONFIG:
            if rx.search(path):
                blob = "deleted" if status == "D" else gitdiff.git(repo, "rev-parse", f"{side}:{path}").stdout.decode().strip()
                out.append(hit(rule, path, 1, f"Change to {rule.replace('-', ' ')}: {path}", blob,
                               SURFACE.get(rule, "code")))
                break
    for path, lines in text_lines(repo, staged, base, head, removed=False).items():
        for n, text in lines.items():
            m = SUPPRESSION.search(text)
            if m:  # keyed on the line and the one after it, so one accept doesn't cover a later identical comment
                out.append(hit("suppression", path, n, f"New suppression ({m.group(0).strip()}) in {path}",
                               normalise.sha1(text.strip() + "\n" + lines.get(n + 1, "").strip())))
            elif is_test(path) and SKIP_TEST.search(text):
                out.append(hit("skipped-test", path, n, f"Test skipped or focused in {path}", normalise.sha1(text.strip())))
    for path, lines in text_lines(repo, staged, base, head, removed=True).items():
        if not is_test(path):
            continue
        for n, text in lines.items():
            if ASSERTION.search(text):
                out.append(hit("deleted-assertion", path, n, f"Assertion removed from {path}",
                               normalise.sha1(text.strip())))
    return out
