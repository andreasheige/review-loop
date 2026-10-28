"""NEEDS_HUMAN (control-weakening): changes that move the goalposts rather than the code. Never hard, never cleared
by a model; a human decides, or records a time-limited `review-loop accept`.

- config: agent instructions, CI workflows, scanner and git-hook config, `.review-loop.toml` — added, changed or
  deleted
- suppression: an added line with a lint/type/scanner suppression comment
- deleted-assertion: a removed assertion in a test file

Runs only when asked (`scan --policy`, eot, recheck): the pre-commit hook keeps its D1–D3 scan.
"""
from __future__ import annotations

import fnmatch
import re

from . import gitdiff, normalise

CONFIG = (
    ("agent-config", re.compile(r"(^|/)(AGENTS|CLAUDE|GEMINI)[^/]*\.md$|(^|/)\.(claude|codex|cursor|gemini|agents)/|"
                                r"(^|/)\.mcp\.json$|copilot-instructions\.md$|(^|/)\.cursorrules$")),
    ("ci-config", re.compile(r"(^|/)\.github/workflows/|(^|/)azure-pipelines[^/]*\.ya?ml$|(^|/)\.gitlab-ci\.ya?ml$|"
                             r"(^|/)\.circleci/|(^|/)Jenkinsfile$")),
    ("scanner-config", re.compile(r"(^|/)\.gitleaks(\.toml|ignore)$|(^|/)\.semgrep(ignore|\.ya?ml)?$|(^|/)\.trivyignore$|"
                                  r"(^|/)\.?osv-scanner\.toml$|(^|/)\.snyk$|(^|/)\.github/dependabot\.ya?ml$|(^|/)CODEOWNERS$")),
    ("git-hooks", re.compile(r"(^|/)\.husky/|(^|/)\.githooks/|(^|/)lefthook\.ya?ml$|(^|/)\.pre-commit-config\.ya?ml$")),
    ("review-loop-config", re.compile(r"(^|/)\.review-loop\.toml$")),
)
SURFACE = {"agent-config": "agent-config", "ci-config": "workflow"}
SUPPRESSION = re.compile(r"eslint-disable|@ts-(ignore|nocheck|expect-error)|#\s*noqa\b|#\s*type:\s*ignore|#\s*nosec\b|"
                         r"nosemgrep|gitleaks:allow|NOSONAR|#pragma\s+warning\s+disable|SuppressMessage|"
                         r"pylint:\s*disable|//\s*nolint|@SuppressWarnings|(istanbul|c8)\s+ignore", re.I)
ASSERTION = re.compile(r"\bassert|\bexpect\s*\(|\.should\b|\bAssert\.|assertThat|\bverify\s*\(")
TEST_FILES = ("tests/*", "test/*", "*/tests/*", "*/test/*", "*/__tests__/*", "test_*.py", "*/test_*.py",
              "*_test.*", "*.test.*", "*.spec.*", "*Tests.cs", "*Test.java")


def hit(rule: str, path: str, line: int, title: str, k: str, surface: str = "code") -> dict:
    return normalise.finding(tool="reviewloop", rule=rule, path=path, k=k, lines=(line, line), status="needs_human",
                             rule_class="control-weakening", surface=surface, title=title, reasoning=rule,
                             ref=f"review-loop:{rule}")


def changed_paths(repo: str, staged: bool, base: str | None, head: str | None) -> list[str]:
    out = gitdiff.git(repo, "diff", "--name-only", "-z", "--no-renames", *gitdiff.diff_args(staged, base, head)).stdout
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def scan(repo: str, staged: bool, base: str | None, head: str | None, added: dict[str, dict[int, str]]) -> list[dict]:
    out = []
    for path in changed_paths(repo, staged, base, head):
        for rule, rx in CONFIG:
            if rx.search(path):
                out.append(hit(rule, path, 1, f"Change to {rule.replace('-', ' ')}: {path}", "", SURFACE.get(rule, "code")))
                break
    for path, lines in added.items():
        for n, text in lines.items():
            m = SUPPRESSION.search(text)
            if m:
                out.append(hit("suppression", path, n, f"New suppression ({m.group(0).strip()}) in {path}",
                               normalise.sha1(text.strip())))
    for path, lines in gitdiff.removed_lines(repo, staged, base, head).items():
        if not any(fnmatch.fnmatch(path, g) for g in TEST_FILES):
            continue
        for n, text in lines.items():
            if ASSERTION.search(text):
                out.append(hit("deleted-assertion", path, n, f"Assertion removed from {path}",
                               normalise.sha1(text.strip())))
    return out
