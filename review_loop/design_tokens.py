"""Design-token lint, warn-first: a hard-coded colour in an added line of a UI file.

Only in repos that opt in with `git config review-loop.design-tokens true`. Token, theme and palette files are
where colours belong, so they are skipped. Always `advisory` (lens ui): it points at a likely token miss and
never blocks a commit, push or ticket.
"""
from __future__ import annotations

import re

from . import gitdiff, normalise

UI_FILE = re.compile(r"\.(css|scss|sass|less|tsx|jsx|vue|svelte|html)$", re.I)
TOKEN_FILE = re.compile(r"(^|/)(tokens?|themes?|palettes?|design-system)(/|\.|$)|(^|/)(colou?rs?|variables)\.[a-z]+$"
                        r"|\.tokens\.json$", re.I)
COLOUR = re.compile(r"(?<![\w&#])#(?:[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})(?![\w-])|\b(?:rgba?|hsla?)\(\s*[\d.]", re.I)


def enabled(repo: str) -> bool:
    return gitdiff.git(repo, "config", "--bool", "review-loop.design-tokens", check=False).stdout.decode().strip() == "true"


def scan(added: dict[str, dict[int, str]]) -> list[dict]:
    out = []
    for path, lines in added.items():
        if not UI_FILE.search(path) or TOKEN_FILE.search(path):
            continue
        for line, text in lines.items():
            code = re.split(r"//|/\*|<!--", text, maxsplit=1)[0]  # an issue ref in a comment isn't a colour
            code = re.sub(r"\b(href|to)=([\"'])#[^\"']*\2", "", code)  # nor an in-page anchor
            m = COLOUR.search(code)
            if not m:
                continue
            f = normalise.finding(tool="reviewloop", rule="design-token", path=path, k=normalise.sha1(text.strip()),
                                  lines=(line, line), status="advisory", rule_class="design-token", surface="code",
                                  title=f"Hard-coded colour {m.group(0).rstrip('(').strip()} in {path}: use a design token",
                                  reasoning="design-token", ref="review-loop:design-token")
            f["lens"] = "ui"
            out.append(f)
    return out
