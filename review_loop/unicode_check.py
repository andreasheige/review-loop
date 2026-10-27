"""D2: hidden Unicode in ADDED lines → hard, rule_class unicode.

Flagged: general category Cf (bidi controls, zero-width, U+2060–2064, U+FEFF except a BOM at file start,
U+00AD, U+180E, tags E0000–E007F), variation selectors FE00–FE0F / E0100–E01EF, Hangul fillers U+115F/U+3164.
ZWJ (U+200D) and VS16 (U+FE0F) inside emoji sequences are allowed, except in agent-config files.
Codepoints are reported as U+XXXX; the raw character never goes into the output.
"""
from __future__ import annotations

import unicodedata

from . import VERSION
from .normalise import finding, sha1

BIDI = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
ZERO_WIDTH = {0x180E, 0x200B, 0x200C, 0x200D, *range(0x2060, 0x2065), 0xFEFF}
ZWJ, VS16, KEYCAP = 0x200D, 0xFE0F, 0x20E3
AGENT_FILES = {"agents.md", "claude.md"}
AGENT_DIRS = {".claude", ".codex", ".pi", ".cursor"}


def char_class(cp: int) -> str | None:
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation-selector"
    if cp in (0x115F, 0x3164):
        return "hangul-filler"
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if unicodedata.category(chr(cp)) != "Cf":
        return None
    if cp in BIDI:
        return "bidi"
    return "zero-width" if cp in ZERO_WIDTH else "format"


def is_agent_config(path: str) -> bool:
    parts = path.split("/")
    return (parts[-1].lower() in AGENT_FILES or path.lower() == ".github/copilot-instructions.md"
            or path.lower().endswith(".mdc") or any(p in AGENT_DIRS for p in parts[:-1]))


def is_emoji(cp: int) -> bool:
    # stdlib has no Extended_Pictographic; these blocks cover the emoji that take ZWJ/VS16
    return (0x1F000 <= cp <= 0x1FAFF or 0x2190 <= cp <= 0x21FF or 0x2300 <= cp <= 0x23FF
            or 0x25A0 <= cp <= 0x27BF or 0x2900 <= cp <= 0x297F or 0x2B00 <= cp <= 0x2BFF
            or cp in (0xA9, 0xAE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299))


def in_emoji_sequence(cps: list[int], i: int) -> bool:
    cp = cps[i]
    prev = next((c for c in reversed(cps[:i]) if c != VS16 and not 0x1F3FB <= c <= 0x1F3FF), None)
    nxt = cps[i + 1] if i + 1 < len(cps) else None
    if cp == ZWJ:
        return prev is not None and nxt is not None and is_emoji(prev) and is_emoji(nxt)
    if cp == VS16:
        base = cps[i - 1] if i else None
        return base is not None and (is_emoji(base) or (chr(base) in "#*0123456789" and nxt == KEYCAP))
    return False


def scan(added: dict[str, dict[int, str]]) -> list[dict]:
    findings = []
    for path, lines in added.items():
        agent = is_agent_config(path)
        for lineno, text in lines.items():
            cps = [ord(c) for c in text]
            hits: dict[str, list[int]] = {}
            for i, cp in enumerate(cps):
                cls = char_class(cp)
                if cls is None or (cp == 0xFEFF and lineno == 1 and i == 0):
                    continue
                if not agent and cp in (ZWJ, VS16) and in_emoji_sequence(cps, i):
                    continue
                hits.setdefault(cls, []).append(i)
            if not hits:
                continue
            flagged = {i for idx in hits.values() for i in idx}
            stripped = " ".join("".join(c for i, c in enumerate(text) if i not in flagged).split())
            k = sha1(stripped)
            for cls, idx in hits.items():
                codepoints = ", ".join(f"U+{cp:04X}" for cp in sorted({cps[i] for i in idx}))
                findings.append(finding(
                    tool="unicode", rule=cls, path=path, k=k, lines=(lineno, lineno), status="hard",
                    rule_class="unicode", surface="agent-config" if agent else "code",
                    title=f"Hidden Unicode ({cls}: {codepoints}) added in {path}",
                    reasoning=f"Added line {lineno} contains {codepoints} ({cls})"
                              + ("; agent-config file, no emoji allowance." if agent else "."),
                    ref=f"review-loop@{VERSION}:unicode-{cls}",
                ))
    return findings
