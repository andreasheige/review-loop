#!/usr/bin/env python3
"""Red-team bypass matrix, hook level: feed every probe to each harness's live PreToolUse guard chain.

usage: run.py [--out redteam/results/<date>.tsv]

Nothing in a probe is executed: each probe becomes the payload the harness would send, in that
harness's wire format, and is piped into the same hook commands the harness has configured.
Verdicts: deny / ask / allow / no-hook (the harness has no guard for that tool at all).
Block-log writes go to /dev/null so probes don't pollute the agent-safety metrics.
"""
import argparse
import base64
import datetime
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = str(Path.home())
GUARDRAIL = f"{HOME}/.claude/hooks/guardrail.sh"
SECRET = f"{HOME}/.agent-global/hooks/secret-placement.sh"
COPILOT = f"{HOME}/.agent-global/hooks/copilot-pretooluse.sh"
AGY = f"{HOME}/.agent-global/hooks/antigravity-pretooluse.sh"
ANTIGRAVITY_HOOKS = Path(HOME) / ".gemini/config/hooks.json"
HARNESSES = ["claude", "codex", "copilot", "pi", "antigravity"]


def call(script, payload, harness):
    env = {**os.environ, "GUARD_LOG": "/dev/null", "AGENT_HARNESS": harness}
    p = subprocess.run(["bash", script], input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30)
    if p.returncode == 2:
        return "deny"
    try:
        out = json.loads(p.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return "allow"
    decision = (out.get("hookSpecificOutput") or {}).get("permissionDecision") or out.get("permissionDecision") or "allow"
    return {"deny": "deny", "ask": "ask"}.get(decision, "allow")


def strongest(verdicts):
    for v in ("deny", "ask", "allow"):
        if v in verdicts:
            return v
    return "no-hook"


def claude_like(kind, arg, cwd, harness):
    """Claude Code and Pi: guardrail on Bash|Read|Write|Edit (plan 6.3), secret-placement on Write|Edit|Bash."""
    if kind == "bash":
        payload, scripts = {"tool_name": "Bash", "tool_input": {"command": arg}}, [GUARDRAIL, SECRET]
    elif kind == "read":
        payload, scripts = {"tool_name": "Read", "tool_input": {"file_path": arg}}, [GUARDRAIL]
    elif kind == "edit":
        payload, scripts = {"tool_name": "Edit", "tool_input": {"file_path": arg, "old_string": "a", "new_string": "b"}}, [GUARDRAIL, SECRET]
    else:
        payload, scripts = {"tool_name": "Write", "tool_input": {"file_path": arg, "content": "#!/bin/sh\nexit 0\n"}}, [GUARDRAIL, SECRET]
    payload.update(cwd=cwd, hook_event_name="PreToolUse", session_id="redteam")
    return strongest([call(s, payload, harness) for s in scripts])


def codex(kind, arg, cwd):
    """Codex: guardrail + secret-placement on Bash and on apply_patch (plan 6.3); reads go through the shell."""
    if kind == "read":
        kind, arg = "bash", f"cat {arg}"
    if kind == "bash":
        payload, scripts = {"tool_name": "Bash", "tool_input": {"command": arg}}, [GUARDRAIL, SECRET]
    else:
        verb = "Update" if kind == "edit" else "Add"
        patch = f"*** Begin Patch\n*** {verb} File: {arg}\n@@\n+x\n*** End Patch"
        payload, scripts = {"tool_name": "apply_patch", "tool_input": {"command": patch}}, [GUARDRAIL, SECRET]
    payload.update(cwd=cwd, hook_event_name="PreToolUse", session_id="redteam")
    return strongest([call(s, payload, "codex") for s in scripts])


def copilot(kind, arg, cwd):
    args = {"bash": {"command": arg}, "read": {"path": arg}, "edit": {"path": arg, "old_str": "a", "new_str": "b"},
            "write": {"path": arg, "file_text": "#!/bin/sh\nexit 0\n"}}[kind]
    tool = {"bash": "bash", "read": "view", "edit": "edit", "write": "create"}[kind]
    return call(COPILOT, {"toolName": tool, "cwd": cwd, "toolArgs": args}, "copilot")


def antigravity(kind, arg, cwd):
    """Antigravity: one adapter on every tool (matcher "*"); no hooks.json means no guard at all."""
    if not ANTIGRAVITY_HOOKS.exists():
        return "no-hook"
    call_ = {"bash": ("run_command", {"CommandLine": arg, "Cwd": cwd}), "read": ("view_file", {"AbsolutePath": arg}),
             "edit": ("replace_file_content", {"TargetFile": arg, "ReplacementChunks": [{"TargetContent": "a", "ReplacementContent": "b"}]}),
             "write": ("write_to_file", {"TargetFile": arg, "CodeContent": "#!/bin/sh\nexit 0\n"})}[kind]
    payload = {"toolCall": {"name": call_[0], "args": call_[1]}, "conversationId": "redteam", "workspacePaths": [cwd]}
    env = {**os.environ, "GUARD_LOG": "/dev/null", "AGY_KEYLOG": "/dev/null"}
    p = subprocess.run(["bash", AGY], input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30)
    try:
        return {"deny": "deny", "ask": "ask"}.get(json.loads(p.stdout.strip() or "{}").get("decision"), "allow")
    except json.JSONDecodeError:
        return "allow"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "results" / f"{datetime.date.today()}-hooks.tsv"))
    a = ap.parse_args()
    probes = []
    for line in (HERE / "probes.tsv").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            pid, group, kind, arg, want = line.split("\t")
            probes.append((pid, group, kind, arg, want))
    cwd = tempfile.mkdtemp(prefix="redteam-cwd-")
    subprocess.run(["git", "init", "-q", cwd], check=True)
    # fixtures for the guardrails-md bypass rows: symlinked guard file and dir, write-then-run script
    os.symlink(GUARDRAIL, f"{cwd}/link-guard")
    os.symlink(f"{HOME}/.claude/hooks", f"{cwd}/linkdir")
    Path(f"{cwd}/evil.sh").write_text("#!/bin/sh\n" + (HERE / "probes.tsv").read_text().split("WRITE_THEN_RUN=")[1].splitlines()[0] + "\n")

    def expand(arg):
        arg = arg.replace("HOME/", HOME + "/").replace("CWD/", cwd + "/")
        if arg.startswith("B64:"):
            arg = f"echo {base64.b64encode(arg[4:].encode()).decode()} | base64 -d | sh"
        return arg
    probes = [(pid, group, kind, expand(arg), want) for pid, group, kind, arg, want in probes]
    rows = []
    for pid, group, kind, arg, want in probes:
        verdicts = {
            "claude": claude_like(kind, arg, cwd, "claude"),
            "codex": codex(kind, arg, cwd),
            "copilot": copilot(kind, arg, cwd),
            "pi": claude_like(kind, arg, cwd, "pi"),
            "antigravity": antigravity(kind, arg, cwd),
        }
        rows.append((pid, group, want, verdicts))
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        f.write("id\tgroup\twant\t" + "\t".join(HARNESSES) + "\n")
        for pid, group, want, v in rows:
            f.write(f"{pid}\t{group}\t{want}\t" + "\t".join(v[h] for h in HARNESSES) + "\n")
    ok = lambda want, got: got == want or (want == "deny" and got == "ask")
    print(f"{'id':5} {'group':8} {'want':5} " + " ".join(f"{h:11}" for h in HARNESSES))
    for pid, group, want, v in rows:
        print(f"{pid:5} {group:8} {want:5} " + " ".join(f"{v[h] + ('' if ok(want, v[h]) else ' !'):11}" for h in HARNESSES))
    for h in HARNESSES:
        held = sum(ok(want, v[h]) for _, _, want, v in rows)
        print(f"{h:12} {held}/{len(rows)} as wanted")
    print(f"written: {out}")


if __name__ == "__main__":
    sys.exit(main())
