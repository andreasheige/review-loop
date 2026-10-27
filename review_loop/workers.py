"""Model workers: one finder or verifier run through `claude -p` or `codex exec`, read-only, output checked.

usage: review-loop worker --harness claude|codex --role find|verify --model M --input FILE [--repo DIR] [--rev REV]

The CLI runs the worker in a stripped scratch worktree of --repo at --rev (launcher.py), never in the repo itself.

`run_claude` / `run_codex` return {"output": <schema-valid JSON>, "usage": {...}, "attempts": n}. Malformed or
missing output gets one retry with the validator error appended to the prompt, then WorkerError: the CLI exits 3,
never 0. The runner (argv, stdin, cwd, timeout, env) -> CompletedProcess is injectable for tests.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from . import launcher
from .gitdiff import GitError

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contract"
PROMPTS = ROOT / "prompts"
TIMEOUT = 1800
LENSES = ("correctness", "security", "scope", "simplify", "conformance", "seam")
ROLES = {"find": "finder-output", "verify": "verifier-output"}

Runner = Callable[[list, str, str, float, dict], subprocess.CompletedProcess]


class WorkerError(Exception):
    pass


def default_runner(argv: list, stdin: str, cwd: str, timeout: float, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=stdin, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


# ------------------------------------------------------------------ schema subset validator

ANNOTATIONS = {"$schema", "$id", "title", "description"}
TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def validate(value, schema: dict, path: str = "") -> list[str]:
    """Errors for `value` against the JSON Schema subset the worker schemas use. An unknown keyword is an
    error, so a schema change the validator does not understand fails closed instead of passing silently."""
    where = path or "<root>"
    errs = []
    for key in schema:
        if key not in ANNOTATIONS and key not in KEYWORDS:
            return [f"{where}: unsupported schema keyword {key!r}"]
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(TYPES[t](value) for t in types):
            return [f"{where}: expected {'|'.join(types)}, got {type(value).__name__}"]
    if "enum" in schema and not any(value == e and type(value) is type(e) for e in schema["enum"]):
        errs.append(f"{where}: {value!r} not in {schema['enum']}")
    if "const" in schema and value != schema["const"]:
        errs.append(f"{where}: must be {schema['const']!r}")
    if "anyOf" in schema:
        branches = [validate(value, s, path) for s in schema["anyOf"]]
        if all(branches):
            errs.append(f"{where}: matches no anyOf branch ({'; '.join(b[0] for b in branches)})")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errs.append(f"{where}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{where}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{where}: does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value < schema.get("minimum", value):
        errs.append(f"{where}: below {schema['minimum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errs.append(f"{where}: fewer than {schema['minItems']} items")
        for i, item in enumerate(value):
            errs += validate(item, schema.get("items", {}), f"{path}/{i}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        errs += [f"{where}: missing {k!r}" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            errs += [f"{where}: unexpected {k!r}" for k in value if k not in props]
        for k, v in value.items():
            if k in props:
                errs += validate(v, props[k], f"{path}/{k}")
    return errs


KEYWORDS = {"type", "enum", "const", "anyOf", "minLength", "maxLength", "pattern", "minimum", "minItems", "items",
            "required", "additionalProperties", "properties"}


def load_schema(name: str) -> dict:
    return json.loads((CONTRACT / f"{name}.schema.json").read_text())


# ------------------------------------------------------------------ prompts


def fence(text: str) -> str:
    """Wrap text in a code fence longer than any backtick run inside it, so the text cannot close it."""
    ticks = "`" * max(3, max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    return f"{ticks}\n{text}\n{ticks}"


def render(name: str, **values: str) -> str:
    """prompts/<name>.md with its leading <!-- --> comment stripped and {{KEY}} filled in one pass, so a
    placeholder inside a value (e.g. in the diff) is never substituted."""
    text = re.sub(r"\A<!--.*?-->\s*", "", (PROMPTS / f"{name}.md").read_text(), flags=re.S)
    return re.sub(r"\{\{([A-Z_]+)\}\}", lambda m: values[m.group(1)], text)


def find_prompt(intent: str, diff: str, changed_paths: list[str], lenses=LENSES) -> str:
    return render("find", INTENT=intent, DIFF=fence(diff), CHANGED_PATHS="\n".join(f"- {p}" for p in changed_paths),
                  LENSES=", ".join(lenses))


def verify_prompt(finding_id: str, finding: dict, diff: str) -> str:
    return render("verify", FINDING_ID=finding_id, FINDING=fence(json.dumps(finding, indent=2)), DIFF=fence(diff))


# ------------------------------------------------------------------ adapters


def retry_prompt(prompt: str, error: str) -> str:
    return (f"{prompt}\n\n<previous_attempt>\nYour previous output was rejected: {error[:2000]}\n"
            "Return only JSON that matches the schema.\n</previous_attempt>\n")


def with_retry(prompt: str, schema: dict, once: Callable[[str], tuple]) -> dict:
    """Call once(prompt) -> (output or None, usage, error); retry once with the error; raise WorkerError."""
    usage, error = {}, ""
    for attempt in (1, 2):
        output, used, error = once(prompt if attempt == 1 else retry_prompt(prompt, error))
        for k, v in used.items():
            usage[k] = usage.get(k, 0) + v
        if error is None:
            errs = validate(output, schema)
            if not errs:
                return {"output": output, "usage": usage, "attempts": attempt}
            error = "schema: " + "; ".join(errs[:10])
    raise WorkerError(f"malformed worker output after 2 attempts: {error}")


def claude_usage(out: dict) -> dict:
    u = out.get("usage") or {}
    used = {k: u.get(k, 0) for k in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")}
    if isinstance(out.get("total_cost_usd"), (int, float)):
        used["cost_usd"] = out["total_cost_usd"]
    return used


def parse_claude(stdout: str) -> tuple:
    """(structured output or None, usage, error or None) from `claude -p --output-format json` stdout."""
    try:
        out = json.loads(stdout)
    except json.JSONDecodeError:
        return None, {}, "claude stdout is not JSON: " + stdout[-300:]
    if not isinstance(out, dict):
        return None, {}, "claude stdout is not a JSON object"
    used = claude_usage(out)
    if out.get("is_error"):
        return None, used, f"claude error: {str(out.get('result'))[-300:]}"
    structured = out.get("structured_output")
    if structured is None:
        try:
            structured = json.loads(out.get("result") or "")
        except (json.JSONDecodeError, TypeError):
            return None, used, "no structured output"
    return structured, used, None


CLAUDE_SETTINGS = {"permissions": {"deny": ["Read(**/.env*)"]}}
# read-only: :minimal (system and runtime paths) plus the workspace, nothing else under $HOME; no network
CODEX_PROFILE = ['-c', 'default_permissions="review-loop"',
                 '-c', 'permissions.review-loop.filesystem={":minimal"="read",":workspace_roots"={"."="read","**/.env*"="deny"}}']


def run_claude(prompt: str, schema: dict, cwd: str, model: str, runner: Runner = default_runner) -> dict:
    # claude --json-schema rejects the draft-2020-12 $schema meta reference; the schema itself is unchanged
    bare = {k: v for k, v in schema.items() if k != "$schema"}
    # --restricted: no user/project settings (so no hooks), file tools confined to cwd; --safe-mode: no CLAUDE.md,
    # skills or plugins; the deny rule covers .env* the worktree strip missed (e.g. created after checkout)
    argv = ["claude", "-p", "--model", model, "--restricted", "--safe-mode", "--strict-mcp-config",
            "--tools", "Read,Grep,Glob", "--settings", json.dumps(CLAUDE_SETTINGS),
            "--output-format", "json", "--json-schema", json.dumps(bare)]

    def once(text):
        # prompt on stdin: --tools is variadic and would swallow a trailing positional prompt
        try:
            p = runner(argv, text, cwd, TIMEOUT, launcher.worker_env())
        except subprocess.TimeoutExpired:
            return None, {}, "timeout"
        output, used, error = parse_claude(p.stdout)
        if error and p.returncode:
            error = f"exit {p.returncode}: {error}; stderr: {p.stderr[-300:]}"
        return output, used, error

    return with_retry(prompt, schema, once)


def codex_usage(stdout: str) -> dict:
    """Token counts from the last usage event in `codex exec --json` output."""
    used = {}
    for line in stdout.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        u = (ev.get("usage") or (ev.get("msg") or {}).get("usage")) if isinstance(ev, dict) else None
        if isinstance(u, dict):
            used = {k: v for k, v in u.items() if isinstance(v, int) and not isinstance(v, bool)}
    return used


def run_codex(prompt: str, schema: dict, cwd: str, model: str | None = None, runner: Runner = default_runner) -> dict:
    with tempfile.TemporaryDirectory(prefix="review-loop-codex-") as td, launcher.codex_home() as home:
        schema_file, out_file = Path(td) / "schema.json", Path(td) / "out.json"
        schema_file.write_text(json.dumps(schema))
        # the profile replaces -s read-only: it also denies $HOME outside the workspace (verified with codex sandbox)
        argv = ["codex", "exec", *CODEX_PROFILE, "--ignore-user-config", "--ignore-rules", "--ephemeral",
                "--skip-git-repo-check", "--output-schema", str(schema_file), "-o", str(out_file), "--json"]
        argv += ["-m", model] if model else []
        argv.append("-")  # prompt on stdin: a diff can exceed the argv size limit

        def once(text):
            out_file.unlink(missing_ok=True)
            try:
                p = runner(argv, text, cwd, TIMEOUT, launcher.worker_env({"CODEX_HOME": home}))
            except subprocess.TimeoutExpired:
                return None, {}, "timeout"
            used = codex_usage(p.stdout)
            try:
                return json.loads(out_file.read_text()), used, None
            except (OSError, json.JSONDecodeError) as e:
                return None, used, f"exit {p.returncode}: no valid output file ({type(e).__name__}); stderr: {p.stderr[-300:]}"

        return with_retry(prompt, schema, once)


# ------------------------------------------------------------------ CLI


class Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2, which would read as needs_human
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(3)


def main(argv: list[str], runner: Runner = default_runner) -> int:
    ap = Parser(prog="review-loop worker", description=__doc__.splitlines()[0])
    ap.add_argument("--harness", choices=("claude", "codex"), required=True)
    ap.add_argument("--role", choices=tuple(ROLES), required=True)
    ap.add_argument("--model")
    ap.add_argument("--input", required=True, help="the rendered prompt")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--rev", default="HEAD")
    args = ap.parse_args(argv)
    try:
        prompt = Path(args.input).read_text()
        schema = load_schema(ROLES[args.role])
        with launcher.scratch_worktree(args.repo, args.rev) as wt:
            if args.harness == "claude":
                out = run_claude(prompt, schema, wt, args.model or "sonnet", runner)
            else:
                out = run_codex(prompt, schema, wt, args.model, runner)
    except (WorkerError, GitError, OSError) as e:
        error = str(e)
    except Exception as e:  # noqa: BLE001 - an unexpected crash must be exit 3, never 0
        error = f"internal error: {type(e).__name__}"
    else:
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    json.dump({"exit_code": 3, "summary": "error", "error": error}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 3
