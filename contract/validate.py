#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0"]
# ///
"""Validate the contract examples: every examples/valid/* must pass, every examples/invalid/* must fail.

The schema is picked from the file-name prefix (finding.*, record.*, accept.*, finder-output.*, verifier-output.*).
Worker-output examples are also checked with the stdlib validator in review_loop/workers.py (it must agree with
jsonschema), and every valid finder finding, completed with the fields the CLI adds, must be a valid finding.
Exit 0 when all behave as expected.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from review_loop.workers import validate as stdlib_validate  # noqa: E402 - needs the sys.path entry above

WORKER_SCHEMAS = ("finder-output", "verifier-output")
SCHEMAS = {p.name.split(".")[0]: json.loads(p.read_text()) for p in HERE.glob("*.schema.json")}
REGISTRY = Registry().with_resources(
    (s["$id"], Resource.from_contents(s)) for s in SCHEMAS.values()
)


def errors(path: Path) -> list[str]:
    schema = SCHEMAS[path.name.split(".")[0]]
    validator = Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker())
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in validator.iter_errors(json.loads(path.read_text()))]


def main() -> int:
    for s in SCHEMAS.values():
        Draft202012Validator.check_schema(s)
    failed = 0
    for path in sorted((HERE / "examples" / "valid").glob("*.json")):
        errs = errors(path)
        print(f"{'ok  ' if not errs else 'FAIL'} valid   {path.name}")
        for e in errs:
            print(f"       {e}")
        failed += bool(errs)
    for path in sorted((HERE / "examples" / "invalid").glob("*.json")):
        errs = errors(path)
        print(f"{'ok  ' if errs else 'FAIL'} invalid {path.name}" + (f"  ({errs[0][:90]})" if errs else "  (accepted, should be rejected)"))
        failed += not errs
    for path in sorted((HERE / "examples").glob("*/*.json")):
        name = path.name.split(".")[0]
        if name not in WORKER_SCHEMAS:
            continue
        accepted = not stdlib_validate(json.loads(path.read_text()), SCHEMAS[name])
        agree = accepted == (path.parent.name == "valid")
        print(f"{'ok  ' if agree else 'FAIL'} stdlib  {path.parent.name}/{path.name}")
        failed += not agree
    for path in sorted((HERE / "examples" / "valid").glob("finder-output.*.json")):
        for i, f in enumerate(json.loads(path.read_text())["findings"]):
            stored = {k: v for k, v in f.items() if v is not None or k == "failure_scenario"}
            stored.update(id="rev-000000000000", rule_class=None, introduced_by="diff", status="advisory")
            errs = [e.message for e in Draft202012Validator(SCHEMAS["finding"], registry=REGISTRY).iter_errors(stored)]
            print(f"{'ok  ' if not errs else 'FAIL'} derived {path.name}#{i} as finding" + (f"  ({errs[0][:90]})" if errs else ""))
            failed += bool(errs)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
