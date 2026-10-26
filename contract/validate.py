#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0"]
# ///
"""Validate the contract examples: every examples/valid/* must pass, every examples/invalid/* must fail.

The schema is picked from the file-name prefix (finding.*, record.*, accept.*). Exit 0 when all behave as expected.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

HERE = Path(__file__).resolve().parent
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
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
