#!/usr/bin/env python3
"""Rule-based, source-only security review for the two local training apps."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent
RULES = {
    "app1/app.js": [
        (
            re.compile(r"\.innerHTML\s*="),
            "HIGH",
            "User input is inserted into innerHTML, which can cause DOM-based XSS.",
            "Use textContent for plain text, or sanitize HTML with a trusted library.",
        ),
        (
            re.compile(
                r"\b\w*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD)\s*=\s*['\"][^'\"]+['\"]",
                re.I,
            ),
            "MEDIUM",
            "A hard-coded credential in JavaScript is visible to every user.",
            "Keep secrets out of frontend code; store them on the backend and rotate any exposed real credential.",
        ),
    ],
    "app2/app.py": [
        (
            re.compile(r"\bSELECT\b.*\+\s*\w+", re.I),
            "HIGH",
            "SQL is concatenated with input instead of using parameter binding.",
            "Use a parameterized query, for example WHERE name LIKE ?, and pass the value separately.",
        ),
        (
            re.compile(r"\b\w+\s*=\s*PUBLIC_DIR\s*/\s*filename\b"),
            "HIGH",
            "A user-supplied filename is joined to a path without restricting it to the intended directory.",
            "Resolve the path and reject it unless it remains inside PUBLIC_DIR.",
        ),
    ],
}


def scan_file(relative_path: str, rules: list[tuple]) -> list[tuple[int, str, str, str]]:
    source_path = ROOT / relative_path
    try:
        lines = source_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        print(f"ERROR: Could not read {relative_path}: {error}", file=sys.stderr)
        raise

    findings = []
    for line_number, line in enumerate(lines, start=1):
        for pattern, severity, issue, recommendation in rules:
            if pattern.search(line):
                findings.append((line_number, severity, issue, recommendation))
    return findings


def main() -> int:
    print("Python Security Agent - local source scan (does not run apps or scan networks)")
    print("Scope: app1/app.js and app2/app.py\n")

    total = 0
    for relative_path, rules in RULES.items():
        print(f"[{relative_path}]")
        findings = scan_file(relative_path, rules)
        if not findings:
            print("  No configured patterns found.")
            continue
        for line_number, severity, issue, recommendation in findings:
            total += 1
            print(f"  {severity} - line {line_number}: {issue}")
            print(f"    Recommendation: {recommendation}")

    print(f"\nSummary: {total} rule-based finding(s).")
    print("This is a rule-based static analyzer, not an LLM; manually review its results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
