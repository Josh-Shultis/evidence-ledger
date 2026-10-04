#!/usr/bin/env python3
"""Flag common private-data hazards before publishing this synthetic repository.

This is a limited pattern check, not a substitute for reviewing staged files.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


FORBIDDEN_SUFFIXES = {
    ".7z", ".burp", ".db", ".docx", ".har", ".jsonl", ".key",
    ".log", ".p12", ".pcap", ".pcapng", ".pdf", ".pem", ".pfx",
    ".rar", ".saz", ".sqlite", ".sqlite3", ".zip",
}
FORBIDDEN_PARTS = {
    "burp", "captures", "har", "inbox", "logs", "originals", "outputs",
    "private", "raw", "takeout", "unredacted",
}
PATTERNS = {
    "PRIVATE_KEY": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "BEARER_TOKEN": re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/-]{6,}"),
    "COOKIE_HEADER": re.compile(r"(?i)\b(?:set-cookie|cookie)\s*[:=]\s*[^\r\n]{4,}"),
    "SECRET_ASSIGNMENT": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9._~+/-]{6,}"
    ),
    "NUMERIC_CASE_ID": re.compile(r"\b[0-9]{8,12}\b"),
    "LOCAL_USER_PATH": re.compile(r"(?i)\b[A-Z]:\\(?:Users|OneDrive)\\"),
}
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
SAFE_EMAIL_DOMAINS = {"example.com", "example.test"}


def publication_files(repo: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return sorted({name.decode("utf-8", errors="surrogateescape") for name in result.stdout.split(b"\0") if name})


def scan(repo: Path) -> tuple[list[tuple[str, str]], int]:
    findings: set[tuple[str, str]] = set()
    names = publication_files(repo)
    for name in names:
        normalized = name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if {part.casefold() for part in path.parts} & FORBIDDEN_PARTS:
            findings.add((normalized, "PRIVATE_PATH"))
        if path.suffix.casefold() in FORBIDDEN_SUFFIXES or path.name.casefold().startswith(".env"):
            findings.add((normalized, "PRIVATE_FILE_TYPE"))
        source = repo / Path(normalized)
        if not source.is_file():
            continue
        try:
            content = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            findings.add((normalized, "UNREADABLE_FILE"))
            continue
        for match in EMAIL.finditer(content):
            if match.group(1).casefold() not in SAFE_EMAIL_DOMAINS:
                findings.add((normalized, "NON_EXAMPLE_EMAIL"))
                break
        for category, pattern in PATTERNS.items():
            if pattern.search(content):
                findings.add((normalized, category))
    return sorted(findings), len(names)


def main() -> int:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    findings, count = scan(repo)
    print(f"publication files scanned: {count}")
    print(f"blocked findings: {len(findings)}")
    for path, category in findings:
        print(f"BLOCKED\t{category}\t{path}")
    print("publication safety: PASS" if not findings else "publication safety: FAIL")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
