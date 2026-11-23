import re

from catchit.models import Finding, RepoFile, Severity

EXEC_DECODE = re.compile(r"\b(exec|eval)\s*\(\s*.*?(b64decode|fromhex|decode\(|zlib)", re.IGNORECASE)
LONG_BASE64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


def check(f: RepoFile) -> list[Finding]:
    out = []
    for i, line in enumerate(f.content.splitlines(), start=1):
        if EXEC_DECODE.search(line):
            out.append(Finding("OB001", "obfuscation", Severity.HIGH, f.path, i,
                               "Executes decoded/hidden code"))
        elif LONG_BASE64.search(line):
            out.append(Finding("OB002", "obfuscation", Severity.LOW, f.path, i,
                               "Very long base64-like blob"))
    return out