from catchit.models import Finding, RepoFile
from catchit.rules import auto_exec, obfuscation, prompt_injection

ALL_RULES = [prompt_injection.check, auto_exec.check, obfuscation.check]


def run_rules(files: list[RepoFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        for rule in ALL_RULES:
            findings.extend(rule(f))
    return findings