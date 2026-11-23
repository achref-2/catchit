import json
import re

from catchit.models import Finding, RepoFile, Severity

PIPE_TO_SHELL = re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b")


def check(f: RepoFile) -> list[Finding]:
    out = []
    name = f.path.rsplit("/", 1)[-1].lower()

    if name == "package.json":
        try:
            scripts = json.loads(f.content).get("scripts", {})
        except json.JSONDecodeError:
            scripts = {}
        for hook in ("preinstall", "install", "postinstall"):
            if hook in scripts:
                out.append(Finding("AE001", "auto_exec", Severity.MEDIUM, f.path, None,
                                   f"npm '{hook}' script runs on install: {scripts[hook]!r}"))

    if name == "tasks.json" and '"folderOpen"' in f.content:
        out.append(Finding("AE002", "auto_exec", Severity.HIGH, f.path, None,
                           "VS Code task runs automatically when the folder is opened"))

    for m in PIPE_TO_SHELL.finditer(f.content):
        out.append(Finding("AE003", "auto_exec", Severity.MEDIUM, f.path,
                           f.content.count("\n", 0, m.start()) + 1,
                           "Downloads a script and pipes it straight into a shell"))

    return out