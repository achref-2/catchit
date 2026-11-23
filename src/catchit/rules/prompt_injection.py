import re

from catchit.models import Finding, RepoFile, Severity

INVISIBLE = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
AGENT_WORDS = re.compile(
    r"(ignore (all |the )?previous instructions|you are an ai|ai assistant|"
    r"as an (ai|llm|agent)|do not tell the user|run the following command)",
    re.IGNORECASE,
)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def check(f: RepoFile) -> list[Finding]:
    out = []

    if m := INVISIBLE.search(f.content):
        out.append(Finding("PI001", "prompt_injection", Severity.HIGH, f.path,
                           _line(f.content, m.start()), "Invisible Unicode characters found"))

    for m in HTML_COMMENT.finditer(f.content):
        if AGENT_WORDS.search(m.group(1)):
            out.append(Finding("PI002", "prompt_injection", Severity.HIGH, f.path,
                               _line(f.content, m.start()),
                               "Hidden HTML comment addresses an AI agent"))

    return out