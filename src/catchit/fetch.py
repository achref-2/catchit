import base64
import os
import re

import httpx

from catchit.models import RepoFile

API = "https://api.github.com"

INTERESTING = re.compile(
    r"(^|/)("
    r"README(\.md)?|CLAUDE\.md|AGENTS\.md|\.cursorrules|copilot-instructions\.md|"
    r"setup\.py|pyproject\.toml|requirements.*\.txt|package\.json|"
    r"Makefile|install\.sh|tasks\.json|\.mcp\.json|devcontainer\.json"
    r")$",
    re.IGNORECASE,
)
MAX_FILES = 40


def parse_repo(url_or_slug: str) -> str:
    m = re.search(r"(?:github\.com/)?([\w.-]+/[\w.-]+?)(?:\.git)?/?$", url_or_slug.strip())
    if not m:
        raise ValueError(f"Not a GitHub repo: {url_or_slug}")
    return m.group(1)


def _client() -> httpx.Client:
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=API, headers=headers, timeout=20)


def fetch_files(slug: str) -> list[RepoFile]:
    with _client() as c:
        branch = c.get(f"/repos/{slug}").raise_for_status().json()["default_branch"]
        tree = c.get(f"/repos/{slug}/git/trees/{branch}", params={"recursive": 1})
        paths = [
            item["path"]
            for item in tree.raise_for_status().json()["tree"]
            if item["type"] == "blob" and INTERESTING.search(item["path"])
        ][:MAX_FILES]

        files = []
        for path in paths:
            data = c.get(f"/repos/{slug}/contents/{path}", params={"ref": branch}).json()
            raw = base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
            files.append(RepoFile(path=path, content=raw))
        return files