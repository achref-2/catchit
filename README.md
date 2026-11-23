# catchit

Scan a GitHub repo for malware patterns and AI-agent prompt injection **before** you clone it, install it, or let your coding agent touch it.

catchit reads the repo through the GitHub API. **Nothing is cloned and nothing runs on your machine.**

## Why

Developers and AI coding agents pull in other people's code all the time. Attackers hide instructions for agents in READMEs, add install scripts that run automatically, and obfuscate payloads. catchit flags these before they reach you.

## Usage

```bash
uv sync
uv run catchit scan owner/repo
uv run catchit scan https://github.com/owner/repo
```

Set `GITHUB_TOKEN` to raise the API rate limit from 60 to 5,000 requests per hour.

## What it detects

| Rule | Category | Severity | Detects |
|---|---|---|---|
| PI001 | Prompt injection | High | Invisible Unicode (zero-width, tag characters) |
| PI002 | Prompt injection | High | Hidden HTML comments addressed to AI agents |
| AE001 | Auto-execution | Medium | npm `preinstall` / `install` / `postinstall` scripts |
| AE002 | Auto-execution | High | VS Code tasks that run on folder open |
| AE003 | Auto-execution | Medium | `curl ... \| bash` style download-and-run |
| OB001 | Obfuscation | High | `exec` / `eval` on decoded data |
| OB002 | Obfuscation | Low | Very long base64-like blobs |

**Risk score:** the most severe finding sets the base (low 15, medium 45, high 80), and each additional finding adds 5, capped at 100.

## Roadmap

- [ ] Labeled dataset of malicious and clean samples
- [ ] Rules for `setup.py`, `.mcp.json`, dependencies and trust signals
- [ ] LLM layer for reworded attacks, hardened against prompt injection itself
- [ ] Benchmark against existing scanners
- [ ] Browser extension showing a risk badge on GitHub pages
- [ ] MCP server so coding agents can check a repo first

## Development

```bash
uv run pytest
```
