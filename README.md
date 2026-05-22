<div align="center">

<img src="https://img.shields.io/badge/OpenCode-Skill_Builder-blue?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0tMiAxNWwtNS01IDEuNDEtMS40MUwxMCAxNC4xN2w3LjU5LTcuNTlMMTkgOGwtOSA5eiIvPjwvc3ZnPg==" />
<img src="https://img.shields.io/badge/Bug%20Bounty-HackerOne%20%7C%20GitHub%20Writeups-red?style=for-the-badge" />
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Model-DeepSeek_v4_Flash_(Free)-green?style=for-the-badge" />

# Public Skills Builder

**Generate OpenCode agent bug bounty skills from public HackerOne reports and GitHub writeups — no private reports, no paid API needed.**

Feed it 500+ public bug bounty reports. Get back 18 ready-to-use OpenCode skill files — one per vulnerability class — packed with real-world techniques, payloads, and bypass patterns.

Powered by **OpenCode Zen** (`deepseek-v4-flash-free`) — completely free to run.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)

[Quick Start](#quick-start) · [Output](#output) · [Sources](#sources) · [Usage](#usage)

</div>

---

## Why Use This

Bug bounty reports are the best training data for hunting. This tool reads hundreds of disclosed HackerOne reports and community writeups, then uses DeepSeek (via OpenCode Zen) to distill them into structured skill files you can load directly into OpenCode.

No private reports required. No paid API required. Everything comes from public data.

---

## Quick Start

```bash
git clone https://github.com/OoS-MaMaD/public-skills-builder
cd public-skills-builder

python3 -m venv .venv
source .venv/bin/activate
pip install openai requests

cp .env.example .env
# Edit .env — add your OPENCODE_API_KEY
# Get it at: https://opencode.ai/zen
```

---

## Sources

| Source | Auth needed | What it fetches |
|--------|-------------|-----------------|
| HackerOne public feed | None | Publicly disclosed reports |
| HackerOne REST API | H1 API key | Your own resolved reports |
| GitHub writeup repos | None (optional token) | 1,200+ community writeups |

---

## Output

One skill directory per vulnerability class, ready to load into OpenCode:

```
skills/
  hunt-idor/SKILL.md
  hunt-ssrf/SKILL.md
  hunt-xss/SKILL.md
  hunt-rce/SKILL.md
  hunt-oauth/SKILL.md
  hunt-sqli/SKILL.md
  hunt-business-logic/SKILL.md
  ... (18 vuln classes total)
  README.md  ← index of all skills
```

Each `SKILL.md` contains:
- YAML frontmatter (name, description, report_count)
- Crown jewel targets
- Attack surface signals
- Step-by-step hunting methodology
- Payloads and grep patterns
- Bypass techniques
- Gate 0 validation checklist

---

## Usage

```bash
# Public GitHub writeups only (just needs OPENCODE_API_KEY)
python3 public_skills_builder.py --source github

# HackerOne public disclosed reports (no H1 key needed)
python3 public_skills_builder.py --source h1-public

# Everything — all sources, all vuln classes
python3 public_skills_builder.py --source all --limit 500

# Specific vuln classes only
python3 public_skills_builder.py --vuln-type idor ssrf xss oauth

# Specific H1 program
python3 public_skills_builder.py --source h1 --program shopify --limit 200

# Use a different Zen model
python3 public_skills_builder.py --model opencode/qwen3.6-plus-free
```

---

## Supported Vuln Classes

`idor` `ssrf` `xss` `sqli` `rce` `auth-bypass` `oauth` `race-condition`
`business-logic` `graphql` `cache-poison` `xxe` `upload` `ssti` `csrf`
`subdomain` `llm-ai` `crypto`

---

## Using the Skills in OpenCode

Once generated, copy the skill directories into your OpenCode config:

```bash
# Global (available in all projects)
cp -r skills/* ~/.config/opencode/skills/

# Project-local only
mkdir -p .opencode/skills
cp -r skills/hunt-idor .opencode/skills/
```

Then in OpenCode:
```
> Load skill hunt-idor and help me hunt IDOR on target.com
```

### Also Compatible with Claude Code

Skills use the shared Agent Skills open standard — they work in both tools:

```bash
cp -r skills/hunt-ssrf .claude/skills/
```

---

## Available Free Models on Zen

| Model | Notes |
|-------|-------|
| `opencode/deepseek-v4-flash-free` | **Default** — fast, strong reasoning |
| `opencode/qwen3.6-plus-free` | Alternative free option |
| `opencode/nemotron-3-super-free` | NVIDIA model |

Switch model with: `--model opencode/qwen3.6-plus-free`

---

## Requirements

- Python 3.10+
- `OPENCODE_API_KEY` — from [opencode.ai/zen](https://opencode.ai/zen) (free models available)
- `H1_API_KEY` — optional, from [hackerone.com/settings/api_token](https://hackerone.com/settings/api_token)
- `GITHUB_TOKEN` — optional, increases GitHub API rate limits

---

## Legal

For authorized security testing only. Only test targets within an approved bug bounty program scope.

---

<div align="center">

MIT License · Built for bug hunters who learn from the community

Originally based on [shuvonsec/public-skills-builder](https://github.com/shuvonsec/public-skills-builder) — adapted for OpenCode + DeepSeek

</div>
