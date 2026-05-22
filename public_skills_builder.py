#!/usr/bin/env python3
"""
Public Skills Builder
Fetches public disclosed bug bounty reports from HackerOne + GitHub writeup repos
and generates OpenCode agent skill files organized by vulnerability class.

Sources:
  1. HackerOne REST API (authenticated)  — your own reports  (H1_API_KEY required)
  2. HackerOne Hacker API /v1/hacktivity  — public disclosed  (H1_API_KEY required)
  3. GitHub writeup collections           — no auth needed

Note: HackerOne retired the unauthenticated GraphQL hacktivity endpoint in 2024.
      Both H1 sources now require an H1_API_KEY (free H1 account + API token).
      See: https://api.hackerone.com/hacker-resources/#hacktivity-get-hacktivity

Usage:
  python public_skills_builder.py [--source h1|h1-public|github|all] [--program HANDLE]
                                   [--vuln-type TYPE] [--limit N] [--out DIR]
"""

import os
import re
import sys
import json
import time
import argparse
import textwrap
import requests
from pathlib import Path
from collections import defaultdict

try:
    from openai import OpenAI
except ImportError:
    print("[!] Missing: pip install openai requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

H1_API_BASE  = "https://api.hackerone.com/v1"

# OpenCode Zen — correct base URL.
# NOTE: ZEN_MODEL uses "opencode/" prefix for readability in logs/CLI help.
#       _api_model() strips it before the actual API call.
ZEN_BASE_URL = "https://opencode.ai/zen/v1"
ZEN_MODEL    = "opencode/deepseek-v4-flash-free"

# Max reports fed into a single LLM call.
# deepseek-v4-flash-free has a small context window (~16k tokens input).
# 20 reports × ~300 chars each ≈ 6k tokens prompt → leaves room for the
# 4096-token output. Increase to 30 if you switch to a larger-context model.
MAX_REPORTS_PER_CALL = 20

# Max chars per report description fed to the LLM (keep prompt small).
MAX_DESC_CHARS = 300


def _api_model(model: str) -> str:
    """Strip the 'opencode/' prefix — the Zen /chat/completions endpoint doesn't want it."""
    return model.removeprefix("opencode/")


GITHUB_WRITEUP_REPOS = [
    ("ngalongc",      "bug-bounty-reference",         "README.md"),
    ("devanshbatham", "Awesome-Bugbounty-Writeups",    "README.md"),
    ("djadmin",       "awesome-bug-bounty",            "README.md"),
]

VULN_KEYWORDS = {
    "idor":           ["idor", "insecure direct object", "broken access control", "horizontal privilege"],
    "ssrf":           ["ssrf", "server-side request forgery", "internal metadata"],
    "xss":            ["xss", "cross-site scripting", "stored xss", "reflected xss", "dom xss"],
    "sqli":           ["sql injection", "sqli", "blind sql", "error-based sql"],
    "rce":            ["rce", "remote code execution", "command injection", "code execution"],
    "auth-bypass":    ["authentication bypass", "auth bypass", "2fa bypass", "mfa bypass"],
    "oauth":          ["oauth", "oidc", "jwt", "pkce", "token theft", "open redirect"],
    "race-condition": ["race condition", "toctou", "double-spend", "concurrent"],
    "business-logic": ["business logic", "price manipulation", "logic flaw", "workflow bypass"],
    "graphql":        ["graphql", "introspection", "batching", "alias bypass"],
    "cache-poison":   ["cache poison", "cache deception", "web cache"],
    "xxe":            ["xxe", "xml external entity", "xml injection"],
    "upload":         ["file upload", "unrestricted upload", "webshell", "path traversal"],
    "ssti":           ["ssti", "server-side template", "template injection"],
    "csrf":           ["csrf", "cross-site request forgery"],
    "subdomain":      ["subdomain takeover", "dangling dns", "cname takeover"],
    "llm-ai":         ["prompt injection", "llm", "ai chatbot", "indirect injection", "ascii smuggling"],
    "crypto":         ["timing attack", "hmac", "signature bypass", "weak crypto", "replay attack"],
}


# ---------------------------------------------------------------------------
# H1 auth helper
# ---------------------------------------------------------------------------

def _h1_auth(api_key: str) -> tuple[tuple[str, str], bool]:
    """Parse H1_API_KEY and return (auth_tuple, valid)."""
    if not api_key or ":" not in api_key:
        return (("", ""), False)
    identifier, token = api_key.split(":", 1)
    return ((identifier, token), True)


# ---------------------------------------------------------------------------
# Source 1: HackerOne REST API — your own disclosed reports
# ---------------------------------------------------------------------------

def fetch_h1_disclosed(api_key: str, program: str | None, limit: int) -> list[dict]:
    """Fetch your own publicly disclosed reports via H1 REST API."""
    auth, valid = _h1_auth(api_key)
    if not valid:
        print("[!] H1_API_KEY must be 'identifier:token'")
        return []

    headers = {"Accept": "application/json"}
    reports = []
    page    = 1
    print(f"[*] Fetching your H1 disclosed reports (limit={limit})...")

    while len(reports) < limit:
        params: dict = {
            "filter[state][]": ["resolved"],
            "filter[disclosed]": True,
            "page[size]": min(100, limit - len(reports)),
            "page[number]": page,
            "sort": "-created_at",
        }
        if program:
            params["filter[program][]"] = program

        try:
            resp = requests.get(
                f"{H1_API_BASE}/hackers/me/reports",
                auth=auth, headers=headers, params=params, timeout=15
            )
        except requests.RequestException as e:
            print(f"[!] H1 API error: {e}")
            break

        if resp.status_code == 401:
            print("[!] H1 auth failed — check H1_API_KEY in .env (format: identifier:token)")
            break
        if resp.status_code == 429:
            print("[*] Rate limited. Waiting 30s...")
            time.sleep(30)
            continue
        if not resp.ok:
            print(f"[!] H1 API returned {resp.status_code}")
            break

        data = resp.json().get("data", [])
        if not data:
            break

        for item in data:
            attrs    = item.get("attributes", {})
            rels     = item.get("relationships", {})
            weakness = (rels.get("weakness", {}).get("data", {}) or {})
            severity = (rels.get("severity", {}).get("data", {}) or {})
            reports.append({
                "source":       "hackerone",
                "id":           item.get("id"),
                "title":        attrs.get("title", ""),
                "severity":     severity.get("attributes", {}).get("rating", ""),
                "weakness":     weakness.get("attributes", {}).get("name", ""),
                "description":  attrs.get("vulnerability_information", ""),
                "impact":       attrs.get("impact", ""),
                "program":      rels.get("program", {}).get("data", {}).get("attributes", {}).get("handle", ""),
                "url":          f"https://hackerone.com/reports/{item.get('id')}",
                "disclosed_at": attrs.get("disclosed_at", ""),
                "bounty":       "",
            })

        if len(data) < 100:
            break
        page += 1
        time.sleep(0.3)

    print(f"[+] Fetched {len(reports)} H1 disclosed reports")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Source 2: HackerOne public hacktivity via REST /v1/hacktivity (auth required)
# ---------------------------------------------------------------------------
# NOTE: HackerOne retired their unauthenticated GraphQL hacktivity endpoint in 2024.
# The official replacement is GET /v1/hacktivity which requires a free H1 API key.
# Docs: https://api.hackerone.com/hacker-resources/#hacktivity-get-hacktivity
# ---------------------------------------------------------------------------

def fetch_h1_hacktivity(api_key: str, limit: int, program: str | None = None) -> list[dict]:
    """
    Fetch public disclosed reports from HackerOne's /v1/hacktivity endpoint.
    Requires H1_API_KEY (free H1 account). Returns titles, severity, weakness,
    bounty, and report URLs for all publicly disclosed reports.
    """
    auth, valid = _h1_auth(api_key)
    if not valid:
        print("[!] H1_API_KEY required for hacktivity feed (format: identifier:token)")
        print("    Create a free API token at: https://hackerone.com/settings/api_token/edit")
        return []

    headers  = {"Accept": "application/json"}
    reports  = []
    page     = 1
    print(f"[*] Fetching H1 public hacktivity (limit={limit})...")

    while len(reports) < limit:
        params: dict = {
            "page[size]": min(100, limit - len(reports)),
            "page[number]": page,
            "sort": "-disclosed_at",
        }
        if program:
            params["filter[program][]"] = program

        try:
            resp = requests.get(
                f"{H1_API_BASE}/hacktivity",
                auth=auth, headers=headers, params=params, timeout=20
            )
        except requests.RequestException as e:
            print(f"[!] Hacktivity fetch error: {e}")
            break

        if resp.status_code == 401:
            print("[!] H1 auth failed — check H1_API_KEY in .env")
            break
        if resp.status_code == 429:
            print("[*] Rate limited. Waiting 30s...")
            time.sleep(30)
            continue
        if not resp.ok:
            print(f"[!] H1 hacktivity returned {resp.status_code} — stopping")
            break

        body = resp.json()
        data = body.get("data", [])
        if not data:
            break

        for item in data:
            attrs    = item.get("attributes", {})
            rels     = item.get("relationships", {})
            weakness = (rels.get("weakness",  {}).get("data", {}) or {})
            severity = (rels.get("severity",  {}).get("data", {}) or {})
            team     = (rels.get("team",      {}).get("data", {}) or {})
            bounty   = (rels.get("bounty",    {}).get("data", {}) or {})
            rid      = item.get("id", "")
            reports.append({
                "source":       "hackerone_public",
                "id":           str(rid),
                "title":        attrs.get("title", ""),
                "severity":     severity.get("attributes", {}).get("rating", ""),
                "weakness":     weakness.get("attributes", {}).get("name", ""),
                "description":  attrs.get("vulnerability_information", ""),
                "impact":       attrs.get("impact", ""),
                "program":      team.get("attributes", {}).get("handle", ""),
                "url":          f"https://hackerone.com/reports/{rid}",
                "disclosed_at": attrs.get("disclosed_at", ""),
                "bounty":       bounty.get("attributes", {}).get("amount", ""),
            })

        # pagination: stop when fewer results than page size
        if len(data) < params["page[size]"]:
            break
        page += 1
        time.sleep(0.4)

    print(f"[+] Fetched {len(reports)} public hacktivity reports")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Source 3: GitHub writeup collections (no auth needed)
# ---------------------------------------------------------------------------

def fetch_github_writeups(limit: int) -> list[dict]:
    """Parse awesome writeup repos from GitHub and extract report links + titles."""
    github_token = os.getenv("GITHUB_TOKEN", "")
    headers = {"User-Agent": "public-skills-builder"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    reports = []
    print("[*] Fetching GitHub writeup collections...")

    for owner, repo, path in GITHUB_WRITEUP_REPOS:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if not resp.ok:
                resp = requests.get(
                    url.replace("/master/", "/main/"),
                    headers=headers, timeout=15
                )
            if not resp.ok:
                print(f"[!] Could not fetch {owner}/{repo}")
                continue
        except requests.RequestException:
            continue

        links = re.findall(r'\[([^\]]+)\]\((https?://[^\)]+)\)', resp.text)

        for title, link_url in links:
            if len(reports) >= limit:
                break
            if any(kw in link_url.lower() for kw in [
                "medium.com", "infosec", "writeup", "hackerone.com/reports",
                "blog", "notion.so", "github.io", "portswigger", "bugcrowd"
            ]):
                reports.append({
                    "source":       f"github:{owner}/{repo}",
                    "id":           re.sub(r'[^a-z0-9]', '-', title.lower())[:40],
                    "title":        title,
                    "severity":     "",
                    "weakness":     classify_report(title, ""),
                    "description":  f"Public writeup: {title}",
                    "impact":       "",
                    "program":      "",
                    "url":          link_url,
                    "disclosed_at": "",
                    "bounty":       "",
                })

        print(f"[+] {owner}/{repo}: {len(links)} links found")
        time.sleep(0.3)

    print(f"[+] Total GitHub writeups: {len(reports)}")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_report(title: str, weakness: str) -> str:
    text = (title + " " + weakness).lower()
    for vuln_class, keywords in VULN_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return vuln_class
    return "misc"


def group_by_vuln(reports: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in reports:
        cls = classify_report(r["title"], r.get("weakness", ""))
        r["vuln_class"] = cls
        groups[cls].append(r)
    return dict(groups)


# ---------------------------------------------------------------------------
# AI Skill Generation via OpenCode Zen
# ---------------------------------------------------------------------------

# Compact prompt — keeps input tokens low for flash/free models.
# The structured output sections are identical; only the preamble is trimmed.
SKILL_PROMPT = """\
You are a senior bug bounty hunter. Extract GENERALIZABLE hunting knowledge from the {count} {vuln_class} reports below.

Write a hunting skill with these sections (markdown, no preamble):

## Crown Jewel Targets
High-value targets, asset types, what pays most.

## Attack Surface Signals
URL patterns, headers, JS clues, tech stack signals that expose this surface.

## Step-by-Step Hunting Methodology
Numbered, specific, actionable steps.

## Payload & Detection Patterns
Concrete payloads or grep patterns in code blocks.

## Common Root Causes
Why developers introduce this bug.

## Bypass Techniques
How defenses fail and how hunters get around them.

## Gate 0 Validation
3-question checklist before writing the report:
1. What can the attacker DO right now?
2. What does the victim LOSE?
3. Reproducible in 10 min?

## Real Impact Examples
2-3 anonymized scenarios from the reports below showing business impact.

Reports:
{reports}
"""


def _build_report_text(reports: list[dict]) -> str:
    """Serialize reports into a compact text block that fits flash context."""
    lines = []
    for i, r in enumerate(reports, 1):
        parts = [f"[{i}] {r['title']}"]
        if r.get("severity"):   parts.append(f"sev={r['severity']}")
        if r.get("program"):    parts.append(f"prog={r['program']}")
        if r.get("bounty"):     parts.append(f"${r['bounty']}")
        if r.get("url"):        parts.append(r["url"])
        lines.append("  ".join(parts))

        desc = (r.get("description") or "").strip()
        if desc and len(desc) > 30:
            lines.append(f"  {desc[:MAX_DESC_CHARS]}")
    return "\n".join(lines)


def _call_zen(client: OpenAI, prompt: str) -> str | None:
    """Single Zen API call with retry. Returns content string or None."""
    api_model = _api_model(ZEN_MODEL)
    for attempt in range(3):
        try:
            resp   = client.chat.completions.create(
                model=api_model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            choice  = resp.choices[0]
            content = choice.message.content
            reason  = getattr(choice, "finish_reason", "unknown")

            if not content:
                print(f"[!] Zen returned empty content (finish_reason={reason}) — retrying")
                time.sleep(10)
                continue

            if reason == "length":
                print(f"[~] finish_reason=length — output was truncated (this is OK, skill still usable)")

            return content

        except Exception as e:
            wait = 30 * (attempt + 1)
            print(f"[!] Zen API error (attempt {attempt + 1}): {e} — waiting {wait}s")
            time.sleep(wait)
    return None


def generate_skill(client: OpenAI, vuln_class: str, reports: list[dict]) -> str:
    """
    Generate skill content for a vuln class.

    Strategy for large report sets (e.g. 124 XSS reports):
      - Split into chunks of MAX_REPORTS_PER_CALL (default 20)
      - Call Zen once per chunk → get a partial skill body
      - If more than one chunk, do a final merge call over all partial bodies
      - This keeps every individual prompt well within the flash context window
    """
    chunks = [
        reports[i : i + MAX_REPORTS_PER_CALL]
        for i in range(0, len(reports), MAX_REPORTS_PER_CALL)
    ]

    if len(chunks) == 1:
        # Single chunk — straightforward
        report_text = _build_report_text(chunks[0])
        prompt = SKILL_PROMPT.format(
            vuln_class=vuln_class.replace("-", " ").upper(),
            count=len(chunks[0]),
            reports=report_text,
        )
        content = _call_zen(client, prompt)
        return content or f"# {vuln_class}\n\n*Skill generation failed.*\n"

    # Multiple chunks — generate partial skills then merge
    partials: list[str] = []
    for idx, chunk in enumerate(chunks, 1):
        print(f"  [*] Chunk {idx}/{len(chunks)} ({len(chunk)} reports)...")
        report_text = _build_report_text(chunk)
        prompt = SKILL_PROMPT.format(
            vuln_class=vuln_class.replace("-", " ").upper(),
            count=len(chunk),
            reports=report_text,
        )
        part = _call_zen(client, prompt)
        if part:
            partials.append(part)
        time.sleep(3)  # be kind to rate limits between chunks

    if not partials:
        return f"# {vuln_class}\n\n*Skill generation failed.*\n"

    if len(partials) == 1:
        return partials[0]

    # Merge pass — combine all partial skills into one cohesive document
    print(f"  [*] Merging {len(partials)} partial skills...")
    combined = "\n\n---\n\n".join(partials)
    merge_prompt = f"""\
You are a senior bug bounty hunter. Below are {len(partials)} partial hunting skill drafts for **{vuln_class.upper()}**, each generated from a different batch of reports.

Merge them into ONE cohesive, non-redundant hunting skill. Keep the best content from each section. Remove duplicates. Use the same section structure:

## Crown Jewel Targets
## Attack Surface Signals
## Step-by-Step Hunting Methodology
## Payload & Detection Patterns
## Common Root Causes
## Bypass Techniques
## Gate 0 Validation
## Real Impact Examples

Start directly with ## Crown Jewel Targets. No preamble.

Partial drafts:
{combined[:6000]}
"""
    merged = _call_zen(client, merge_prompt)
    return merged or partials[0]  # fallback to first partial if merge fails


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_skill_file(out_dir: Path, vuln_class: str, content: str, report_count: int, sources: list[str]) -> Path:
    """
    Write SKILL.md in OpenCode agent skill format.
    Path: <out_dir>/hunt-<vuln>/SKILL.md
    """
    name = f"hunt-{vuln_class.lower().replace(' ', '-').replace('_', '-')}"
    description = (
        f"Hunting skill for {vuln_class.replace('-', ' ')} vulnerabilities. "
        f"Built from {report_count} public bug bounty reports. "
        f"Use when hunting {vuln_class.replace('-', ' ')} on any target."
    )[:300]

    frontmatter = (
        f"---\n"
        f"name: {name}\n"
        f"description: {description}\n"
        f"sources: {', '.join(set(sources))}\n"
        f"report_count: {report_count}\n"
        f"---\n\n"
    )

    skill_dir = out_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    filepath  = skill_dir / "SKILL.md"
    filepath.write_text(frontmatter + content, encoding="utf-8")
    print(f"[+] Written: {filepath}  ({report_count} reports, {len(content)} chars)")
    return filepath


def write_index(out_dir: Path, skills: list[dict]):
    lines = [
        "# Public Bug Bounty Skills",
        "",
        f"Generated from {sum(s['count'] for s in skills)} public reports across {len(skills)} vulnerability classes.",
        "",
        "| Skill | Reports | Sources |",
        "|-------|---------|---------| ",
    ]
    for s in sorted(skills, key=lambda x: -x["count"]):
        lines.append(f"| [{s['name']}]({s['name']}/SKILL.md) | {s['count']} | {s['sources']} |")

    lines += [
        "",
        "## Usage with OpenCode",
        "```bash",
        "# Global (available in all projects)",
        "cp -r skills/hunt-idor ~/.config/opencode/skills/",
        "",
        "# Project-local",
        "cp -r skills/hunt-ssrf .opencode/skills/",
        "```",
        "",
        "## Usage with Claude Code (same Agent Skills format)",
        "```bash",
        "cp -r skills/hunt-idor .claude/skills/",
        "```",
    ]
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Index written: {out_dir}/README.md")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Build OpenCode agent hunting skills from public bug bounty reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python public_skills_builder.py                              # all sources
          python public_skills_builder.py --source github             # no API keys needed
          python public_skills_builder.py --source h1-public          # H1 hacktivity (needs H1_API_KEY)
          python public_skills_builder.py --source h1 --program shopify
          python public_skills_builder.py --vuln-type idor ssrf xss
          python public_skills_builder.py --model opencode/big-pickle
        """),
    )
    p.add_argument("--source",      choices=["h1", "h1-public", "github", "all"], default="all")
    p.add_argument("--program",     help="H1 program handle filter (e.g. shopify)")
    p.add_argument("--vuln-type",   nargs="+", choices=list(VULN_KEYWORDS.keys()),
                   help="Only generate skills for these vuln classes")
    p.add_argument("--limit",       type=int, default=500)
    p.add_argument("--out",         default="skills")
    p.add_argument("--min-reports", type=int, default=3)
    p.add_argument("--model",       default=ZEN_MODEL,
                   help=f"Zen model ID (default: {ZEN_MODEL}). Other free options: opencode/big-pickle, opencode/nemotron-3-super-free")
    return p.parse_args()


def load_env():
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main():
    load_env()
    args = parse_args()

    opencode_key = os.getenv("OPENCODE_API_KEY")
    if not opencode_key:
        print("[!] Set OPENCODE_API_KEY in .env or environment")
        print("    Get your key at: https://opencode.ai/zen")
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    global ZEN_MODEL
    ZEN_MODEL = args.model

    client = OpenAI(api_key=opencode_key, base_url=ZEN_BASE_URL)
    print(f"[*] Using model: {ZEN_MODEL} (API id: {_api_model(ZEN_MODEL)}) via OpenCode Zen")

    # --- Fetch ---
    all_reports: list[dict] = []
    h1_key = os.getenv("H1_API_KEY", "")

    try:
        if args.source in ("h1", "all"):
            if h1_key:
                all_reports += fetch_h1_disclosed(h1_key, args.program, args.limit)
            else:
                print("[!] H1_API_KEY not set — skipping personal H1 reports")

        if args.source in ("h1-public", "all"):
            if h1_key:
                all_reports += fetch_h1_hacktivity(h1_key, args.limit, args.program)
            else:
                print("[!] H1_API_KEY not set — skipping H1 hacktivity feed")
                print("    HackerOne retired the unauthenticated feed. A free API key is now required.")
                print("    Create one at: https://hackerone.com/settings/api_token/edit")

        if args.source in ("github", "all"):
            all_reports += fetch_github_writeups(args.limit // 2)

    except KeyboardInterrupt:
        print("\n[*] Interrupted during fetch. Proceeding with what was collected...")

    if not all_reports:
        print("[!] No reports collected. Check your API keys and source settings.")
        sys.exit(1)

    print(f"\n[*] Total reports collected: {len(all_reports)}")

    # --- Group ---
    groups = group_by_vuln(all_reports)
    if args.vuln_type:
        groups = {k: v for k, v in groups.items() if k in args.vuln_type}

    print(f"[*] Vuln classes found: {', '.join(f'{k}({len(v)})' for k, v in sorted(groups.items(), key=lambda x: -len(x[1])))}")

    # --- Generate skills ---
    skills_written: list[dict] = []
    try:
        for vuln_class, reports in sorted(groups.items(), key=lambda x: -len(x[1])):
            if len(reports) < args.min_reports:
                print(f"[~] Skipping {vuln_class} ({len(reports)} < min {args.min_reports})")
                continue

            n_chunks = max(1, (len(reports) + MAX_REPORTS_PER_CALL - 1) // MAX_REPORTS_PER_CALL)
            print(f"\n[*] Generating skill: {vuln_class} ({len(reports)} reports, {n_chunks} chunk(s))...")
            content = generate_skill(client, vuln_class, reports)

            sources  = list(set(r["source"].split(":")[0] for r in reports))
            filepath = write_skill_file(out_dir, vuln_class, content, len(reports), sources)
            skills_written.append({
                "name":    f"hunt-{vuln_class}",
                "file":    filepath.name,
                "count":   len(reports),
                "sources": ", ".join(sources),
            })
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Interrupted. Saving index for skills generated so far...")

    if skills_written:
        write_index(out_dir, skills_written)
        print(f"\n[+] Done. {len(skills_written)} skills written to {out_dir}/")
        print(f"[*] To install globally in OpenCode:")
        print(f"    cp -r {out_dir}/* ~/.config/opencode/skills/")
    else:
        print("[!] No skills generated.")


if __name__ == "__main__":
    main()
