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

      H1_API_KEY format: identifier:token
        - Go to https://hackerone.com/settings/api_token/edit
        - Create a token — H1 will show you an 'identifier' string and a 'token' string
        - The identifier looks like: your_username-abc12345 (NOT your login username alone)
        - Set H1_API_KEY=your_username-abc12345:the_long_token_string

Usage:
  python public_skills_builder.py [--source h1|h1-public|github|all] [--program HANDLE]
                                   [--vuln-type TYPE] [--limit N] [--out DIR]
                                   [--chunk-size N] [--debug]
"""

import os
import re
import sys
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
ZEN_BASE_URL = "https://opencode.ai/zen/v1"
ZEN_MODEL    = "opencode/deepseek-v4-flash-free"

# Free flash models typically have 4k–8k combined token budgets.
# 10 reports x ~60 chars each ≈ 600 tokens input → safe for all free tiers.
# Use --chunk-size 20 if you switch to a larger model.
DEFAULT_CHUNK_SIZE = 10
MAX_DESC_CHARS     = 200   # per report description, fed to LLM
DEBUG              = False  # set via --debug flag


def _api_model(model: str) -> str:
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
    if not api_key or ":" not in api_key:
        return (("", ""), False)
    identifier, token = api_key.split(":", 1)
    return ((identifier.strip(), token.strip()), True)


# ---------------------------------------------------------------------------
# Source 1: HackerOne REST API — your own disclosed reports
# ---------------------------------------------------------------------------

def fetch_h1_disclosed(api_key: str, program: str | None, limit: int) -> list[dict]:
    auth, valid = _h1_auth(api_key)
    if not valid:
        print("[!] H1_API_KEY must be 'identifier:token' (see --help for format)")
        return []

    headers = {"Accept": "application/json"}
    reports, page = [], 1
    print(f"[*] Fetching your H1 disclosed reports (identifier={auth[0]!r}, limit={limit})...")

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
            print("[!] H1 auth failed (401). Check H1_API_KEY format:")
            print("    identifier:token")
            print("    The 'identifier' is shown on https://hackerone.com/settings/api_token/edit")
            print("    It looks like: yourusername-abc12345  (NOT just your username)")
            break
        if resp.status_code == 429:
            print("[*] Rate limited. Waiting 30s...")
            time.sleep(30)
            continue
        if not resp.ok:
            print(f"[!] H1 API returned {resp.status_code}: {resp.text[:200]}")
            break

        data = resp.json().get("data", [])
        if not data:
            break

        for item in data:
            attrs  = item.get("attributes", {})
            rels   = item.get("relationships", {})
            wk     = (rels.get("weakness", {}).get("data", {}) or {})
            sv     = (rels.get("severity", {}).get("data", {}) or {})
            reports.append({
                "source":      "hackerone",
                "id":          item.get("id"),
                "title":       attrs.get("title", ""),
                "severity":    sv.get("attributes", {}).get("rating", ""),
                "weakness":    wk.get("attributes", {}).get("name", ""),
                "description": attrs.get("vulnerability_information", ""),
                "impact":      attrs.get("impact", ""),
                "program":     rels.get("program", {}).get("data", {}).get("attributes", {}).get("handle", ""),
                "url":         f"https://hackerone.com/reports/{item.get('id')}",
                "bounty":      "",
            })

        if len(data) < 100:
            break
        page += 1
        time.sleep(0.3)

    print(f"[+] Fetched {len(reports)} H1 disclosed reports")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Source 2: HackerOne public hacktivity via REST /v1/hacktivity
# ---------------------------------------------------------------------------

def fetch_h1_hacktivity(api_key: str, limit: int, program: str | None = None) -> list[dict]:
    auth, valid = _h1_auth(api_key)
    if not valid:
        print("[!] H1_API_KEY required for hacktivity (format: identifier:token)")
        print("    https://hackerone.com/settings/api_token/edit")
        return []

    headers = {"Accept": "application/json"}
    reports, page = [], 1
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
            print("[!] H1 auth failed (401). The identifier in your H1_API_KEY is wrong.")
            print("    On https://hackerone.com/settings/api_token/edit, look for the")
            print("    'Identifier' field shown after token creation — copy that exactly.")
            break
        if resp.status_code == 429:
            print("[*] Rate limited. Waiting 30s...")
            time.sleep(30)
            continue
        if not resp.ok:
            print(f"[!] H1 hacktivity {resp.status_code}: {resp.text[:200]}")
            break

        data = resp.json().get("data", [])
        if not data:
            break

        for item in data:
            attrs = item.get("attributes", {})
            rels  = item.get("relationships", {})
            wk    = (rels.get("weakness", {}).get("data",  {}) or {})
            sv    = (rels.get("severity", {}).get("data",  {}) or {})
            team  = (rels.get("team",     {}).get("data",  {}) or {})
            bnty  = (rels.get("bounty",   {}).get("data",  {}) or {})
            rid   = item.get("id", "")
            reports.append({
                "source":      "hackerone_public",
                "id":          str(rid),
                "title":       attrs.get("title", ""),
                "severity":    sv.get("attributes", {}).get("rating", ""),
                "weakness":    wk.get("attributes", {}).get("name", ""),
                "description": attrs.get("vulnerability_information", ""),
                "impact":      attrs.get("impact", ""),
                "program":     team.get("attributes", {}).get("handle", ""),
                "url":         f"https://hackerone.com/reports/{rid}",
                "bounty":      bnty.get("attributes", {}).get("amount", ""),
            })

        if len(data) < params["page[size]"]:
            break
        page += 1
        time.sleep(0.4)

    print(f"[+] Fetched {len(reports)} public hacktivity reports")
    return reports[:limit]


# ---------------------------------------------------------------------------
# Source 3: GitHub writeup collections
# ---------------------------------------------------------------------------

def fetch_github_writeups(limit: int) -> list[dict]:
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
                resp = requests.get(url.replace("/master/", "/main/"), headers=headers, timeout=15)
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
                    "source":      f"github:{owner}/{repo}",
                    "id":          re.sub(r'[^a-z0-9]', '-', title.lower())[:40],
                    "title":       title,
                    "severity":    "",
                    "weakness":    classify_report(title, ""),
                    "description": "",  # no description for link-only sources
                    "impact":      "",
                    "program":     "",
                    "url":         link_url,
                    "bounty":      "",
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
# AI Skill Generation
# ---------------------------------------------------------------------------

# Ultra-compact prompt — every byte saved here = more room for LLM output.
# Free flash models have ~4k–8k combined token budgets.
SKILL_PROMPT = """\
Senior bug bounty hunter. Write a hunting skill for {vuln_class} from these {count} reports.

Sections (markdown, start immediately with the first ##):
## Crown Jewel Targets
## Attack Surface Signals
## Hunting Steps
## Payloads & Detection
## Root Causes
## Bypass Techniques
## Gate 0 Validation
## Impact Examples

Reports:
{reports}
"""

MERGE_PROMPT = """\
Merge these {n} partial {vuln_class} hunting skill drafts into one. Remove duplicates, keep best content. Same sections. Start with ## Crown Jewel Targets.

{combined}
"""


def _build_report_text(reports: list[dict]) -> str:
    lines = []
    for i, r in enumerate(reports, 1):
        parts = [f"[{i}] {r['title']}"]
        if r.get("severity"): parts.append(r["severity"])
        if r.get("program"):  parts.append(r["program"])
        if r.get("bounty"):   parts.append(f"${r['bounty']}")
        if r.get("url"):      parts.append(r["url"])
        lines.append("  ".join(parts))
        desc = (r.get("description") or "").strip()
        if desc and len(desc) > 30:
            lines.append(f"  {desc[:MAX_DESC_CHARS]}")
    return "\n".join(lines)


def _call_zen(client: OpenAI, prompt: str, label: str = "") -> str | None:
    api_model = _api_model(ZEN_MODEL)

    if DEBUG:
        chars = len(prompt)
        # rough token estimate: 1 token ≈ 4 chars for English
        est_tokens = chars // 4
        print(f"  [dbg] prompt {chars} chars (~{est_tokens} tokens) for {label}")

    for attempt in range(3):
        try:
            resp    = client.chat.completions.create(
                model=api_model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            choice  = resp.choices[0]
            content = choice.message.content
            reason  = getattr(choice, "finish_reason", "unknown")

            if not content:
                print(f"  [!] Empty response (finish_reason={reason}) — retrying")
                time.sleep(10)
                continue

            if reason == "length":
                print(f"  [~] Output truncated (finish_reason=length) — still usable")

            if DEBUG:
                print(f"  [dbg] response {len(content)} chars, finish={reason}")

            return content

        except Exception as e:
            wait = 20 * (attempt + 1)
            print(f"  [!] Zen error (attempt {attempt+1}): {e} — waiting {wait}s")
            time.sleep(wait)

    return None


def generate_skill(client: OpenAI, vuln_class: str, reports: list[dict], chunk_size: int) -> str:
    """
    Chunk reports into groups of `chunk_size`, call Zen once per chunk,
    then do a merge pass if more than one chunk.
    """
    vname  = vuln_class.replace("-", " ").upper()
    chunks = [reports[i:i+chunk_size] for i in range(0, len(reports), chunk_size)]

    partials: list[str] = []
    for idx, chunk in enumerate(chunks, 1):
        label  = f"{vuln_class} chunk {idx}/{len(chunks)}"
        if len(chunks) > 1:
            print(f"  [*] Chunk {idx}/{len(chunks)} ({len(chunk)} reports)...")
        prompt = SKILL_PROMPT.format(vuln_class=vname, count=len(chunk),
                                     reports=_build_report_text(chunk))
        part = _call_zen(client, prompt, label=label)
        if part:
            partials.append(part)
        if idx < len(chunks):
            time.sleep(2)

    if not partials:
        return f"# {vuln_class}\n\n*Skill generation failed after all retries.*\n"

    if len(partials) == 1:
        return partials[0]

    # Merge pass — cap combined input to 5000 chars to stay in context
    print(f"  [*] Merging {len(partials)} partial skills...")
    combined = "\n\n---\n\n".join(p[:1200] for p in partials)[:5000]
    prompt   = MERGE_PROMPT.format(n=len(partials), vuln_class=vname, combined=combined)
    merged   = _call_zen(client, prompt, label=f"{vuln_class} merge")
    return merged or partials[0]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_skill_file(out_dir: Path, vuln_class: str, content: str,
                     report_count: int, sources: list[str]) -> Path:
    name = f"hunt-{vuln_class.lower().replace(' ', '-').replace('_', '-')}"
    desc = (
        f"Hunting skill for {vuln_class.replace('-', ' ')} vulnerabilities. "
        f"Built from {report_count} public bug bounty reports."
    )[:300]

    front = (
        f"---\n"
        f"name: {name}\n"
        f"description: {desc}\n"
        f"sources: {', '.join(set(sources))}\n"
        f"report_count: {report_count}\n"
        f"---\n\n"
    )

    skill_dir = out_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    filepath  = skill_dir / "SKILL.md"
    filepath.write_text(front + content, encoding="utf-8")
    print(f"[+] Written: {filepath}  ({report_count} reports, {len(content)} chars)")
    return filepath


def write_index(out_dir: Path, skills: list[dict]):
    lines = [
        "# Public Bug Bounty Skills",
        "",
        f"Generated from {sum(s['count'] for s in skills)} reports across {len(skills)} vuln classes.",
        "",
        "| Skill | Reports | Sources |",
        "|-------|---------|---------|",
    ]
    for s in sorted(skills, key=lambda x: -x["count"]):
        lines.append(f"| [{s['name']}]({s['name']}/SKILL.md) | {s['count']} | {s['sources']} |")
    lines += [
        "",
        "## Install to OpenCode",
        "```bash",
        "cp -r skills/hunt-xss ~/.config/opencode/skills/",
        "# or project-local:",
        "cp -r skills/hunt-ssrf .opencode/skills/",
        "```",
    ]
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Index: {out_dir}/README.md")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Build OpenCode agent hunting skills from public bug bounty reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        H1_API_KEY format:
          identifier:token
          The 'identifier' is shown on https://hackerone.com/settings/api_token/edit
          after you create a token. It is NOT your username — it looks like:
          yourusername-abc12345

        Examples:
          python public_skills_builder.py --source github
          python public_skills_builder.py --source github --vuln-type xss ssrf
          python public_skills_builder.py --source all
          python public_skills_builder.py --chunk-size 5   # for very small context models
          python public_skills_builder.py --debug          # show prompt token estimates
        """),
    )
    p.add_argument("--source",      choices=["h1", "h1-public", "github", "all"], default="all")
    p.add_argument("--program",     help="H1 program handle filter")
    p.add_argument("--vuln-type",   nargs="+", choices=list(VULN_KEYWORDS.keys()))
    p.add_argument("--limit",       type=int, default=500)
    p.add_argument("--out",         default="skills")
    p.add_argument("--min-reports", type=int, default=3)
    p.add_argument("--chunk-size",  type=int, default=DEFAULT_CHUNK_SIZE,
                   help=f"Reports per LLM call (default {DEFAULT_CHUNK_SIZE}). Lower = safer for small-context models.")
    p.add_argument("--model",       default=ZEN_MODEL)
    p.add_argument("--debug",       action="store_true", help="Print prompt size estimates")
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
    global DEBUG, ZEN_MODEL
    load_env()
    args  = parse_args()
    DEBUG = args.debug

    opencode_key = os.getenv("OPENCODE_API_KEY")
    if not opencode_key:
        print("[!] OPENCODE_API_KEY not set. Get yours at https://opencode.ai/zen")
        sys.exit(1)

    ZEN_MODEL = args.model
    client    = OpenAI(api_key=opencode_key, base_url=ZEN_BASE_URL)
    print(f"[*] Using model: {ZEN_MODEL} (API id: {_api_model(ZEN_MODEL)}) via OpenCode Zen")
    print(f"[*] Chunk size: {args.chunk_size} reports/call")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

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
                print("[!] H1_API_KEY not set — skipping H1 hacktivity")
                print("    See --help for the correct H1_API_KEY format.")

        if args.source in ("github", "all"):
            all_reports += fetch_github_writeups(args.limit // 2)

    except KeyboardInterrupt:
        print("\n[*] Interrupted during fetch. Continuing with collected reports...")

    if not all_reports:
        print("[!] No reports collected.")
        sys.exit(1)

    print(f"\n[*] Total reports: {len(all_reports)}")

    groups = group_by_vuln(all_reports)
    if args.vuln_type:
        groups = {k: v for k, v in groups.items() if k in args.vuln_type}

    vuln_summary = ", ".join(f"{k}({len(v)})" for k, v in sorted(groups.items(), key=lambda x: -len(x[1])))
    print(f"[*] Vuln classes: {vuln_summary}")

    # --- Generate ---
    skills_written: list[dict] = []
    try:
        for vuln_class, reports in sorted(groups.items(), key=lambda x: -len(x[1])):
            if len(reports) < args.min_reports:
                print(f"[~] Skipping {vuln_class} ({len(reports)} < {args.min_reports})")
                continue

            n_chunks = max(1, (len(reports) + args.chunk_size - 1) // args.chunk_size)
            print(f"\n[*] Generating skill: {vuln_class} ({len(reports)} reports, {n_chunks} chunk(s))...")

            content  = generate_skill(client, vuln_class, reports, args.chunk_size)
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
        print("\n[*] Interrupted. Saving progress...")

    if skills_written:
        write_index(out_dir, skills_written)
        print(f"\n[+] Done. {len(skills_written)} skills in {out_dir}/")
        print(f"    Install globally: cp -r {out_dir}/* ~/.config/opencode/skills/")
    else:
        print("[!] No skills generated.")


if __name__ == "__main__":
    main()
