#!/usr/bin/env python3
"""
Public Skills Builder
Fetches public disclosed bug bounty reports from HackerOne + GitHub writeup repos
and generates OpenCode agent skill files organized by vulnerability class.

Sources:
  1. HackerOne REST API (authenticated)  — your own reports  (H1_API_KEY required)
  2. HackerOne Hacker API /v1/hacktivity  — public disclosed  (H1_API_KEY required)
  3. GitHub writeup collections           — no auth needed

LLM backend priority (first found wins):
  1. --provider flag  (e.g. --provider deepseek  --model deepseek-chat)
  2. DEEPSEEK_API_KEY env / .env          → api.deepseek.com
  3. OPENAI_API_KEY env / .env            → api.openai.com
  4. ~/.local/share/opencode/auth.json    → whichever provider key is stored there
  5. OPENCODE_API_KEY env / .env          → opencode.ai/zen (free, quota-limited)

Usage:
  python public_skills_builder.py [--source h1|h1-public|github|all] [--program HANDLE]
                                   [--vuln-type TYPE] [--limit N] [--out DIR]
                                   [--chunk-size N] [--delay N]
                                   [--provider PROVIDER] [--model MODEL]
                                   [--debug]

Provider shortcuts:
  --provider deepseek   uses DEEPSEEK_API_KEY + api.deepseek.com
  --provider openai     uses OPENAI_API_KEY   + api.openai.com
  --provider openrouter uses OPENROUTER_API_KEY + openrouter.ai/api/v1
  --provider ollama     uses http://localhost:11434/v1  (no key needed)
  --provider zen        forces OpenCode Zen  (free, quota-limited)

H1_API_KEY format: identifier:token
  - Go to https://hackerone.com/settings/api_token/edit
  - The identifier looks like: your_username-abc12345 (NOT just your username)
"""

import json
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

H1_API_BASE = "https://api.hackerone.com/v1"

# Provider registry: name -> (base_url, env_key_name, default_model)
PROVIDERS = {
    "deepseek":   ("https://api.deepseek.com/v1",           "DEEPSEEK_API_KEY",   "deepseek-chat"),
    "openai":     ("https://api.openai.com/v1",              "OPENAI_API_KEY",     "gpt-4o-mini"),
    "openrouter": ("https://openrouter.ai/api/v1",           "OPENROUTER_API_KEY", "deepseek/deepseek-chat-v3-0324:free"),
    "ollama":     ("http://localhost:11434/v1",               "",                   "llama3"),
    "zen":        ("https://opencode.ai/zen/v1",             "OPENCODE_API_KEY",   "deepseek-v4-flash-free"),
}

# OpenCode stores provider keys here after `opencode auth login` or /connect
OPENCODE_AUTH_FILE = Path.home() / ".local" / "share" / "opencode" / "auth.json"

# Map provider names in auth.json to our PROVIDERS registry
AUTH_JSON_PROVIDER_MAP = {
    "deepseek":   "deepseek",
    "openai":     "openai",
    "openrouter": "openrouter",
    "anthropic":  None,   # not OpenAI-compatible, skip
}

DEFAULT_CHUNK_SIZE = 10
DEFAULT_DELAY      = 3    # seconds between LLM calls
MAX_DESC_CHARS     = 200
DEBUG              = False

QUOTA_ERROR_TYPES  = {"FreeUsageLimitError", "quota_exceeded", "insufficient_quota"}
_QUOTA_EXHAUSTED   = False


# ---------------------------------------------------------------------------
# LLM backend resolution
# ---------------------------------------------------------------------------

def _read_opencode_auth() -> dict:
    """Parse ~/.local/share/opencode/auth.json and return {provider: api_key}."""
    if not OPENCODE_AUTH_FILE.exists():
        return {}
    try:
        raw = json.loads(OPENCODE_AUTH_FILE.read_text())
        result = {}
        for pname, pdata in raw.items():
            if isinstance(pdata, dict):
                key = pdata.get("key") or pdata.get("api_key") or pdata.get("token", "")
            elif isinstance(pdata, str):
                key = pdata
            else:
                continue
            if key:
                result[pname] = key
        return result
    except Exception:
        return {}


def resolve_backend(provider_flag: str | None, model_flag: str | None
                    ) -> tuple[OpenAI, str, str]:
    """
    Returns (OpenAI client, model_name, provider_label).
    Priority:
      1. --provider flag
      2. DEEPSEEK_API_KEY
      3. OPENAI_API_KEY
      4. ~/.local/share/opencode/auth.json  (first usable provider)
      5. OPENCODE_API_KEY  (Zen fallback)
    """
    # 1. Explicit --provider flag
    if provider_flag:
        pname = provider_flag.lower()
        if pname not in PROVIDERS:
            print(f"[!] Unknown provider '{pname}'. Valid: {', '.join(PROVIDERS)}")
            sys.exit(1)
        base_url, env_key, default_model = PROVIDERS[pname]
        model = model_flag or default_model
        if pname == "ollama":
            api_key = "ollama"
        else:
            api_key = os.getenv(env_key, "")
            if not api_key and pname != "zen":
                print(f"[!] {env_key} not set for --provider {pname}")
                sys.exit(1)
            if not api_key:
                api_key = os.getenv("OPENCODE_API_KEY", "")
            if not api_key:
                print(f"[!] Neither {env_key} nor OPENCODE_API_KEY is set.")
                sys.exit(1)
        print(f"[*] LLM provider: {pname}  model: {model}  base: {base_url}")
        return OpenAI(api_key=api_key, base_url=base_url), model, pname

    # 2. DEEPSEEK_API_KEY in env
    dk = os.getenv("DEEPSEEK_API_KEY", "")
    if dk:
        base_url, _, default_model = PROVIDERS["deepseek"]
        model = model_flag or default_model
        print(f"[*] LLM provider: deepseek (env)  model: {model}")
        return OpenAI(api_key=dk, base_url=base_url), model, "deepseek"

    # 3. OPENAI_API_KEY in env
    ok = os.getenv("OPENAI_API_KEY", "")
    if ok:
        base_url, _, default_model = PROVIDERS["openai"]
        model = model_flag or default_model
        print(f"[*] LLM provider: openai (env)  model: {model}")
        return OpenAI(api_key=ok, base_url=base_url), model, "openai"

    # 4. OpenCode auth.json
    auth_data = _read_opencode_auth()
    if auth_data:
        for pname_raw, api_key in auth_data.items():
            mapped = AUTH_JSON_PROVIDER_MAP.get(pname_raw)
            if mapped is None:
                continue  # skip anthropic etc.
            base_url, _, default_model = PROVIDERS[mapped]
            model = model_flag or default_model
            print(f"[*] LLM provider: {mapped} (from OpenCode auth.json)  model: {model}")
            return OpenAI(api_key=api_key, base_url=base_url), model, mapped

    # 5. Zen fallback
    zen_key = os.getenv("OPENCODE_API_KEY", "")
    if zen_key:
        base_url, _, default_model = PROVIDERS["zen"]
        model = model_flag or default_model
        print(f"[*] LLM provider: zen (fallback)  model: {model}")
        print(f"    [~] Zen has a daily free quota. For unlimited use, set DEEPSEEK_API_KEY.")
        return OpenAI(api_key=zen_key, base_url=base_url), model, "zen"

    # Nothing found
    print("[!] No LLM API key found. Options:")
    print("    a) Set DEEPSEEK_API_KEY=sk-...  (recommended, cheap, no quota)")
    print("    b) Set OPENAI_API_KEY=sk-...")
    print("    c) Set OPENCODE_API_KEY=...  (Zen, free but daily quota)")
    print("    d) Use --provider ollama  (local, free, no key needed)")
    print("    e) Run 'opencode' and use /connect to save a provider key,")
    print(f"       then re-run — keys auto-loaded from {OPENCODE_AUTH_FILE}")
    sys.exit(1)


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
        print("[!] H1_API_KEY must be 'identifier:token'")
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
            resp = requests.get(f"{H1_API_BASE}/hackers/me/reports",
                                auth=auth, headers=headers, params=params, timeout=15)
        except requests.RequestException as e:
            print(f"[!] H1 API error: {e}")
            break

        if resp.status_code == 401:
            print("[!] H1 auth failed (401). Check H1_API_KEY=identifier:token")
            break
        if resp.status_code == 429:
            print("[*] H1 rate limited. Waiting 30s...")
            time.sleep(30)
            continue
        if not resp.ok:
            print(f"[!] H1 API {resp.status_code}: {resp.text[:200]}")
            break

        data = resp.json().get("data", [])
        if not data:
            break

        for item in data:
            attrs = item.get("attributes", {})
            rels  = item.get("relationships", {})
            wk    = (rels.get("weakness", {}).get("data", {}) or {})
            sv    = (rels.get("severity", {}).get("data", {}) or {})
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
# Source 2: HackerOne public hacktivity
# ---------------------------------------------------------------------------

def fetch_h1_hacktivity(api_key: str, limit: int, program: str | None = None) -> list[dict]:
    auth, valid = _h1_auth(api_key)
    if not valid:
        print("[!] H1_API_KEY required for hacktivity (format: identifier:token)")
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
            resp = requests.get(f"{H1_API_BASE}/hacktivity",
                                auth=auth, headers=headers, params=params, timeout=20)
        except requests.RequestException as e:
            print(f"[!] Hacktivity fetch error: {e}")
            break

        if resp.status_code == 401:
            print("[!] H1 auth failed (401). Check identifier in H1_API_KEY.")
            break
        if resp.status_code == 429:
            print("[*] H1 rate limited. Waiting 30s...")
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

GITHUB_WRITEUP_REPOS = [
    ("ngalongc",      "bug-bounty-reference",         "README.md"),
    ("devanshbatham", "Awesome-Bugbounty-Writeups",    "README.md"),
    ("djadmin",       "awesome-bug-bounty",            "README.md"),
]


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
                    "description": "",
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


def _is_quota_error(exc: Exception) -> bool:
    msg = str(exc)
    return any(t in msg for t in QUOTA_ERROR_TYPES)


def _retry_after(exc: Exception) -> int | None:
    m = re.search(r'retry.after[^0-9]*([0-9]+)', str(exc), re.I)
    return int(m.group(1)) if m else None


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


def _call_llm(client: OpenAI, model: str, prompt: str, delay: int,
              provider: str, label: str = "") -> str | None:
    global _QUOTA_EXHAUSTED
    if _QUOTA_EXHAUSTED:
        return None

    if DEBUG:
        print(f"  [dbg] prompt {len(prompt)} chars (~{len(prompt)//4} tokens) for {label}")

    for attempt in range(3):
        try:
            resp    = client.chat.completions.create(
                model=model,
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
                print(f"  [dbg] {len(content)} chars back, finish={reason}")

            if delay > 0:
                time.sleep(delay)
            return content

        except Exception as e:
            if _is_quota_error(e):
                _QUOTA_EXHAUSTED = True
                print(f"\n  [!] Quota exhausted for {provider}/{model}")
                if provider == "zen":
                    print("  [!] Zen daily free quota hit. Use your own provider key instead:")
                    print("      a) Set DEEPSEEK_API_KEY=sk-...  (cheap, ~$0.001/call)")
                    print("      b) Set OPENROUTER_API_KEY=... and use free models")
                    print("      c) --provider ollama  (local, no quota)")
                    print(f"      d) Keys saved by OpenCode are auto-read from {OPENCODE_AUTH_FILE}")
                return None

            ra = _retry_after(e)
            if ra:
                print(f"  [!] Rate limited — waiting {ra}s (Retry-After)...")
                time.sleep(ra + 2)
                continue

            wait = 30 * (attempt + 1)
            print(f"  [!] LLM error (attempt {attempt+1}): {e} — waiting {wait}s")
            time.sleep(wait)

    return None


def generate_skill(client: OpenAI, model: str, provider: str,
                   vuln_class: str, reports: list[dict],
                   chunk_size: int, delay: int) -> str:
    global _QUOTA_EXHAUSTED
    vname  = vuln_class.replace("-", " ").upper()
    chunks = [reports[i:i+chunk_size] for i in range(0, len(reports), chunk_size)]

    partials: list[str] = []
    for idx, chunk in enumerate(chunks, 1):
        if _QUOTA_EXHAUSTED:
            break
        label = f"{vuln_class} chunk {idx}/{len(chunks)}"
        if len(chunks) > 1:
            print(f"  [*] Chunk {idx}/{len(chunks)} ({len(chunk)} reports)...")
        prompt = SKILL_PROMPT.format(vuln_class=vname, count=len(chunk),
                                     reports=_build_report_text(chunk))
        part = _call_llm(client, model, prompt, delay=delay, provider=provider, label=label)
        if part:
            partials.append(part)

    if not partials:
        return f"# {vuln_class}\n\n*Skill generation failed.*\n"
    if len(partials) == 1:
        return partials[0]

    print(f"  [*] Merging {len(partials)} partial skills...")
    combined = "\n\n---\n\n".join(p[:1200] for p in partials)[:5000]
    prompt   = MERGE_PROMPT.format(n=len(partials), vuln_class=vname, combined=combined)
    merged   = _call_llm(client, model, prompt, delay=0, provider=provider,
                         label=f"{vuln_class} merge")
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
        f"---\nname: {name}\ndescription: {desc}\n"
        f"sources: {', '.join(set(sources))}\nreport_count: {report_count}\n---\n\n"
    )
    skill_dir = out_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    filepath  = skill_dir / "SKILL.md"
    filepath.write_text(front + content, encoding="utf-8")
    print(f"[+] Written: {filepath}  ({report_count} reports, {len(content)} chars)")
    return filepath


def write_index(out_dir: Path, skills: list[dict]):
    lines = [
        "# Public Bug Bounty Skills", "",
        f"Generated from {sum(s['count'] for s in skills)} reports across {len(skills)} vuln classes.",
        "", "| Skill | Reports | Sources |", "|-------|---------|---------|",
    ]
    for s in sorted(skills, key=lambda x: -x["count"]):
        lines.append(f"| [{s['name']}]({s['name']}/SKILL.md) | {s['count']} | {s['sources']} |")
    lines += [
        "", "## Install to OpenCode", "```bash",
        "cp -r skills/hunt-xss ~/.config/opencode/skills/",
        "# or project-local:",
        "cp -r skills/hunt-ssrf .opencode/skills/", "```",
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
        LLM backend auto-detection order:
          1. --provider flag
          2. DEEPSEEK_API_KEY env / .env
          3. OPENAI_API_KEY env / .env
          4. ~/.local/share/opencode/auth.json  (keys saved by 'opencode /connect')
          5. OPENCODE_API_KEY  (Zen, free but has a daily quota)

        Provider shortcuts for --provider:
          deepseek   DEEPSEEK_API_KEY  → api.deepseek.com
          openai     OPENAI_API_KEY    → api.openai.com
          openrouter OPENROUTER_API_KEY→ openrouter.ai  (has free models)
          ollama     (no key needed)   → localhost:11434
          zen        OPENCODE_API_KEY  → opencode.ai/zen  (daily quota)

        Examples:
          python public_skills_builder.py --source github
          python public_skills_builder.py --source github --vuln-type xss ssrf
          python public_skills_builder.py --provider deepseek --model deepseek-chat
          python public_skills_builder.py --provider ollama --model llama3
          python public_skills_builder.py --provider openrouter --model deepseek/deepseek-chat-v3-0324:free
          python public_skills_builder.py --chunk-size 5 --delay 2 --debug
        """),
    )
    p.add_argument("--source",      choices=["h1", "h1-public", "github", "all"], default="all")
    p.add_argument("--program",     help="H1 program handle filter")
    p.add_argument("--vuln-type",   nargs="+", choices=list(VULN_KEYWORDS.keys()))
    p.add_argument("--limit",       type=int, default=500)
    p.add_argument("--out",         default="skills")
    p.add_argument("--min-reports", type=int, default=3)
    p.add_argument("--chunk-size",  type=int, default=DEFAULT_CHUNK_SIZE)
    p.add_argument("--delay",       type=int, default=DEFAULT_DELAY,
                   help=f"Seconds between LLM calls (default {DEFAULT_DELAY})")
    p.add_argument("--provider",    help="Force a specific LLM provider (deepseek/openai/openrouter/ollama/zen)")
    p.add_argument("--model",       help="Override model name for the selected provider")
    p.add_argument("--debug",       action="store_true")
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
    global DEBUG, _QUOTA_EXHAUSTED
    load_env()
    args  = parse_args()
    DEBUG = args.debug
    _QUOTA_EXHAUSTED = False

    client, model, provider = resolve_backend(args.provider, args.model)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

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

        if args.source in ("github", "all"):
            all_reports += fetch_github_writeups(args.limit // 2)

    except KeyboardInterrupt:
        print("\n[*] Fetch interrupted. Continuing with collected reports...")

    if not all_reports:
        print("[!] No reports collected.")
        sys.exit(1)

    print(f"\n[*] Total reports: {len(all_reports)}")

    groups = group_by_vuln(all_reports)
    if args.vuln_type:
        groups = {k: v for k, v in groups.items() if k in args.vuln_type}

    print(f"[*] Vuln classes: {', '.join(f'{k}({len(v)})' for k, v in sorted(groups.items(), key=lambda x: -len(x[1])))}")

    skills_written: list[dict] = []
    try:
        for vuln_class, reports in sorted(groups.items(), key=lambda x: -len(x[1])):
            if _QUOTA_EXHAUSTED:
                print("[!] Quota exhausted — stopping skill generation.")
                break
            if len(reports) < args.min_reports:
                print(f"[~] Skipping {vuln_class} ({len(reports)} < {args.min_reports})")
                continue

            n_chunks = max(1, (len(reports) + args.chunk_size - 1) // args.chunk_size)
            print(f"\n[*] Generating skill: {vuln_class} ({len(reports)} reports, {n_chunks} chunk(s))...")

            content  = generate_skill(client, model, provider, vuln_class, reports,
                                      args.chunk_size, args.delay)
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
        print(f"    Install: cp -r {out_dir}/* ~/.config/opencode/skills/")
    else:
        print("[!] No skills generated.")


if __name__ == "__main__":
    main()
