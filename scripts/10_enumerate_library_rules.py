#!/usr/bin/env python3
"""Enumerate Library detection rules on the tenant and find ones relevant to
Claroty / OT / Palo Alto so we can trigger them by shaping our ingested events.

Mirrors `02d_list_library_via_rest.py` from the librarydetections repo:
  GET /web/api/v2.1/detection-library/platform-rules

Writes:
  hyperautomation/library_rules.json                  -- full catalog
  hyperautomation/library_rules_relevant.json         -- filtered subset
  hyperautomation/library_rules_relevant.md           -- human-readable list
"""
from __future__ import annotations
import json, sys
from pathlib import Path
import requests

ROOT     = Path(__file__).resolve().parent.parent
OUT_DIR  = ROOT / "hyperautomation"
OUT_DIR.mkdir(parents=True, exist_ok=True)

S1_CFG = Path("hyperautomation/config.json")
cfg    = json.loads(S1_CFG.read_text())
BASE   = cfg["base_url"].rstrip("/")
TOKEN  = cfg["api_token"]
H      = {"Authorization": f"ApiToken {TOKEN}", "Content-Type": "application/json"}

def discover_site_id() -> str:
    r = requests.get(f"{BASE}/web/api/v2.1/sites", headers=H,
                     params={"limit": 5}, timeout=30)
    r.raise_for_status()
    sites = (r.json().get("data") or {}).get("sites") or []
    if not sites:
        raise RuntimeError("No sites visible to this token")
    sid = sites[0]["id"]
    print(f"[+] site: {sites[0]['name']} ({sid})")
    return sid


def list_rules():
    """Page through detection-library/rules (Library catalogue)."""
    sid = discover_site_id()
    rules = []
    skip = 0
    PAGE = 100
    while True:
        params = {"limit": PAGE, "skip": skip, "siteIds": sid, "useLabels": "true"}
        r = requests.get(
            f"{BASE}/web/api/v2.1/detection-library/rules",
            headers=H, params=params, timeout=60,
        )
        if r.status_code != 200:
            print(f"  {r.status_code}: {r.text[:300]}")
            return rules
        data = r.json().get("data") or []
        print(f"    paged skip={skip}: got {len(data)} (total so far: {len(rules)+len(data)})")
        if not data:
            break
        rules.extend(data)
        if len(data) < PAGE:
            break
        skip += PAGE
    return rules


def main() -> int:
    print(f"[+] tenant: {BASE}")
    print(f"[+] enumerating Library rules (cloud-detection/rules?isLibrary=true)")
    rules = list_rules()
    print(f"[+] total Library rules: {len(rules)}")
    if not rules:
        print("[-] no rules returned — token may lack the Detection Library.view permission")
        return 1

    (OUT_DIR / "library_rules.json").write_text(json.dumps(rules, indent=2))
    print(f"    -> wrote hyperautomation/library_rules.json")

    # Filter for Claroty / OT / Palo Alto / firewall relevance
    KEYWORDS = ["claroty", "palo alto", "panos", "pan-os", "firewall",
                "ot device", "ics", "scada", "operational technology",
                "modbus", "dnp3", "iec61850", "ot asset", "industrial",
                "external dynamic list", "edl", "dynamic address group"]

    def matches(rule):
        name = (rule.get("name") or "").lower()
        desc = (rule.get("description") or "").lower()
        q    = (rule.get("queryLanguage") or "") + " " + (rule.get("query") or rule.get("s1ql") or "")
        q    = q.lower()
        tags = " ".join(rule.get("tags", []) if isinstance(rule.get("tags"), list) else []).lower()
        haystack = " ".join([name, desc, q, tags])
        return any(k in haystack for k in KEYWORDS)

    relevant = [r for r in rules if matches(r)]
    (OUT_DIR / "library_rules_relevant.json").write_text(json.dumps(relevant, indent=2))

    md = ["# Library rules relevant to Claroty x Palo Alto drift", ""]
    md.append(f"Filtered by keywords: {', '.join(KEYWORDS)}")
    md.append("")
    md.append(f"**Matches: {len(relevant)} / {len(rules)} total Library rules**")
    md.append("")
    for r in relevant:
        md.append(f"## {r.get('name','(unnamed)')}")
        md.append(f"- id: `{r.get('id','')}`")
        md.append(f"- severity: {r.get('severity','')}")
        md.append(f"- status: {r.get('status','')}")
        md.append(f"- description: {(r.get('description') or '')[:280]}")
        q = r.get("query") or r.get("s1ql") or ""
        md.append(f"- query: `{q[:280]}`")
        md.append("")
    (OUT_DIR / "library_rules_relevant.md").write_text("\n".join(md))
    print(f"    -> wrote hyperautomation/library_rules_relevant.{{json,md}} ({len(relevant)} matches)")

    # Also show top 20 relevant matches on stdout
    print("\nTop relevant Library rules:")
    for r in relevant[:20]:
        print(f"  - [{r.get('severity','?'):8}] {r.get('name','')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
