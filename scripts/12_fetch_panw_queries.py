#!/usr/bin/env python3
"""Fetch full s1ql query body for every Palo Alto Library Detection rule so we
can decide which ones are triggerable from synthetic events."""
import json, time
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parent.parent
CAT  = json.loads((ROOT / "hyperautomation" / "library_rules.json").read_text())
S1_CFG = Path("hyperautomation/config.json")
cfg = json.loads(S1_CFG.read_text())
BASE = cfg["base_url"].rstrip("/")
H = {"Authorization": f"ApiToken {cfg['api_token']}", "Content-Type": "application/json"}


def kw(r, terms):
    h = ((r.get("name") or "") + " " + (r.get("description") or "")).lower()
    return any(t in h for t in terms)


panw = [r for r in CAT if kw(r, ["palo alto", "pan-os", "panos", "panw"])]
print(f"[+] {len(panw)} PANW Library rules")

OUT = []
for r in panw:
    rid = r.get("id")
    if not rid:
        continue
    url = f"{BASE}/web/api/v2.1/detection-library/rules/{rid}"
    try:
        rr = requests.get(url, headers=H, timeout=30)
        if rr.status_code == 200:
            detail = rr.json().get("data") or {}
        else:
            detail = {"_err": f"{rr.status_code} {rr.text[:100]}"}
    except Exception as e:
        detail = {"_err": str(e)[:120]}
    OUT.append({
        "name":     r.get("name"),
        "id":       rid,
        "severity": r.get("severity"),
        "query":    detail.get("query") or detail.get("s1ql") or r.get("query"),
        "description": (r.get("description") or "")[:300],
    })
    time.sleep(2.1)

out_path = ROOT / "hyperautomation" / "panw_library_rules_full.json"
out_path.write_text(json.dumps(OUT, indent=2))
print(f"[+] wrote {out_path.relative_to(ROOT)}")
print()
for r in OUT:
    print(f"--- {r['severity']:8} {r['name']}")
    print(f"    q: {r['query'] or '(no query)'}")
