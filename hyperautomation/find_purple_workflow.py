#!/usr/bin/env python3
"""Find the existing 'Trigger Purple AI Investigation' Hyperautomation workflow
on the tenant and export its JSON so we can use it as a starting point."""
import json, sys, requests
from pathlib import Path

CFG = json.loads(Path("hyperautomation/config.json").read_text())
BASE = CFG["base_url"].rstrip("/")
TOKEN = CFG["api_token"]
H = {"Authorization": f"ApiToken {TOKEN}", "Content-Type": "application/json"}

# Hyperautomation workflows live at /web/api/v2.1/hyperautomation/workflows
# (different versions of S1 use slightly different endpoints; try a few)
candidates = [
    "/web/api/v2.1/hyper-automate/api/public/workflows",
]
found = None
for ep in candidates:
    url = BASE + ep
    r = requests.get(url, headers=H, params={"limit": 100}, timeout=30)
    print(f"GET {ep:50} -> {r.status_code}")
    if r.status_code == 200:
        found = ep
        break

if not found:
    print("[!] couldn't find workflow endpoint. Trying search via 'name' filter...")
    sys.exit(1)

url = BASE + found
out_dir = Path(__file__).resolve().parent.parent / "hyperautomation"
out_dir.mkdir(parents=True, exist_ok=True)

cursor = None
all_wfs = []
while True:
    params = {"limit": 100}
    if cursor: params["cursor"] = cursor
    r = requests.get(url, headers=H, params=params, timeout=30)
    r.raise_for_status()
    j = r.json()
    data = j.get("data") or []
    all_wfs.extend(data)
    cursor = (j.get("pagination") or {}).get("nextCursor")
    if not cursor: break
print(f"[+] total workflows on tenant: {len(all_wfs)}")

# Save listing
(out_dir / "_all_workflows_summary.json").write_text(json.dumps([
    {"id": w.get("id"), "name": w.get("name"), "description": w.get("description", "")[:80]}
    for w in all_wfs
], indent=2))

# Find purple-related
purple = [w for w in all_wfs if "purple" in (w.get("name","").lower() + " " + (w.get("description","") or "").lower())]
print(f"[+] purple-related: {len(purple)}")
for w in purple:
    print(f"    - {w['id']}  {w['name']}")
    out = out_dir / f"existing_{w['name'].replace(' ', '_').replace('/','-')[:60]}.json"
    out.write_text(json.dumps(w, indent=2))
    print(f"      -> saved {out.relative_to(out_dir.parent)}")

if not purple:
    print("[!] no 'Purple' workflow found. Listing names containing 'investigation':")
    inv = [w for w in all_wfs if "investigation" in (w.get("name","").lower())]
    for w in inv[:10]:
        print(f"    - {w['id']}  {w['name']}")
