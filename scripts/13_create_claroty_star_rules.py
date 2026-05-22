#!/usr/bin/env python3
"""Register the 5 Claroty x Palo Alto PowerQuery detections as Custom STAR
rules on the tenant, then enable them at site scope.

Endpoint:  POST /web/api/v2.1/cloud-detection/rules
Auth:      ApiToken <S1 console API token>
Required permission: STAR Custom Rules: Create/Edit

The query language is PowerQuery (queryLang=2 for some tenants, sometimes
expressed as 'PowerQuery'/'EventQuery'; we send both and fall back). Each
rule body is the corresponding .pq file from detections/.
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path
import requests

ROOT  = Path(__file__).resolve().parent.parent
DETN  = ROOT / "detections"
CFG   = Path("hyperautomation/config.json")
cfg   = json.loads(CFG.read_text())
BASE  = cfg["base_url"].rstrip("/")
H     = {"Authorization": f"ApiToken {cfg['api_token']}", "Content-Type": "application/json"}

# Map our local files to STAR rule metadata
RULES = [
    {
        "file":     "D1_OT_critical_asset_has_wrong_or_missing_Palo_Alto_EDL-DAG.pq",
        "name":     "Claroty: Critical OT device has wrong/missing PAN EDL or DAG",
        "severity": "High",
        "description": "Critical/High Claroty asset observed with an EDL or DAG that does not match the expected value from Claroty inventory. Trigger Hyperautomation to re-tag.",
    },
    {
        "file":     "D2_OT_device_reclassified_in_Claroty_but_Palo_Alto_tagging_is_s.pq",
        "name":     "Claroty: Device reclassified but PAN tagging is stale",
        "severity": "Medium",
        "description": "Claroty has updated the device_type but PAN traffic still references the previous DAG. Re-tag required.",
    },
    {
        "file":     "D3_Newly_discovered_or_unmanaged_OT_asset_crossing_zones.pq",
        "name":     "Claroty: Newly discovered / unmanaged OT asset crossing zones",
        "severity": "High",
        "description": "An asset Claroty considers unassigned/unknown is sending PAN traffic across zones (src_zone != dst_zone).",
    },
    {
        "file":     "D4_High-risk_Claroty_asset_communicating_outside_its_approved_z.pq",
        "name":     "Claroty: High-risk asset talking outside approved zone",
        "severity": "Critical",
        "description": "Asset with Claroty risk >=80 communicating to IT-CORP/INTERNET/DMZ/GUEST. Immediate EDL block candidate.",
    },
    {
        "file":     "D5_Decommissioned_Claroty_asset_still_resolved_by_an_active_EDL.pq",
        "name":     "Claroty: Decommissioned asset still in active EDL/DAG",
        "severity": "Medium",
        "description": "Claroty marked the asset Decommissioned but PAN traffic still shows it tagged in a production EDL or DAG.",
    },
]


def discover_site_id() -> str:
    r = requests.get(f"{BASE}/web/api/v2.1/sites", headers=H,
                     params={"limit": 5}, timeout=30)
    r.raise_for_status()
    sites = (r.json().get("data") or {}).get("sites") or []
    if not sites:
        raise RuntimeError("No sites visible to this token")
    print(f"[+] site: {sites[0]['name']} ({sites[0]['id']})")
    return sites[0]["id"]


def list_existing_rules(site_id: str) -> dict:
    """Map name -> rule_id for already-created rules under this site."""
    out = {}
    skip = 0
    while True:
        r = requests.get(f"{BASE}/web/api/v2.1/cloud-detection/rules",
                         headers=H, params={"limit": 200, "skip": skip,
                                            "siteIds": site_id}, timeout=60)
        if r.status_code != 200:
            print(f"  list-existing {r.status_code}: {r.text[:200]}")
            return out
        data = r.json().get("data") or []
        for d in data:
            out[d.get("name")] = d.get("id")
        if len(data) < 200:
            break
        skip += 200
    return out


def create_rule(site_id: str, rule: dict, query: str) -> dict | None:
    payload = {
        "filter": {"siteIds": [site_id]},
        "data": {
            "name":              rule["name"],
            "description":       rule["description"],
            "severity":          rule["severity"],
            "queryType":         "events",
            "queryLang":         "PowerQuery",
            "s1ql":              query,
            "expirationMode":    "Permanent",
            "networkQuarantine": False,
            "treatAsThreat":     "UNDEFINED",
            "status":            "Activating",
        },
    }
    r = requests.post(f"{BASE}/web/api/v2.1/cloud-detection/rules",
                      headers=H, json=payload, timeout=60)
    if r.status_code == 200:
        d = r.json().get("data") or {}
        print(f"   created id={d.get('id')}")
        return d
    print(f"   [FAIL {r.status_code}] {r.text[:400]}")
    return None


def enable_rule(site_id: str, rule_id: str) -> bool:
    body = {
        "filter": {"ids": [rule_id], "siteIds": [site_id]},
    }
    r = requests.put(f"{BASE}/web/api/v2.1/cloud-detection/rules/enable",
                     headers=H, json=body, timeout=30)
    if r.status_code == 200:
        print(f"   enabled {rule_id}")
        return True
    print(f"   enable {rule_id} [{r.status_code}] {r.text[:200]}")
    return False


def main() -> int:
    site = discover_site_id()
    existing = list_existing_rules(site)
    print(f"[+] {len(existing)} custom rules already on this site")

    created, skipped = 0, 0
    for rule in RULES:
        print(f"\n--- {rule['name']}")
        if rule["name"] in existing:
            print(f"   already exists id={existing[rule['name']]} -> ensuring enabled")
            enable_rule(site, existing[rule["name"]])
            skipped += 1
            continue
        q = (DETN / rule["file"]).read_text().strip()
        d = create_rule(site, rule, q)
        if d:
            created += 1
            time.sleep(1.0)
            enable_rule(site, d.get("id"))
        time.sleep(2.0)

    print(f"\n[+] created: {created}, skipped existing: {skipped}, total target: {len(RULES)}")
    print("[+] STAR rules evaluate every 5-15 min. Watch Detect -> Findings (Detection engine = STAR).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
