#!/usr/bin/env python3
"""End-to-end:
  1. Read Claroty inventory CSV -> IP -> attrs dict
  2. Regenerate the PAN events at the current wall-clock and ENRICH each event
     with Claroty attrs (claroty_*) AND pre-computed drift flags
     (claroty_*_drift_flag = '1' / '0') so STAR rules can match a single
     enriched event without needing a lookup join.
  3. Ingest enriched events via SDL addEvents to serverHost='pan-claroty-enriched'.
  4. Register 5 STAR custom rules using s1ql (queryLang='2.0') that simply
     filter on the pre-computed drift flags. Enable at site scope.

After STAR re-evaluation (5-15 min) the alerts appear in Detect -> Findings.
"""
from __future__ import annotations
import csv, json, sys, time
from pathlib import Path
import requests

ROOT      = Path(__file__).resolve().parent.parent
CLAR_CSV  = ROOT / "data" / "claroty_assets.csv"
S1_CFG    = Path("hyperautomation/config.json")
cfg       = json.loads(S1_CFG.read_text())
BASE      = cfg["base_url"].rstrip("/")
H_MGMT    = {"Authorization": f"ApiToken {cfg['api_token']}", "Content-Type": "application/json"}

# SDL ingest creds: prefer dedicated SDL config if present
sdl_cfg   = json.loads((ROOT / "config.json").read_text())
SDL_BASE  = (sdl_cfg.get("base_url") or "https://<your-region>.sentinelone.net").rstrip("/")
SDL_TOKEN = (sdl_cfg.get("log_write_key") or sdl_cfg.get("sdl_log_write_token")
             or sdl_cfg.get("log_write_token"))
H_SDL = {"Authorization": f"Bearer {SDL_TOKEN}", "Content-Type": "application/json"} if SDL_TOKEN else None

SERVER_HOST = "pan-claroty-enriched"
SESSION_ID  = int(time.time())
print(f"[+] tenant     : {BASE}")
print(f"[+] sdl base   : {SDL_BASE}")
print(f"[+] sdl token  : {'set' if SDL_TOKEN else 'MISSING'}")
print(f"[+] serverHost : {SERVER_HOST}  (session={SESSION_ID})")


# ---------------- 1. Load Claroty inventory ----------------
inv = {}
with CLAR_CSV.open() as f:
    for row in csv.DictReader(f):
        inv[row["ip"]] = row
print(f"[+] loaded {len(inv)} Claroty assets")


# ---------------- 2. Build enriched PAN events ----------------
APPROVED_ZONES = {
    "OT-CTRL":      {"OT-HISTORIAN", "OT-CTRL", "OT-HMI"},
    "OT-HMI":       {"OT-CTRL", "OT-HMI", "OT-HISTORIAN"},
    "OT-ENG":       {"OT-CTRL", "OT-HMI"},
    "OT-PROTECT":   {"OT-RTAC", "OT-PROTECT"},
    "OT-RTAC":      {"OT-HMI", "OT-PROTECT"},
    "OT-HISTORIAN": {"OT-HISTORIAN", "OT-CTRL"},
    "OT-FIELD":     {"OT-CTRL", "OT-HISTORIAN"},
    "OT-SAFETY":    {"OT-CTRL", "OT-SAFETY"},
    "OT-DRIVES":    {"OT-CTRL"},
    "OT-GATEWAY":   {"OT-HMI", "OT-CTRL"},
}

# Re-use the same scenario list from 02_generate_pan.py but inline & enriched.
# (sip, dip, sz, dz, act, app, edl, dag, group)
SCENARIOS = []
# CLEAN baseline
CLEAN = [
    ("10.20.10.11","10.20.40.41","OT-CTRL","OT-HISTORIAN","allow","opcua","edl-plc-prod","dag-plc-prod"),
    ("10.20.10.12","10.20.40.41","OT-CTRL","OT-HISTORIAN","allow","opcua","edl-plc-prod","dag-plc-prod"),
    ("10.20.10.13","10.20.40.41","OT-CTRL","OT-HISTORIAN","allow","opcua","edl-plc-prod","dag-plc-prod"),
    ("10.20.20.21","10.20.10.11","OT-HMI","OT-CTRL","allow","modbus","edl-hmi-prod","dag-hmi-prod"),
    ("10.20.20.22","10.20.10.12","OT-HMI","OT-CTRL","allow","s7comm","edl-hmi-prod","dag-hmi-prod"),
    ("10.20.30.31","10.20.10.13","OT-ENG","OT-CTRL","allow","ssh","edl-ews","dag-ews"),
    ("10.40.10.11","10.40.20.21","OT-PROTECT","OT-RTAC","allow","iec61850","edl-ied","dag-ied"),
    ("10.20.70.71","10.20.10.11","OT-SAFETY","OT-CTRL","allow","safety-bus","edl-safety","dag-safety"),
    ("10.20.50.51","10.20.40.41","OT-FIELD","OT-HISTORIAN","allow","dnp3","edl-rtu","dag-rtu"),
    ("10.20.60.61","10.20.10.11","OT-DRIVES","OT-CTRL","allow","profinet","edl-drives","dag-drives"),
]
for _ in range(3):
    SCENARIOS.extend([("CLEAN", *t) for t in CLEAN])

# D1 — Critical OT device with WRONG/MISSING EDL/DAG
SCENARIOS.extend([("D1", "10.20.10.11","10.20.40.41","OT-CTRL","OT-HISTORIAN","allow","opcua","edl-misc-iot","dag-misc-iot")]*4)
SCENARIOS.extend([("D1", "10.20.70.71","10.20.10.11","OT-SAFETY","OT-CTRL","allow","safety-bus","","")]*3)
# D2 — Reclassified device (PAN still has OLD tags)
SCENARIOS.extend([("D2", "10.20.30.32","10.20.10.11","OT-ENG","OT-CTRL","allow","ssh","edl-hmi-prod","dag-hmi-prod")]*5)
# D3 — Newly discovered unmanaged asset crossing zones
SCENARIOS.extend([("D3", "10.20.99.99","10.20.10.11","OT-UNKNOWN","OT-CTRL","allow","modbus","unknown","unknown")]*4)
SCENARIOS.extend([("D3", "10.20.99.99","10.20.40.41","OT-UNKNOWN","OT-HISTORIAN","allow","https","unknown","unknown")]*4)
# D4 — High-risk Claroty asset OFF approved zone
SCENARIOS.extend([("D4", "10.30.50.51","192.168.50.20","OT-CTRL","IT-CORP","allow","rdp","edl-plc-prod","dag-plc-prod")]*5)
SCENARIOS.extend([("D4", "10.30.50.51","203.0.113.45","OT-CTRL","INTERNET","allow","http-proxy","edl-plc-prod","dag-plc-prod")]*2)
# D5 — Decommissioned IP still tagged with active EDL
SCENARIOS.extend([("D5", "10.99.99.10","10.20.40.41","OT-CTRL","OT-HISTORIAN","allow","opcua","edl-plc-prod","dag-plc-prod")]*3)


def enrich(sip, sip_zone, dst_zone, edl, dag):
    """Return dict of claroty_* + drift flags."""
    asset = inv.get(sip)
    apg   = (asset or {}).get("approved_policy_group", "")
    # Derive status from approved_policy_group (CSV has no explicit status column)
    if apg == "decommissioned":
        status = "Decommissioned"
    elif apg == "unassigned":
        status = "Unassigned"
    elif asset:
        status = "Active"
    else:
        status = "Unknown"
    a = {
        "claroty_in_inventory":      "1" if (asset and apg not in ("unassigned",)) else "0",
        "claroty_hostname":          (asset or {}).get("hostname", ""),
        "claroty_device_type":       (asset or {}).get("device_type", ""),
        "claroty_criticality":       (asset or {}).get("criticality", ""),
        "claroty_risk":              (asset or {}).get("claroty_risk", "0"),
        "claroty_status":            status,
        "claroty_site":              (asset or {}).get("site", ""),
        "claroty_expected_edl":      (asset or {}).get("expected_edl", ""),
        "claroty_expected_dag":      (asset or {}).get("expected_dag", ""),
        "claroty_approved_policy":   apg,
    }
    crit  = a["claroty_criticality"] in ("High", "Critical")
    risk  = int(a["claroty_risk"] or 0)
    in_inv = a["claroty_in_inventory"] == "1"
    decom = status == "Decommissioned"
    edl_mismatch = (a["claroty_expected_edl"] and a["claroty_expected_edl"] != edl)
    dag_mismatch = (a["claroty_expected_dag"] and a["claroty_expected_dag"] != dag)
    approved = APPROVED_ZONES.get(sip_zone, set())
    cross_zone = (sip_zone != dst_zone)
    off_zone   = (dst_zone not in approved) if approved else False

    a["claroty_edl_drift_flag"]            = "1" if (crit and edl_mismatch) else "0"
    a["claroty_dag_reclassified_flag"]     = "1" if (in_inv and dag_mismatch and a["claroty_device_type"] == "EWS") else "0"
    a["claroty_unmanaged_cross_zone_flag"] = "1" if (not in_inv and cross_zone) else "0"
    a["claroty_highrisk_offzone_flag"]     = "1" if (in_inv and risk >= 80 and off_zone) else "0"
    a["claroty_decommissioned_active_flag"]= "1" if (decom and edl and edl != "unknown") else "0"
    return a


def build_event(i, scenario, sip, dip, sz, dz, act, app, edl, dag):
    attrs = {
        "dataSource.name":           "Palo Alto Networks Firewall",
        "dataSource.vendor":         "Palo Alto Networks",
        "dataSource.category":       "security",
        "event.type":                "traffic",
        "class_uid":                 "4001",  # OCSF Network Activity
        "serverHost":                SERVER_HOST,
        "scenario":                  scenario,
        "session_id":                str(SESSION_ID),
        "src.ip.address":            sip,
        "dst.ip.address":            dip,
        "src_zone":                  sz,
        "dst_zone":                  dz,
        "action":                    act,
        "application":               app,
        "src_external_dynamic_list": edl,
        "src_dynamic_address_group": dag,
        "message":                   f"{scenario} {sip}->{dip} {app} {act}",
    }
    attrs.update(enrich(sip, sz, dz, edl, dag))
    return {"ts": int((time.time() - 600 + i * 2) * 1_000_000_000), "attrs": attrs}


events = [build_event(i, *s) for i, s in enumerate(SCENARIOS)]
print(f"[+] built {len(events)} enriched events")
# Flag counts
flag_counts = {}
for e in events:
    for k, v in e["attrs"].items():
        if k.endswith("_flag") and v == "1":
            flag_counts[k] = flag_counts.get(k, 0) + 1
print(f"[+] drift flag counts: {flag_counts}")


# ---------------- 3. Ingest via addEvents ----------------
if not SDL_TOKEN:
    print("[-] no SDL log-write token configured -> cannot ingest")
    sys.exit(2)

# addEvents schema: {token, session, events:[{ts, sev, attrs}]}
batch = {
    "token":  SDL_TOKEN,
    "session": f"claroty-enriched-{SESSION_ID}",
    "events": [{"ts": e["ts"], "sev": 3, "attrs": e["attrs"]} for e in events],
}
url = f"{SDL_BASE}/api/addEvents"
r = requests.post(url, json=batch, timeout=60)
print(f"[+] addEvents -> {r.status_code} {r.text[:160]}")
if r.status_code != 200:
    sys.exit(3)


# ---------------- 4. Register STAR rules ----------------
def discover_site() -> str:
    rr = requests.get(f"{BASE}/web/api/v2.1/sites", headers=H_MGMT, params={"limit":1}, timeout=30)
    return rr.json()["data"]["sites"][0]["id"]

site_id = discover_site()
print(f"[+] site_id: {site_id}")

RULES = [
    ("Claroty: Critical OT device has wrong/missing PAN EDL or DAG", "High",
     "dataSource.name='Palo Alto Networks Firewall' AND claroty_edl_drift_flag='1'"),
    ("Claroty: Device reclassified but PAN tagging is stale", "Medium",
     "dataSource.name='Palo Alto Networks Firewall' AND claroty_dag_reclassified_flag='1'"),
    ("Claroty: Newly discovered / unmanaged OT asset crossing zones", "High",
     "dataSource.name='Palo Alto Networks Firewall' AND claroty_unmanaged_cross_zone_flag='1'"),
    ("Claroty: High-risk asset talking outside approved zone", "Critical",
     "dataSource.name='Palo Alto Networks Firewall' AND claroty_highrisk_offzone_flag='1'"),
    ("Claroty: Decommissioned asset still in active EDL/DAG", "Medium",
     "dataSource.name='Palo Alto Networks Firewall' AND claroty_decommissioned_active_flag='1'"),
]

# Map of existing rule name -> id
existing = {}
skip = 0
while True:
    rr = requests.get(f"{BASE}/web/api/v2.1/cloud-detection/rules",
                      headers=H_MGMT, params={"limit":200,"skip":skip,"siteIds":site_id}, timeout=60)
    data = rr.json().get("data") or []
    for d in data:
        existing[d.get("name")] = d.get("id")
    if len(data) < 200:
        break
    skip += 200
print(f"[+] {len(existing)} pre-existing custom rules on site")

created, enabled = [], []
for name, sev, query in RULES:
    print(f"\n--- {name}")
    rid = existing.get(name)
    if rid:
        print(f"   already exists id={rid}, will re-enable")
    else:
        payload = {
            "filter": {"siteIds": [site_id]},
            "data": {
                "name":              name,
                "description":       f"Auto-created. {query}",
                "severity":          sev,
                "queryType":         "events",
                "queryLang":         "2.0",
                "s1ql":              query,
                "expirationMode":    "Permanent",
                "networkQuarantine": False,
                "treatAsThreat":     "UNDEFINED",
                "status":            "Activating",
            },
        }
        cr = requests.post(f"{BASE}/web/api/v2.1/cloud-detection/rules",
                           headers=H_MGMT, json=payload, timeout=60)
        if cr.status_code != 200:
            print(f"   [FAIL {cr.status_code}] {cr.text[:300]}")
            continue
        rid = cr.json().get("data",{}).get("id")
        print(f"   created id={rid}")
        created.append(rid)
        time.sleep(1.0)

    er = requests.put(f"{BASE}/web/api/v2.1/cloud-detection/rules/enable",
                      headers=H_MGMT,
                      json={"filter": {"ids":[rid], "siteIds":[site_id]}},
                      timeout=30)
    if er.status_code == 200:
        print(f"   enabled")
        enabled.append(rid)
    else:
        print(f"   enable [{er.status_code}] {er.text[:200]}")
    time.sleep(1.5)

print(f"\n[+] created: {len(created)}, enabled: {len(enabled)} / {len(RULES)}")
print("[+] First STAR evaluation in 5-15 min. Watch Detect -> Findings (engine = STAR).")
