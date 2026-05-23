#!/usr/bin/env python3
"""
Create / upsert STAR Custom Detection rules (scheduled PowerQuery) for the
OT/ICS use cases:

  3.2 Nozomi process-variable anomaly cross-correlation
    a) Unauthorized write to SAFETY zone                              High
    b) Process-variable anomaly in BLAST_FURNACE                      Medium
    c) BLAST_FURNACE/SAFETY write + PV anomaly within 1 min           Critical
    d) PLC programming / firmware download                            Critical
    e) Operating-mode change on Safety PLC                            Critical

  3.3 Crown-jewel / safety-PLC
    f) Long SRA session (>1h) on SIL-3 crown jewel                    High
    g) New CRITICAL vulnerability on a CROWN_JEWEL asset              Critical

Each rule is created at the user's site scope. If a rule with the same
name already exists, it's updated in place (idempotent).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# locate S1Client
SKILL = Path.home() / ".codeium/windsurf/s1-claude-skills/sentinelone-mgmt-console-api"
sys.path.insert(0, str(SKILL / "scripts"))

from s1_client import S1Client  # type: ignore


# Scope: user's site (Marc Chisinevski).
SITE_ID = "REDACTED_SITE_ID"
ACCOUNT_ID = "REDACTED_ACCOUNT_ID"


# ----------------------------------------------------------------------------
# Rule queries (PowerQuery, lookback 24h, run every 60 min)
# ----------------------------------------------------------------------------
RULES = [
    {
        "name": "OT 3.2a - Nozomi unauthorized write to SAFETY zone",
        "severity": "High",
        "description": ("Modbus write function code (5/6/15/16 or WRITE_VAR/"
                        "STOP_PLC/FORCE_OUTPUT) observed targeting an asset "
                        "in the SAFETY zone. MITRE ATT&CK for ICS T0836."),
        "query": (
            "| filter dataset == 'nozomi'\n"
            "| parse '\"function_code\": \"$fc{regex=[^\"]+}$\"' from message\n"
            "| parse '\"zone\": \"$zn{regex=[^\"]+}$\"' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"src_ip\": \"$srcip{regex=[^\"]+}$\"' from message\n"
            "| filter zn == \"SAFETY\"\n"
            "| filter fc == \"5\" or fc == \"6\" or fc == \"15\" or fc == \"16\""
            " or fc == \"WRITE_VAR\" or fc == \"STOP_PLC\" or fc == \"FORCE_OUTPUT\"\n"
            "| group writes = count() by an, srcip, fc\n"
            "| filter writes > 0"
        ),
    },
    {
        "name": "OT 3.2b - Nozomi PV anomaly in BLAST_FURNACE",
        "severity": "Medium",
        "description": ("Process-variable deviation detected in the "
                        "BLAST_FURNACE zone. MITRE ATT&CK for ICS T0831."),
        "query": (
            "| filter dataset == 'nozomi'\n"
            "| parse '\"alert_type\": \"$at{regex=[^\"]+}$\"' from message\n"
            "| parse '\"zone\": \"$zn{regex=[^\"]+}$\"' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"process_variable\": \"$pv{regex=[^\"]+}$\"' from message\n"
            "| filter zn == \"BLAST_FURNACE\"\n"
            "| filter at == \"PROCESS_VARIABLE_ANOMALY\"\n"
            "| group anomalies = count() by an, pv\n"
            "| filter anomalies > 0"
        ),
    },
    {
        "name": "OT 3.2c - Nozomi BLAST_FURNACE/SAFETY write + PV anomaly (1 min)",
        "severity": "Critical",
        "description": ("ANSSI-2014 German steel-mill pattern: an unauthorized "
                        "write to a BLAST_FURNACE/SAFETY asset coincides "
                        "within the same minute with a process-variable "
                        "anomaly on that asset. MITRE ATT&CK for ICS "
                        "T0836/T0855/T0831."),
        "query": (
            "| filter dataset == 'nozomi'\n"
            "| parse '\"alert_type\": \"$at{regex=[^\"]+}$\"' from message\n"
            "| parse '\"function_code\": \"$fc{regex=[^\"]+}$\"' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"zone\": \"$zn{regex=[^\"]+}$\"' from message\n"
            "| group\n"
            "    writes    = count( (zn == \"BLAST_FURNACE\" or zn == \"SAFETY\")"
            " and (fc == \"5\" or fc == \"6\" or fc == \"15\" or fc == \"16\""
            " or fc == \"WRITE_VAR\") ),\n"
            "    anomalies = count( at == \"PROCESS_VARIABLE_ANOMALY\" )\n"
            "  by minute = timebucket('1 minute'), an\n"
            "| filter writes > 0 and anomalies > 0"
        ),
    },
    {
        "name": "OT 3.2d - Nozomi PLC programming / firmware download",
        "severity": "Critical",
        "description": ("PLC program upload/download or firmware update "
                        "observed against an ICS asset. MITRE ATT&CK for "
                        "ICS T0843/T0857."),
        "query": (
            "| filter dataset == 'nozomi'\n"
            "| parse '\"alert_type\": \"$at{regex=[^\"]+}$\"' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"src_ip\": \"$srcip{regex=[^\"]+}$\"' from message\n"
            "| filter at == \"PLC_PROGRAM_UPLOAD\""
            " or at == \"PLC_PROGRAM_DOWNLOAD\""
            " or at == \"FIRMWARE_UPDATE\"\n"
            "| group attempts = count() by an, srcip, at\n"
            "| filter attempts > 0"
        ),
    },
    {
        "name": "OT 3.2e - Nozomi operating-mode change on Safety PLC",
        "severity": "Critical",
        "description": ("Operating-mode change or PLC start/stop command "
                        "observed against a SAFETY or BLAST_FURNACE asset. "
                        "MITRE ATT&CK for ICS T0858."),
        "query": (
            "| filter dataset == 'nozomi'\n"
            "| parse '\"alert_type\": \"$at{regex=[^\"]+}$\"' from message\n"
            "| parse '\"zone\": \"$zn{regex=[^\"]+}$\"' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"src_ip\": \"$srcip{regex=[^\"]+}$\"' from message\n"
            "| filter zn == \"SAFETY\" or zn == \"BLAST_FURNACE\"\n"
            "| filter at == \"CHANGE_OPERATING_MODE\""
            " or at == \"STOP_PLC\" or at == \"START_PLC\"\n"
            "| group events = count() by an, zn, srcip, at\n"
            "| filter events > 0"
        ),
    },
    {
        "name": "OT 3.3a - Claroty long SRA session on SIL-3 crown jewel",
        "severity": "High",
        "description": ("Secure-Remote-Access session lasting more than one "
                        "hour against a SIL-3 crown-jewel asset. MITRE ATT&CK "
                        "for ICS T0822/T0866."),
        "query": (
            "| filter dataset == 'claroty'\n"
            "| parse '\"sra_session_id\": \"$sid{regex=[^\"]+}$\"' from message\n"
            "| parse '\"sra_user\": \"$su{regex=[^\"]+}$\"' from message\n"
            "| parse '\"sra_duration_sec\": $dur{regex=[0-9]+}$' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"sil_level\": \"$sl{regex=[^\"]+}$\"' from message\n"
            "| parse '\"criticality\": \"$cr{regex=[^\"]+}$\"' from message\n"
            "| filter sl == \"SIL-3\" or sl == \"SIL3\"\n"
            "| filter cr == \"CROWN_JEWEL\" or cr == \"CRITICAL\"\n"
            "| filter dur > 3600\n"
            "| group max_sec = max(dur) by sid, su, an\n"
            "| filter max_sec > 3600"
        ),
    },
    {
        "name": "OT 3.3b - Claroty new CRITICAL vuln on crown jewel",
        "severity": "Critical",
        "description": ("A new CRITICAL-severity vulnerability finding was "
                        "reported on a CROWN_JEWEL / CRITICAL Claroty asset. "
                        "MITRE ATT&CK for ICS T0866."),
        "query": (
            "| filter dataset == 'claroty'\n"
            "| parse '\"event_type\": \"$et{regex=[^\"]+}$\"' from message\n"
            "| parse '\"vuln_severity\": \"$vs{regex=[^\"]+}$\"' from message\n"
            "| parse '\"asset_name\": \"$an{regex=[^\"]+}$\"' from message\n"
            "| parse '\"criticality\": \"$cr{regex=[^\"]+}$\"' from message\n"
            "| parse '\"cve_id\": \"$cve{regex=[^\"]+}$\"' from message\n"
            "| filter et == \"VULN_FOUND\"\n"
            "| filter vs == \"CRITICAL\"\n"
            "| filter cr == \"CROWN_JEWEL\" or cr == \"CRITICAL\"\n"
            "| group n = count() by an, cve, vs\n"
            "| filter n > 0"
        ),
    },
]


def build_body(rule: dict) -> dict:
    return {
        "filter": {"siteIds": [SITE_ID]},
        "data": {
            "name":           rule["name"],
            "description":    rule["description"],
            "severity":       rule["severity"],
            "queryType":      "scheduled",
            "status":         "Active",
            "expirationMode": "Permanent",
            "queryLang":      "2.0",
            "scheduledParams": {
                "query":                 rule["query"],
                "lookbackWindowMinutes": 1440,    # 24h
                "runIntervalMinutes":    15,      # every 15 min (min for 24h lookback)
                "threshold":             {"value": 0, "operator": "Greater"},
            },
            "coolOffSettings": {"renotifyMinutes": 60},
            "networkQuarantine": False,
        },
    }


_RULES_CACHE: list[dict] | None = None


def _list_site_rules(c: S1Client) -> list[dict]:
    """Cached list of rules at the site (filtering client-side because the
    server's `nameSubstring` / `name__contains` params return HTTP 500 on
    this tenant)."""
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    out: list[dict] = []
    params = {"siteIds": SITE_ID, "limit": 1000}
    for page in c.paginate("/web/api/v2.1/cloud-detection/rules", params=params):
        out.extend(page.get("data") or [])
    _RULES_CACHE = out
    return out


def find_existing(c: S1Client, name: str) -> str | None:
    for item in _list_site_rules(c):
        if item.get("name") == name:
            return item.get("id")
    return None


def upsert(c: S1Client, rule: dict) -> tuple[str, str]:
    body = build_body(rule)
    existing_id = find_existing(c, rule["name"])
    if existing_id:
        res = c.put(f"/web/api/v2.1/cloud-detection/rules/{existing_id}", json_body=body)
        return ("updated", existing_id)
    res = c.post("/web/api/v2.1/cloud-detection/rules", json_body=body)
    items = res.get("data") or []
    new_id = (items[0].get("id") if isinstance(items, list) and items
              else (res.get("data", {}).get("id") if isinstance(res.get("data"), dict)
                    else ""))
    return ("created", new_id or "?")


def main() -> int:
    c = S1Client()
    print(f"Connected to: {c.base_url}")
    print(f"Site:         {SITE_ID}")
    print(f"Rules:        {len(RULES)}\n")
    for r in RULES:
        try:
            action, rid = upsert(c, r)
            print(f"  [{action:>7}]  id={rid}  {r['severity']:<8}  {r['name']}")
        except Exception as e:
            print(f"  [   FAIL]  {r['name']}  -> {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
