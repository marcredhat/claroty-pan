#!/usr/bin/env python3
"""
Ingest one fresh, self-contained set of OT/ICS sample events so that the
dashboards and rules light up when you refresh for the **last 1 hour**.

It produces and ingests:
  * Nozomi events   (dataset = 'nozomi')
      - baseline reads + occasional protocol violations spread across 60 min
      - a 25-min "steel-mill" attack burst in the most recent 25 min:
        unauthorized writes from a DMZ EWS to BLAST_FURNACE PLCs +
        coincident PV anomalies on those PLCs +
        a programming-download attempt + a SAFETY-zone stop command.
  * Claroty events  (dataset = 'claroty')
      - SRA sessions to crown-jewel assets (incl. some > 1 h on SIL-3)
      - new CRITICAL vuln findings on crown-jewel assets
      - asset inventory snapshots for the heatmap
  * PAN firewall events (dataset = 'panw_firewall')
      - 14 events with each of the 5 claroty_*_flag = '1' values, so the
        existing Claroty-on-PANW STAR rules see fresh data
      - 12 CORRELATION events (severity high/critical) for the platform rule
        "PANW Firewall High Severity Correlation Event Detected"

Rules and dashboards are NOT touched. Run as often as you like.

Usage:
    python ingest_fresh_all.py                 # default 60-min window
    python ingest_fresh_all.py --minutes 30
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

# locate SDLClient
_default = Path.home() / "windsurf/shared/sentinelone-sdl-api/scripts"
sys.path.insert(0, str(Path(os.environ.get("SDL_CLIENT_PATH", _default))))

from sdl_client import SDLClient  # type: ignore


# ----------------------------------------------------------------------------
# OT topology (matches the dashboards / generator already in this repo)
# ----------------------------------------------------------------------------
NOZOMI_ASSETS = [
    # asset_id, asset_name, ip, zone, role, criticality
    ("PLC-BF-001", "plc-bf-burner-01",  "192.0.2.50", "BLAST_FURNACE", "PLC", "CROWN_JEWEL"),
    ("PLC-BF-002", "plc-bf-tap-02",     "192.0.2.51", "BLAST_FURNACE", "PLC", "CROWN_JEWEL"),
    ("PLC-BF-003", "plc-bf-cool-03",    "192.0.2.52", "BLAST_FURNACE", "PLC", "CROWN_JEWEL"),
    ("PLC-BF-004", "plc-bf-charge-04",  "192.0.2.53", "BLAST_FURNACE", "PLC", "CRITICAL"),
    ("SIS-BF-001", "sis-bf-safety-01",  "192.0.2.40", "SAFETY",        "SIS", "CROWN_JEWEL"),
    ("HMI-BF-001", "hmi-bf-control-01", "192.0.2.30", "HMI",           "HMI", "HIGH"),
    ("EWS-BF-001", "ews-bf-eng-01",     "192.0.2.31", "DMZ",           "EWS", "MEDIUM"),
    ("EWS-BF-002", "ews-bf-eng-02",     "192.0.2.62", "DMZ",           "EWS", "MEDIUM"),
]
BF_PLCS    = [a for a in NOZOMI_ASSETS if a[3] == "BLAST_FURNACE"]
SAFETY     = [a for a in NOZOMI_ASSETS if a[3] == "SAFETY"]
EVIL_EWS   = next(a for a in NOZOMI_ASSETS if a[1] == "ews-bf-eng-02")  # the suspect

CLAROTY_ASSETS = [
    # name, ip, zone, sil, criticality
    ("plc-bf-burner-01",  "192.0.2.50", "BLAST_FURNACE", "SIL-3", "CROWN_JEWEL"),
    ("plc-bf-tap-02",     "192.0.2.51", "BLAST_FURNACE", "SIL-3", "CROWN_JEWEL"),
    ("plc-bf-cool-03",    "192.0.2.52", "BLAST_FURNACE", "SIL-3", "CROWN_JEWEL"),
    ("plc-bf-charge-04",  "192.0.2.53", "BLAST_FURNACE", "SIL-2", "CRITICAL"),
    ("sis-bf-safety-01",  "192.0.2.40", "SAFETY",        "SIL-3", "CROWN_JEWEL"),
    ("hmi-bf-control-01", "192.0.2.30", "HMI",           "N/A",   "HIGH"),
    ("hist-bf-pi-01",     "192.0.2.20", "DCS",           "SIL-1", "HIGH"),
    ("hist-bf-pi-02",     "192.0.2.21", "DCS",           "SIL-1", "HIGH"),
    ("ews-bf-eng-01",     "192.0.2.31", "DMZ",           "N/A",   "MEDIUM"),
    ("ews-bf-eng-02",     "192.0.2.62", "DMZ",           "N/A",   "MEDIUM"),
]

CRITICAL_CVES = [
    ("CVE-2024-21413", "Microsoft Outlook RCE",            9.8),
    ("CVE-2024-3400",  "PAN-OS GlobalProtect Command Inj", 10.0),
    ("CVE-2024-1086",  "Linux Kernel nf_tables UAF",       7.8),
    ("CVE-2025-1234",  "Siemens SIMATIC S7 Auth Bypass",   9.6),
    ("CVE-2025-5678",  "Schneider Modicon RCE",            9.4),
]

SRA_USERS = ["vendor.ot.maint", "siemens.support", "schneider.eng",
             "internal.engineer.01", "internal.engineer.02"]


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def ns(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000_000)


def jitter(base: datetime, seconds: int) -> datetime:
    return base - timedelta(seconds=random.randint(0, seconds))


def chunked(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# ----------------------------------------------------------------------------
# Generators
# ----------------------------------------------------------------------------
def gen_nozomi(now: datetime, window_min: int) -> List[dict]:
    """Last `window_min` of Nozomi telemetry + a recent steel-mill burst."""
    events: List[dict] = []

    # 1) Baseline reads, every ~30 s per asset
    for asset in NOZOMI_ASSETS:
        for k in range(window_min * 2):
            ts = now - timedelta(seconds=k * 30 + random.randint(0, 25))
            events.append(_noz(ts, asset, alert_type="BASELINE_READ",
                               function_code="3", role=asset[4]))

    # 2) Sporadic PV telemetry (normal values)
    for _ in range(window_min * 4):
        a = random.choice(BF_PLCS)
        ts = jitter(now, window_min * 60)
        pv = random.choice(["blast_furnace_temp_c", "blast_furnace_pressure_bar",
                            "cooling_water_flow_lps", "oxygen_flow_nm3h"])
        events.append(_noz(ts, a, alert_type="PV_TELEMETRY",
                           process_variable=pv,
                           value=round(random.uniform(1400, 1500), 1),
                           baseline=1450, deviation=0.0,
                           function_code="3", role="PLC", severity="INFO"))

    # 3) Steel-mill attack burst in the most recent ~min(25, window_min) min
    burst_min = min(25, window_min)
    burst_start = now - timedelta(minutes=burst_min)
    for _ in range(80):
        target = random.choice(BF_PLCS)
        t = burst_start + timedelta(seconds=random.randint(0, burst_min * 60))
        # Unauthorized write from the suspicious EWS
        events.append(_noz(
            t, target,
            alert_type="UNAUTHORIZED_WRITE",
            function_code=random.choice(["WRITE_VAR", "6", "16"]),
            role="PLC",
            severity="HIGH",
            src_ip=EVIL_EWS[2],
        ))
        # PV anomaly on the same target within seconds
        t2 = t + timedelta(seconds=random.randint(2, 25))
        pv = "blast_furnace_temp_c"
        events.append(_noz(
            t2, target,
            alert_type="PROCESS_VARIABLE_ANOMALY",
            process_variable=pv,
            value=round(random.choice([1340, 1620, 1700, 1280]) +
                        random.uniform(-30, 30), 1),
            baseline=1450,
            deviation=round(random.uniform(60, 250), 1),
            function_code="3", role="PLC", severity="HIGH",
        ))
    # 4) Programming download on a PLC + STOP on SAFETY SIS
    target = random.choice(BF_PLCS)
    t = jitter(now, burst_min * 60)
    events.append(_noz(t, target,
                       alert_type="PLC_PROGRAM_DOWNLOAD",
                       function_code="PROGRAM_DOWNLOAD",
                       role="PLC", severity="CRITICAL",
                       src_ip=EVIL_EWS[2]))
    sis = SAFETY[0]
    t = jitter(now, min(10, window_min) * 60)
    events.append(_noz(t, sis,
                       alert_type="CHANGE_OPERATING_MODE",
                       function_code="STOP_PLC",
                       role="SIS", severity="CRITICAL",
                       src_ip=EVIL_EWS[2]))
    # 5) Protocol violations sprinkled in
    for _ in range(8):
        target = random.choice(NOZOMI_ASSETS)
        t = jitter(now, window_min * 60)
        events.append(_noz(t, target,
                           alert_type="PROTOCOL_VIOLATION",
                           function_code="NEW_FUNCTION_CODE",
                           role=target[4], severity="MEDIUM"))
    return events


def _noz(ts: datetime, asset, **kw) -> dict:
    aid, name, ip, zone, role, _crit = asset
    payload = {
        "dataset":    "nozomi",
        "timestamp":  ts.isoformat().replace("+00:00", "Z"),
        "vendor":     "Nozomi Networks",
        "product":    "Guardian",
        "severity":   kw.pop("severity", "LOW"),
        "src_ip":     kw.pop("src_ip", ip),
        "dst_ip":     ip,
        "protocol":   "modbus",
        "asset_id":   aid,
        "asset_name": name,
        "zone":       zone,
        "role":       kw.pop("role", role),
        **kw,
    }
    # message is the canonical JSON, attrs are flat for top-level queries
    import json as _json
    return {
        "ts":   ns(ts),
        "sev":  {"INFO": 2, "LOW": 3, "MEDIUM": 4, "HIGH": 5, "CRITICAL": 6}
                .get(payload["severity"], 3),
        "attrs": {**payload, "message": _json.dumps(payload), "dataset": "nozomi"},
    }


def gen_claroty(now: datetime, window_min: int) -> List[dict]:
    """Last `window_min` of Claroty telemetry: inventory snapshots, SRA, vulns.

    NOTE: The dashboard panel "Claroty assets in inventory" filters on
    ``serverHost = 'claroty-inventory' AND ip = *``, and the time series
    "Stage 1+2 - Claroty inventory ingest over time" groups by
    ``claroty_site``. Both require fields to be flat top-level attributes
    (`ip`, `claroty_site`), not buried in nested `message`. We emit them
    that way here."""
    events: List[dict] = []
    import json as _json

    # zone -> Claroty "site" name (matches dashboard $plant parameter).
    ZONE_TO_SITE = {
        "BLAST_FURNACE": "PLANT-A",
        "SAFETY":        "PLANT-A",
        "HMI":           "PLANT-A",
        "DCS":           "PLANT-A",
        "DMZ":           "PLANT-B",
    }

    # 1) Inventory snapshot (one per asset)
    for name, ip, zone, sil, crit in CLAROTY_ASSETS:
        ts = jitter(now, window_min * 60)
        risk = random.randint(40, 95)
        site = ZONE_TO_SITE.get(zone, "PLANT-A")
        payload = {
            "dataset":            "claroty",
            "timestamp":          ts.isoformat().replace("+00:00", "Z"),
            "vendor":             "Claroty",
            "product":            "xDome",
            "event_type":         "INVENTORY_SNAPSHOT",
            "asset_name":         name,
            "asset_ip":           ip,
            "zone":               zone,
            "sil_level":          sil,
            "criticality":        crit,
            "risk_score":         risk,
            # ---- fields required by claroty-pan-pipeline dashboard ----
            "ip":                 ip,           # top-level for `ip = *` filter
            "claroty_site":       site,         # group-by + $plant filter
            "claroty_hostname":   name,
            "claroty_criticality":crit,
            "claroty_risk":       risk,
            "claroty_status":     "ACTIVE",
        }
        events.append({"ts": ns(ts), "sev": 2,
                       "attrs": {**payload, "message": _json.dumps(payload),
                                 "dataset": "claroty"}})

    # 2) SRA sessions: 12 normal + 4 long (>1h) targeting SIL-3 crown jewels
    for _ in range(12):
        a = random.choice(CLAROTY_ASSETS)
        ts = jitter(now, window_min * 60)
        dur = random.randint(60, 1800)
        u = random.choice(SRA_USERS)
        site = ZONE_TO_SITE.get(a[2], "PLANT-A")
        payload = {
            "dataset":         "claroty",
            "timestamp":       ts.isoformat().replace("+00:00", "Z"),
            "vendor":          "Claroty",
            "product":         "SRA",
            "event_type":      "SRA_SESSION",
            "asset_name":      a[0],
            "zone":            a[2],
            "sil_level":       a[3],
            "criticality":     a[4],
            "sra_session_id":  f"SRA-{random.randint(100000, 999999)}",
            "sra_user":        u,
            "sra_duration_sec": dur,
            # ---- claroty_* enrichment + ip so SRA rows also appear in the
            #      Stage 1+2 time-series panel (group-by claroty_site).
            "ip":               a[1],
            "claroty_site":     site,
            "claroty_hostname": a[0],
            "claroty_criticality": a[4],
            "claroty_status":   "ACTIVE",
        }
        events.append({"ts": ns(ts), "sev": 3,
                       "attrs": {**payload, "message": _json.dumps(payload),
                                 "dataset": "claroty"}})
    crown_jewels_sil3 = [a for a in CLAROTY_ASSETS
                         if a[3] == "SIL-3" and a[4] == "CROWN_JEWEL"]
    for _ in range(4):
        a = random.choice(crown_jewels_sil3)
        ts = jitter(now, window_min * 60)
        dur = random.randint(3700, 14400)   # >1h up to 4h
        u = random.choice(SRA_USERS)
        site = ZONE_TO_SITE.get(a[2], "PLANT-A")
        payload = {
            "dataset":         "claroty",
            "timestamp":       ts.isoformat().replace("+00:00", "Z"),
            "vendor":          "Claroty",
            "product":         "SRA",
            "event_type":      "SRA_SESSION",
            "asset_name":      a[0],
            "zone":            a[2],
            "sil_level":       a[3],
            "criticality":     a[4],
            "sra_session_id":  f"SRA-{random.randint(100000, 999999)}",
            "sra_user":        u,
            "sra_duration_sec": dur,
            "ip":               a[1],
            "claroty_site":     site,
            "claroty_hostname": a[0],
            "claroty_criticality": a[4],
            "claroty_status":   "ACTIVE",
        }
        events.append({"ts": ns(ts), "sev": 5,
                       "attrs": {**payload, "message": _json.dumps(payload),
                                 "dataset": "claroty"}})

    # 3) New CRITICAL vuln findings on crown jewels
    for _ in range(5):
        a = random.choice(crown_jewels_sil3)
        cve, desc, cvss = random.choice(CRITICAL_CVES)
        ts = jitter(now, window_min * 60)
        site = ZONE_TO_SITE.get(a[2], "PLANT-A")
        payload = {
            "dataset":       "claroty",
            "timestamp":     ts.isoformat().replace("+00:00", "Z"),
            "vendor":        "Claroty",
            "product":       "xDome",
            "event_type":    "VULN_FOUND",
            "asset_name":    a[0],
            "zone":          a[2],
            "sil_level":     a[3],
            "criticality":   a[4],
            "cve_id":        cve,
            "cve_desc":      desc,
            "cvss":          cvss,
            "vuln_severity": "CRITICAL",
            "ip":               a[1],
            "claroty_site":     site,
            "claroty_hostname": a[0],
            "claroty_criticality": a[4],
            "claroty_status":   "ACTIVE",
        }
        events.append({"ts": ns(ts), "sev": 6,
                       "attrs": {**payload, "message": _json.dumps(payload),
                                 "dataset": "claroty"}})
    return events


def gen_pan_claroty(now: datetime, window_min: int) -> List[dict]:
    """PAN firewall events carrying the 5 claroty_*_flag values.

    Emits the full set of claroty_* enrichment fields that the
    "Stage 4/5 Drift events ..." panels group by:
      claroty_site, claroty_criticality, claroty_risk, claroty_status,
      claroty_hostname, claroty_expected_edl, src_external_dynamic_list,
      scenario, src.ip.address.
    """
    scenarios = [
        # (flag,                                count, hostname_prefix, zone,            site)
        ("claroty_edl_drift_flag",                3, "plc-bf-tap",      "BLAST_FURNACE", "PLANT-A"),
        ("claroty_decommissioned_active_flag",   2, "hmi-decom",       "BLAST_FURNACE", "PLANT-A"),
        ("claroty_dag_reclassified_flag",         2, "sis-bf-safety",   "SAFETY",        "PLANT-A"),
        ("claroty_highrisk_offzone_flag",         4, "plc-bf-burner",   "BLAST_FURNACE", "PLANT-A"),
        ("claroty_unmanaged_cross_zone_flag",     3, "unknown-host",    "GUEST_WIFI",    "PLANT-B"),
    ]
    events: List[dict] = []
    for flag, count, prefix, zone, site in scenarios:
        scenario_name = flag.replace("claroty_", "").replace("_flag", "")
        for i in range(count):
            ts = jitter(now, window_min * 60)
            hostname    = f"{prefix}-{(i % 3) + 1:02d}"
            src_ip      = f"192.0.2.{60 + i}"
            criticality = "CROWN_JEWEL" if zone in ("BLAST_FURNACE", "SAFETY") else "HIGH"
            risk        = random.randint(60, 98)
            status      = ("DECOMMISSIONED"
                           if flag == "claroty_decommissioned_active_flag"
                           else "ACTIVE")
            expected_edl = f"edl-{zone.lower()}-approved"
            observed_edl = (expected_edl
                            if flag != "claroty_edl_drift_flag"
                            else f"edl-{zone.lower()}-unapproved")
            attrs = {
                "dataSource": {
                    "name":    "Palo Alto Networks Firewall",
                    "vendor":  "Palo Alto Networks",
                    "product": "PA-Series Firewall",
                },
                "dataSource.name":     "Palo Alto Networks Firewall",
                "vendor":              "Palo Alto Networks",
                "product":             "Firewall",
                "action":              "deny" if i % 2 else "allow",
                "log_type":            "TRAFFIC",
                "rule_name":           f"ot-policy-{scenario_name}",
                # ---- the flag the dashboard / STAR rules pivot on ----
                flag:                  "1",
                # ---- canonical claroty_* enrichment expected by Stage 4/5 panels
                "claroty_asset_id":         f"AST-{scenario_name[:4].upper()}-{i:04d}",
                "claroty_asset_name":       hostname,
                "claroty_hostname":         hostname,
                "claroty_zone":             zone,
                "claroty_site":             site,
                "claroty_criticality":      criticality,
                "claroty_risk":             risk,
                "claroty_status":           status,
                "claroty_expected_edl":     expected_edl,
                # ---- src/dst plus the dotted form the Stage 4 panel uses
                "src_ip":                   src_ip,
                "src.ip.address":           src_ip,
                "src_external_dynamic_list":observed_edl,
                "dst_ip":                   f"203.0.113.{10 + i}",
                # ---- scenario tag for the "Stage 5 - Recent Claroty STAR drift events" panel
                "scenario":                 scenario_name,
            }
            events.append({"ts": ns(ts), "sev": 4, "attrs": attrs})
    return events


def gen_pan_library_trigger(now: datetime, window_min: int) -> List[dict]:
    """PANW Library trigger events (firewall library rule hits) enriched
    with Claroty context. Routed to serverHost ``pan-library-trigger`` so
    the dashboard panel "PANW Library triggers with Claroty enrichment"
    can group by ``library_rule_target``."""
    library_rules = [
        ("ot-block-internet-egress",       "plc-bf-tap-02",    "192.0.2.51", "BLAST_FURNACE", "PLANT-A", "CROWN_JEWEL"),
        ("ot-block-rdp-from-corp",         "hmi-bf-control-01","192.0.2.30", "HMI",           "PLANT-A", "HIGH"),
        ("ot-allow-engineering-station",   "ews-bf-eng-01",    "192.0.2.31", "DMZ",           "PLANT-B", "MEDIUM"),
        ("ot-deny-unmanaged-asset",        "unknown-host-001", "192.0.2.99", "GUEST_WIFI",    "PLANT-B", "HIGH"),
        ("ot-isolate-decommissioned",      "hmi-bf-decom-01",  "192.0.2.99", "BLAST_FURNACE", "PLANT-A", "CRITICAL"),
    ]
    events: List[dict] = []
    for rule, hostname, ip, zone, site, crit in library_rules:
        for i in range(random.randint(2, 4)):
            ts = jitter(now, window_min * 60)
            in_inventory = "true" if not hostname.startswith("unknown-host") else "false"
            context = ("crown-jewel-engineering"
                       if crit == "CROWN_JEWEL"
                       else "managed-asset"
                       if in_inventory == "true"
                       else "unmanaged-shadow-asset")
            attrs = {
                "dataSource": {
                    "name":    "Palo Alto Networks Firewall",
                    "vendor":  "Palo Alto Networks",
                    "product": "PA-Series Firewall",
                },
                "dataSource.name":      "Palo Alto Networks Firewall",
                "vendor":               "Palo Alto Networks",
                "product":              "Firewall",
                "log_type":             "LIBRARY-TRIGGER",
                "rule_name":            rule,
                # ---- library rule fields ----
                "library_rule":         rule,
                "library_rule_target":  hostname,
                "action":               "deny" if rule.startswith("ot-block") or rule.startswith("ot-deny") else "allow",
                # ---- Claroty enrichment expected by the Stage 5 panel ----
                "claroty_hostname":     hostname,
                "claroty_site":         site,
                "claroty_criticality":  crit,
                "claroty_risk":         random.randint(50, 95),
                "claroty_status":       "DECOMMISSIONED" if "decom" in hostname else "ACTIVE",
                "claroty_in_inventory": in_inventory,
                "claroty_context":      context,
                # ---- src/dst ----
                "src_ip":               ip,
                "src.ip.address":       ip,
                "dst_ip":               f"203.0.113.{random.randint(2, 250)}",
            }
            events.append({"ts": ns(ts), "sev": 4, "attrs": attrs})
    return events


def gen_pan_correlation(now: datetime, window_min: int) -> List[dict]:
    """PAN CORRELATION events (high/critical) for the platform rule."""
    objects = ["compromised-host", "command-and-control-activity",
               "beacon-detection", "exfiltration-detected", "exploit-kit-activity"]
    targets = [
        ("plc-bf-tap-02",     "192.0.2.51", "BLAST_FURNACE", "CROWN_JEWEL"),
        ("plc-bf-burner-01",  "192.0.2.50", "BLAST_FURNACE", "CROWN_JEWEL"),
        ("sis-bf-safety-01",  "192.0.2.40", "SAFETY",        "CROWN_JEWEL"),
        ("hmi-bf-eng-02",     "192.0.2.62", "DMZ",           "CRITICAL"),
        ("plc-bf-cool-03",    "192.0.2.53", "BLAST_FURNACE", "CRITICAL"),
    ]
    events: List[dict] = []
    for i in range(12):
        target_name, target_ip, zone, crit = random.choice(targets)
        obj = random.choice(objects)
        sev = random.choice(["high", "critical"])
        ts = jitter(now, window_min * 60)
        attrs = {
            "dataSource": {"name": "Palo Alto Networks Firewall",
                           "vendor": "Palo Alto Networks",
                           "product": "PA-Series Firewall"},
            "dataSource.name":  "Palo Alto Networks Firewall",
            "metadata": {"log_name": "CORRELATION",
                         "log_type": "CORRELATION",
                         "product_type": "PAN-OS",
                         "vendor": "Palo Alto Networks",
                         "uid": f"CORR-{i:08d}"},
            "metadata.log_name": "CORRELATION",
            "metadata.log_type": "CORRELATION",
            "unmapped": {"severity": sev,
                         "correlation_object": obj,
                         "correlation_id": f"CO-{i:08d}",
                         "match_count": random.randint(3, 25),
                         "threat_id": random.randint(10000, 99999),
                         "rule_name": f"PAN-Correlation-{obj}"},
            "unmapped.severity":           sev,
            "unmapped.correlation_object": obj,
            "asset_name":  target_name,
            "src_ip":      target_ip,
            "dst_ip":      f"203.0.113.{random.randint(2, 250)}",
            "src_zone":    zone,
            "dst_zone":    "DMZ",
            "criticality": crit,
            "action":      "alert",
            "log_type":    "CORRELATION",
            "vendor":      "Palo Alto Networks",
            "product":     "Firewall",
        }
        events.append({"ts": ns(ts), "sev": 5, "attrs": attrs})
    return events


# ----------------------------------------------------------------------------
# Ingest
# ----------------------------------------------------------------------------
# IMPORTANT: dashboards/claroty-pan-pipeline.json filters on these exact
# serverHost names. Do not change them without also updating the dashboard.
SERVERHOSTS = {
    "nozomi":               "nozomi-guardian",
    "claroty":              "claroty-inventory",     # "Claroty assets in inventory" panel
    "panw_firewall":        "pan-claroty-enriched",  # "Drift events ..." panels
    "panw_correlation":     "pan-correlation",       # "PAN events (24h)" counter
    "panw_library_trigger": "pan-library-trigger",   # "PANW Library triggers ..." panel
}


def ingest(client: SDLClient, events: List[dict], dataset: str,
           server_host: str | None = None) -> None:
    if not events:
        print(f"[SKIP] {dataset}: no events")
        return
    session = SDLClient.new_session_id()
    sh = server_host or SERVERHOSTS.get(dataset, f"ot-ics-fresh-{dataset}")
    session_info = {
        "serverHost": sh,
        "parser":     dataset,
        "dataset":    dataset,
        "source":     "ot-ics-dashboards/sample_data/ingest_fresh_all",
    }
    print(f"[*] {dataset} -> serverHost='{sh}': ingesting {len(events)} events")
    for i, chunk in enumerate(chunked(events, 500), 1):
        res = client.add_events(session=session, events=chunk,
                                session_info=session_info)
        print(f"    chunk {i:>2}: {len(chunk):>4} events  "
              f"status={res.get('status')}  bytes={res.get('bytesCharged')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=60,
                    help="Spread events over the last N minutes (default 60).")
    ap.add_argument("--seed", type=int, default=None,
                    help="Random seed (default: time-based, so each run "
                         "produces different events).")
    ap.add_argument("--config", type=Path, default=None,
                    help="Path to SDL config.json. Defaults to the SDLClient "
                         "built-in path (~/windsurf/shared/sentinelone-sdl-"
                         "api/config.json). Can also be set via the "
                         "SDL_CONFIG_PATH env var. Individual settings can "
                         "still be overridden via SDL_BASE_URL, "
                         "SDL_LOG_WRITE_KEY, etc.")
    args = ap.parse_args()

    random.seed(args.seed if args.seed is not None else int(time.time()))

    config_path = args.config or (
        Path(os.environ["SDL_CONFIG_PATH"]) if os.environ.get("SDL_CONFIG_PATH")
        else None
    )
    if config_path is not None:
        config_path = config_path.expanduser().resolve()
        if not config_path.is_file():
            print(f"ERROR: config file not found: {config_path}", file=sys.stderr)
            return 2
        print(f"Config:       {config_path}")
        client = SDLClient(config_path=config_path)
    else:
        client = SDLClient()
    print(f"Connected to: {client.base_url}")
    now = datetime.now(timezone.utc)
    print(f"Now (UTC):    {now.isoformat()}")
    print(f"Window:       last {args.minutes} min\n")

    noz_events   = gen_nozomi(now, args.minutes)
    cla_events   = gen_claroty(now, args.minutes)
    pan_claroty  = gen_pan_claroty(now, args.minutes)
    pan_corr     = gen_pan_correlation(now, args.minutes)
    pan_libtrig  = gen_pan_library_trigger(now, args.minutes)

    print(f"Generated:")
    print(f"  nozomi:                  {len(noz_events):>5}")
    print(f"  claroty (inventory):     {len(cla_events):>5}")
    print(f"  panw_firewall (flags):   {len(pan_claroty):>5}")
    print(f"  panw correlation:        {len(pan_corr):>5}")
    print(f"  panw library trigger:    {len(pan_libtrig):>5}\n")

    # Route each stream to the serverHost the dashboard queries.
    ingest(client, noz_events,    "nozomi")
    ingest(client, cla_events,    "claroty")
    ingest(client, pan_claroty,   "panw_firewall")
    ingest(client, pan_corr,      "panw_correlation")
    ingest(client, pan_libtrig,   "panw_library_trigger")

    print("\nDone. Refresh the dashboards with a 'last 1 hour' time window:")
    print("  https://<your-xdr-host>/#/dashboards")
    print("And check alerts:")
    print("  https://<your-mgmt-console>/incidents/unified-alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
