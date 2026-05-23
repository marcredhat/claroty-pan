#!/usr/bin/env python3
"""
Ingest synthetic Palo Alto Networks firewall events that trigger the five
existing Claroty-on-PANW STAR Custom Detection rules.

Each rule fires on:
    dataSource.name == 'Palo Alto Networks Firewall'
    AND claroty_<scenario>_flag == '1'

We ingest a handful of events per flag so each rule produces one or more
alerts in https://<your-mgmt-console>/incidents/unified-alerts.

The events are spread evenly across the last 30 minutes (so they appear in
all the dashboards' 24h windows and in the rules' lookbackWindowMinutes=1440
evaluation window).
"""

from __future__ import annotations

import os
import sys
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Locate SDLClient
_default = Path.home() / "windsurf/shared/sentinelone-sdl-api/scripts"
SDL_CLIENT_PATH = Path(os.environ.get("SDL_CLIENT_PATH", _default))
sys.path.insert(0, str(SDL_CLIENT_PATH))

from sdl_client import SDLClient  # type: ignore


SCENARIOS = [
    {
        "flag":   "claroty_edl_drift_flag",
        "rule":   "Claroty: Critical OT device has wrong/missing PAN EDL or DAG",
        "events": 3,
        "extra":  lambda i: {
            "claroty_asset_id":      f"AST-EDL-{i:04d}",
            "claroty_asset_name":    f"plc-bf-tap-0{(i % 3) + 1}",
            "claroty_zone":          "BLAST_FURNACE",
            "claroty_criticality":   "CROWN_JEWEL",
            "claroty_sil":           "SIL-3",
            "expected_edl":          "ot_blast_furnace_v3",
            "observed_edl":          "" if i % 2 else "ot_legacy_v1",
            "pan_dag":               "" if i == 0 else "ot-dag-legacy",
            "expected_dag":          "ot-dag-blast-furnace",
            "policy_violation":      "Missing EDL membership",
        },
    },
    {
        "flag":   "claroty_decommissioned_active_flag",
        "rule":   "Claroty: Decommissioned asset still in active EDL/DAG",
        "events": 2,
        "extra":  lambda i: {
            "claroty_asset_id":          f"AST-DEC-{i:04d}",
            "claroty_asset_name":        f"hmi-bf-decom-0{i + 1}",
            "claroty_zone":              "BLAST_FURNACE",
            "claroty_status":            "DECOMMISSIONED",
            "claroty_decom_date":        "2026-03-15T00:00:00Z",
            "pan_edl":                   "ot_blast_furnace_v3",
            "pan_dag":                   "ot-dag-blast-furnace",
            "policy_violation":          "Decommissioned asset still in active policy",
        },
    },
    {
        "flag":   "claroty_dag_reclassified_flag",
        "rule":   "Claroty: Device reclassified but PAN tagging is stale",
        "events": 2,
        "extra":  lambda i: {
            "claroty_asset_id":          f"AST-RECL-{i:04d}",
            "claroty_asset_name":        f"sis-bf-safety-0{i + 1}",
            "claroty_zone":              "SAFETY",
            "claroty_criticality":       "CROWN_JEWEL",
            "claroty_sil":               "SIL-3",
            "old_classification":        "ot-asset-l2-control",
            "new_classification":        "ot-asset-sis-l3-safety",
            "pan_dag":                   "ot-dag-l2-control",
            "expected_dag":              "ot-dag-sis-safety",
            "policy_violation":          "Stale DAG tag after reclassification",
        },
    },
    {
        "flag":   "claroty_highrisk_offzone_flag",
        "rule":   "Claroty: High-risk asset talking outside approved zone",
        "events": 4,
        "extra":  lambda i: {
            "claroty_asset_id":          f"AST-HR-{i:04d}",
            "claroty_asset_name":        f"plc-bf-burner-0{(i % 2) + 1}",
            "claroty_zone_approved":     "BLAST_FURNACE",
            "claroty_zone_observed":     "DMZ" if i % 2 else "CORP",
            "claroty_criticality":       "CROWN_JEWEL",
            "src_ip":                    f"192.0.2.{50 + i}",
            "dst_ip":                    f"203.0.113.{10 + i}",
            "dst_port":                  443 if i % 2 else 8443,
            "policy_violation":          "Crown-jewel asset talking outside approved zone",
        },
    },
    {
        "flag":   "claroty_unmanaged_cross_zone_flag",
        "rule":   "Claroty: Newly discovered / unmanaged OT asset crossing zones",
        "events": 3,
        "extra":  lambda i: {
            "claroty_asset_id":          f"AST-UNK-{i:04d}",
            "claroty_asset_name":        f"unknown-host-{i:03d}",
            "claroty_first_seen":        (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "claroty_managed":           "false",
            "claroty_zone_observed":     ["BLAST_FURNACE", "SAFETY", "CORP"][i % 3],
            "claroty_zone_crossed_from": "GUEST_WIFI",
            "src_ip":                    f"192.0.2.{200 + i}",
            "policy_violation":          "Unknown/unmanaged asset crossing zone boundary",
        },
    },
]


def main() -> int:
    random.seed(20260523)
    client = SDLClient()
    print(f"Connected to: {client.base_url}\n")

    now = datetime.now(timezone.utc)
    base_ns = int(now.timestamp() * 1_000_000_000)
    window_ns = 30 * 60 * 1_000_000_000   # spread across last 30 min

    session = SDLClient.new_session_id()
    session_info = {
        "serverHost":   "pan-ot-fw-01",
        "parser":       "panFirewall",
        "dataset":      "panw_firewall",
        "source":       "ot-ics-dashboards/sample_data/pan_claroty_triggers",
    }

    all_events: list[dict] = []
    for sc in SCENARIOS:
        flag = sc["flag"]
        for i in range(sc["events"]):
            jitter = random.randint(0, window_ns)
            ts_ns = base_ns - jitter
            attrs = {
                # Top-level field used by the STAR rules' s1ql 2.0 syntax
                "dataSource": {
                    "name":   "Palo Alto Networks Firewall",
                    "vendor": "Palo Alto Networks",
                    "product": "PA-Series Firewall",
                },
                # Promote dataSource.name as a flat key too so Scalyr can
                # match either dot-path or flat lookup.
                "dataSource.name": "Palo Alto Networks Firewall",
                "vendor":          "Palo Alto Networks",
                "product":         "Firewall",
                # PAN-ish fields
                "action":          "deny" if i % 2 else "allow",
                "log_type":        "TRAFFIC",
                "rule_name":       f"ot-policy-{flag.replace('claroty_', '').replace('_flag','')}",
                # The flag the rule looks for
                flag:              "1",
                # Extra context
                **sc["extra"](i),
            }
            all_events.append({"ts": ts_ns, "sev": 4, "attrs": attrs})

    print(f"Total events to send: {len(all_events)}")
    res = client.add_events(session=session, events=all_events,
                            session_info=session_info)
    print(f"  status={res.get('status')}  bytes={res.get('bytesCharged')}")

    # short pause so SDL has the events when we verify
    print("\nWaiting 5 s for indexing...")
    time.sleep(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
