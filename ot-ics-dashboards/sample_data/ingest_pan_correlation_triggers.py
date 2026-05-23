#!/usr/bin/env python3
"""
Ingest synthetic PAN firewall CORRELATION events that trigger the platform
rule "PANW Firewall High Severity Correlation Event Detected".

Rule s1ql:
    dataSource.name = 'Palo Alto Networks Firewall'
    AND metadata.log_name = 'CORRELATION'
    AND unmapped.severity in ('high', 'critical')
"""

from __future__ import annotations

import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

_default = Path.home() / "windsurf/shared/sentinelone-sdl-api/scripts"
sys.path.insert(0, str(Path(os.environ.get("SDL_CLIENT_PATH", _default))))

from sdl_client import SDLClient  # type: ignore


# A few PAN-style "correlation object" categories
CORRELATION_OBJECTS = [
    "compromised-host",
    "command-and-control-activity",
    "beacon-detection",
    "exfiltration-detected",
    "exploit-kit-activity",
]

# Targets from the OT environment we've been simulating
TARGETS = [
    ("plc-bf-tap-02",     "192.0.2.51", "BLAST_FURNACE", "CROWN_JEWEL"),
    ("plc-bf-burner-01",  "192.0.2.50", "BLAST_FURNACE", "CROWN_JEWEL"),
    ("sis-bf-safety-01",  "192.0.2.40", "SAFETY",        "CROWN_JEWEL"),
    ("hmi-bf-eng-02",     "192.0.2.62", "DMZ",           "CRITICAL"),
    ("plc-bf-cool-03",    "192.0.2.53", "BLAST_FURNACE", "CRITICAL"),
]

NUM_EVENTS = 12   # enough to fire several alerts (deduped by rule)


def main() -> int:
    random.seed(20260523)
    client = SDLClient()
    print(f"Connected to: {client.base_url}\n")

    now = datetime.now(timezone.utc)
    base_ns = int(now.timestamp() * 1_000_000_000)
    window_ns = 20 * 60 * 1_000_000_000   # last 20 min

    session = SDLClient.new_session_id()
    session_info = {
        "serverHost":  "pan-ot-fw-01",
        "parser":      "panFirewall",
        "dataset":     "panw_firewall",
        "source":      "ot-ics-dashboards/sample_data/pan_correlation_triggers",
    }

    events: list[dict] = []
    for i in range(NUM_EVENTS):
        target_name, target_ip, zone, criticality = random.choice(TARGETS)
        corr_object  = random.choice(CORRELATION_OBJECTS)
        sev_label    = random.choice(["high", "critical"])
        jitter       = random.randint(0, window_ns)
        ts_ns        = base_ns - jitter

        # Build the event with all three "nested" fields the rule looks for.
        # Provide BOTH nested-dict form and dot-flat form, so XDR
        # normalization picks them up either way.
        attrs = {
            # --- dataSource.name ---
            "dataSource": {
                "name":    "Palo Alto Networks Firewall",
                "vendor":  "Palo Alto Networks",
                "product": "PA-Series Firewall",
                "category": "Firewall",
            },
            "dataSource.name":    "Palo Alto Networks Firewall",
            "dataSource.vendor":  "Palo Alto Networks",
            "dataSource.product": "PA-Series Firewall",

            # --- metadata.log_name ---
            "metadata": {
                "log_name":       "CORRELATION",
                "log_type":       "CORRELATION",
                "product_type":   "PAN-OS",
                "vendor":         "Palo Alto Networks",
                "log_source":     "pan-ot-fw-01",
                "uid":            f"CORR-{i:08d}",
                "time":           datetime.fromtimestamp(
                                    ts_ns / 1_000_000_000, tz=timezone.utc
                                  ).isoformat(),
            },
            "metadata.log_name":     "CORRELATION",
            "metadata.log_type":     "CORRELATION",
            "metadata.product_type": "PAN-OS",
            "metadata.vendor":       "Palo Alto Networks",

            # --- unmapped.severity ---
            "unmapped": {
                "severity":            sev_label,
                "correlation_object":  corr_object,
                "correlation_id":      f"CO-{i:08d}",
                "match_count":         random.randint(3, 25),
                "category":            "spyware" if "command" in corr_object
                                        else "exploit",
                "threat_id":           random.randint(10000, 99999),
                "rule_name":           f"PAN-Correlation-{corr_object}",
            },
            "unmapped.severity":           sev_label,
            "unmapped.correlation_object": corr_object,
            "unmapped.match_count":        random.randint(3, 25),

            # Target / OT context
            "asset_name":   target_name,
            "src_ip":       target_ip,
            "dst_ip":       f"203.0.113.{random.randint(2, 250)}",
            "src_zone":     zone,
            "dst_zone":     "DMZ",
            "criticality":  criticality,
            "action":       "alert",
            "log_type":     "CORRELATION",
            "vendor":       "Palo Alto Networks",
            "product":      "Firewall",
            "rule_name":    f"PAN-CorrEngine-{corr_object}",
        }

        events.append({"ts": ts_ns, "sev": 5, "attrs": attrs})

    print(f"Sending {len(events)} CORRELATION events ({NUM_EVENTS} total, "
          f"random high/critical severity, random targets)...")
    res = client.add_events(session=session, events=events,
                            session_info=session_info)
    print(f"  status={res.get('status')}  bytes={res.get('bytesCharged')}")

    print("\nWaiting 5 s for indexing...")
    time.sleep(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
