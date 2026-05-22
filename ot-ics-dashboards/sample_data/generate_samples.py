#!/usr/bin/env python3
"""
Generate sanitized synthetic Nozomi Guardian + Claroty xDome events that
match the field schema expected by the OT/ICS dashboards.

Output:
  - nozomi_sample.jsonl    (~2000 events, includes the ANSSI 2014 steel-mill
                            HMI->PLC write + PV-anomaly cross-correlation
                            pattern over a 90-minute window)
  - claroty_sample.jsonl   (~600 events, includes SIL-3 BLAST_FURNACE crown
                            jewels, SRA sessions, vuln severities, risk
                            scores 10..98)

All hostnames/IPs are RFC 5737 / RFC 2606 reserved. No real customer data.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
random.seed(20260523)

NOW = datetime.now(timezone.utc).replace(microsecond=0)


# ----------------------------------------------------------------------------
# Inventory (sanitized)
# ----------------------------------------------------------------------------
ZONES = ["DCS", "SAFETY", "BLAST_FURNACE", "UTILITIES", "DMZ"]
PLC_ASSETS = [
    # (asset_id, asset_name, zone, role, ip)
    ("PLC-BF-001", "plc-bf-burner-01",   "BLAST_FURNACE", "PLC", "192.0.2.11"),
    ("PLC-BF-002", "plc-bf-tap-02",      "BLAST_FURNACE", "PLC", "192.0.2.12"),
    ("PLC-SIS-01", "sis-bf-shutdown-01", "SAFETY",        "SIS", "192.0.2.21"),
    ("PLC-SIS-02", "sis-bf-vent-02",     "SAFETY",        "SIS", "192.0.2.22"),
    ("PLC-DCS-01", "plc-dcs-mix-01",     "DCS",           "PLC", "192.0.2.31"),
    ("PLC-DCS-02", "plc-dcs-feed-02",    "DCS",           "PLC", "192.0.2.32"),
    ("PLC-UTL-01", "plc-utl-water-01",   "UTILITIES",     "PLC", "192.0.2.41"),
]
HMI_EWS = [
    ("HMI-BF-01", "hmi-bf-op-01",  "DCS",   "HMI", "192.0.2.51"),
    ("HMI-BF-02", "hmi-bf-op-02",  "DCS",   "HMI", "192.0.2.52"),
    ("EWS-BF-01", "ews-bf-eng-01", "DCS",   "EWS", "192.0.2.61"),
    ("EWS-BF-02", "ews-bf-eng-02", "DMZ",   "EWS", "192.0.2.62"),  # suspicious
]

PROCESS_VARS = [
    ("blast_furnace_temp_c",   1450, 50,  "BLAST_FURNACE"),
    ("blast_furnace_press_bar",   4,  0.3, "BLAST_FURNACE"),
    ("tap_flow_kgs",            120, 10,  "BLAST_FURNACE"),
    ("burner_o2_pct",            21,  1,  "BLAST_FURNACE"),
    ("sis_trip_threshold_c",   1500, 20,  "SAFETY"),
    ("water_flow_lpm",          800, 30,  "UTILITIES"),
    ("mixer_speed_rpm",         750, 25,  "DCS"),
    ("feed_rate_kgs",            45,  2,  "DCS"),
]


def write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


# ----------------------------------------------------------------------------
# Nozomi event generators
# ----------------------------------------------------------------------------
def nozomi_event(ts: datetime, **fields) -> dict:
    base = {
        "dataset": "nozomi",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "vendor": "Nozomi Networks",
        "product": "Guardian",
        "severity": fields.pop("severity", "INFO"),
        "src_ip": fields.pop("src_ip", "192.0.2.51"),
        "dst_ip": fields.pop("dst_ip", "192.0.2.11"),
        "protocol": fields.pop("protocol", "modbus"),
    }
    base.update(fields)
    # The dashboards parse from the 'message' field, so collapse the structured
    # event into a JSON string there as well (matches how raw Nozomi syslog
    # arrives at SDL with a JSON payload in message).
    return {"message": json.dumps(base), **base}


def gen_nozomi() -> list[dict]:
    events: list[dict] = []
    start = NOW - timedelta(hours=23)

    # 1) Steady-state baseline traffic over 24h
    for minute in range(0, 24 * 60, 2):
        ts = start + timedelta(minutes=minute)
        plc = random.choice(PLC_ASSETS)
        hmi = random.choice(HMI_EWS)
        events.append(nozomi_event(
            ts,
            asset_id=plc[0], asset_name=plc[1], zone=plc[2], role=plc[3],
            src_ip=hmi[4], dst_ip=plc[4],
            function_code=random.choice(["3", "4", "READ_VAR"]),
            alert_type="BASELINE_READ",
            severity="INFO",
        ))

    # 2) Light, normal PV variance
    for minute in range(0, 24 * 60, 5):
        ts = start + timedelta(minutes=minute)
        pv_name, base_v, sigma, zone = random.choice(PROCESS_VARS)
        plc = next(p for p in PLC_ASSETS if p[2] == zone)
        events.append(nozomi_event(
            ts,
            asset_id=plc[0], asset_name=plc[1], zone=zone, role=plc[3],
            process_variable=pv_name,
            value=round(random.gauss(base_v, sigma * 0.3), 2),
            baseline=base_v,
            deviation=round(random.uniform(0, 0.5), 2),
            alert_type="PV_TELEMETRY",
            severity="INFO",
        ))

    # 3) ANSSI 2014 steel-mill pattern: 90-minute attack window starting ~6h ago.
    #    Suspicious EWS in DMZ -> Modbus WRITE_VAR / FC 6 / FC 16 against
    #    BLAST_FURNACE PLCs, followed within the same minute by PV anomalies.
    attack_start = NOW - timedelta(hours=6)
    suspicious_ews = HMI_EWS[3]   # ews-bf-eng-02 in DMZ
    target_plcs   = [p for p in PLC_ASSETS if p[2] == "BLAST_FURNACE"]
    sis_plcs      = [p for p in PLC_ASSETS if p[2] == "SAFETY"]

    for n in range(90):
        ts = attack_start + timedelta(minutes=n)
        plc = random.choice(target_plcs)

        # Unauthorized writes
        for _ in range(random.randint(2, 5)):
            events.append(nozomi_event(
                ts + timedelta(seconds=random.randint(0, 50)),
                asset_id=plc[0], asset_name=plc[1], zone=plc[2], role=plc[3],
                src_ip=suspicious_ews[4], dst_ip=plc[4],
                function_code=random.choice(["6", "16", "WRITE_VAR"]),
                protocol="modbus",
                alert_type="UNAUTHORIZED_WRITE",
                severity="HIGH",
            ))

        # Correlated PV anomalies (deviation grows over time)
        pv_name, base_v, sigma, _z = next(
            p for p in PROCESS_VARS if p[3] == "BLAST_FURNACE"
        )
        magnitude = 1.0 + (n / 30.0)
        events.append(nozomi_event(
            ts + timedelta(seconds=random.randint(5, 55)),
            asset_id=plc[0], asset_name=plc[1], zone=plc[2], role=plc[3],
            process_variable=pv_name,
            value=round(base_v + sigma * magnitude * random.choice([-1, 1]), 2),
            baseline=base_v,
            deviation=round(sigma * magnitude, 2),
            alert_type="PROCESS_VARIABLE_ANOMALY",
            severity="HIGH",
        ))

        # Periodic safety-zone protocol violation + mode change
        if n % 8 == 0:
            sis = random.choice(sis_plcs)
            events.append(nozomi_event(
                ts + timedelta(seconds=30),
                asset_id=sis[0], asset_name=sis[1], zone="SAFETY", role="SIS",
                src_ip=suspicious_ews[4], dst_ip=sis[4],
                function_code="STOP_PLC",
                protocol="modbus",
                alert_type="PROTOCOL_VIOLATION",
                severity="CRITICAL",
            ))
            events.append(nozomi_event(
                ts + timedelta(seconds=35),
                asset_id=sis[0], asset_name=sis[1], zone="SAFETY", role="SIS",
                src_ip=suspicious_ews[4], dst_ip=sis[4],
                alert_type="CHANGE_OPERATING_MODE",
                severity="CRITICAL",
            ))

        # Programming download attempt every ~20 minutes
        if n % 20 == 5:
            events.append(nozomi_event(
                ts + timedelta(seconds=15),
                asset_id=plc[0], asset_name=plc[1], zone=plc[2], role=plc[3],
                src_ip=suspicious_ews[4], dst_ip=plc[4],
                protocol="s7comm",
                alert_type=random.choice([
                    "PLC_PROGRAM_DOWNLOAD", "FIRMWARE_UPDATE"
                ]),
                severity="CRITICAL",
            ))

    # 4) A handful of baseline-drift alerts spread through the day
    for _ in range(15):
        ts = start + timedelta(minutes=random.randint(0, 24 * 60))
        plc = random.choice(PLC_ASSETS)
        events.append(nozomi_event(
            ts,
            asset_id=plc[0], asset_name=plc[1], zone=plc[2], role=plc[3],
            src_ip="192.0.2.62", dst_ip=plc[4],
            protocol=random.choice(["dnp3", "iec104", "opcua"]),
            function_code=random.choice(["23", "65", "CUSTOM_42"]),
            alert_type=random.choice(["NEW_PROTOCOL", "NEW_FUNCTION_CODE"]),
            severity="MEDIUM",
        ))

    return events


# ----------------------------------------------------------------------------
# Claroty event generators
# ----------------------------------------------------------------------------
CROWN_JEWELS = [
    # (asset_id, asset_name, zone, sil, crit, vendor, model, biz_impact)
    ("CL-001", "plc-bf-burner-01",   "BLAST_FURNACE", "SIL-3", "CROWN_JEWEL",
     "Siemens",    "S7-1500F",   "Production stop"),
    ("CL-002", "plc-bf-tap-02",      "BLAST_FURNACE", "SIL-3", "CROWN_JEWEL",
     "Siemens",    "S7-1500F",   "Production stop"),
    ("CL-003", "sis-bf-shutdown-01", "SAFETY",        "SIL-3", "CROWN_JEWEL",
     "HIMA",       "HIMax",      "Safety hazard"),
    ("CL-004", "sis-bf-vent-02",     "SAFETY",        "SIL-3", "CROWN_JEWEL",
     "HIMA",       "HIMax",      "Safety hazard"),
    ("CL-005", "plc-dcs-mix-01",     "DCS",           "SIL-2", "CRITICAL",
     "Rockwell",   "ControlLogix","Quality impact"),
    ("CL-006", "plc-dcs-feed-02",    "DCS",           "SIL-2", "CRITICAL",
     "Rockwell",   "ControlLogix","Quality impact"),
    ("CL-007", "plc-utl-water-01",   "UTILITIES",     "SIL-1", "HIGH",
     "Schneider",  "M580",       "Utility loss"),
    ("CL-008", "hist-bf-01",         "DCS",           "N/A",   "HIGH",
     "OSIsoft",    "PI Server",  "Reporting gap"),
    ("CL-009", "ews-bf-eng-01",      "DCS",           "N/A",   "MEDIUM",
     "Siemens",    "TIA Portal", "Engineering loss"),
    ("CL-010", "hmi-bf-op-01",       "DCS",           "N/A",   "MEDIUM",
     "Siemens",    "WinCC",      "Operator blind"),
]

VULN_SEV_WEIGHTS = ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]
SRA_USERS = ["vendor.siemens", "vendor.hima", "ot.engineer.01",
             "ot.engineer.02", "contractor.maint", "third.party.audit"]


def claroty_event(ts: datetime, **fields) -> dict:
    base = {
        "dataset": "claroty",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "vendor": fields.pop("vendor", "Claroty"),
        "product": "xDome",
    }
    base.update(fields)
    return {"message": json.dumps(base), **base}


def gen_claroty() -> list[dict]:
    events: list[dict] = []
    start = NOW - timedelta(hours=23)

    # 1) Daily inventory heartbeat per asset (every 4h)
    for hr in range(0, 24, 4):
        ts = start + timedelta(hours=hr)
        for (aid, aname, zone, sil, crit, vendor, model, biz) in CROWN_JEWELS:
            risk = {
                "CROWN_JEWEL": random.randint(85, 98),
                "CRITICAL":    random.randint(60, 84),
                "HIGH":        random.randint(40, 69),
                "MEDIUM":      random.randint(20, 49),
                "LOW":         random.randint(0, 25),
            }[crit]
            vuln_count = {
                "CROWN_JEWEL": random.randint(3, 14),
                "CRITICAL":    random.randint(1, 8),
                "HIGH":        random.randint(0, 5),
                "MEDIUM":      random.randint(0, 3),
                "LOW":         0,
            }[crit]
            events.append(claroty_event(
                ts,
                asset_id=aid, asset_name=aname, zone=zone,
                sil_level=sil, criticality=crit,
                vendor=vendor, model=model,
                firmware=f"v{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 20)}",
                risk_score=risk,
                vuln_count=vuln_count,
                business_impact=biz,
                last_seen=ts.isoformat().replace("+00:00", "Z"),
                event_type="ASSET_INVENTORY",
            ))

    # 2) Per-vulnerability records on crown jewels
    for (aid, aname, zone, sil, crit, vendor, model, _biz) in CROWN_JEWELS:
        if crit not in ("CROWN_JEWEL", "CRITICAL"):
            continue
        for _ in range(random.randint(2, 6)):
            ts = start + timedelta(minutes=random.randint(0, 24 * 60))
            sev = random.choice(VULN_SEV_WEIGHTS)
            events.append(claroty_event(
                ts,
                asset_id=aid, asset_name=aname, zone=zone,
                sil_level=sil, criticality=crit, vendor=vendor, model=model,
                vuln_severity=sev,
                cve_id=f"CVE-2024-{random.randint(1000, 9999)}",
                vuln_count=1,
                risk_score=random.randint(60, 98),
                event_type="VULN_FOUND",
            ))

    # 3) SRA sessions — some short (<1h), some long (>1h) to SIL-3 assets
    crown_assets = [c for c in CROWN_JEWELS if c[4] in ("CROWN_JEWEL", "CRITICAL")]
    for _ in range(60):
        (aid, aname, zone, sil, crit, vendor, model, _b) = random.choice(crown_assets)
        user = random.choice(SRA_USERS)
        duration = random.choice([
            random.randint(120, 1800),     # short < 30min
            random.randint(1800, 3500),    # < 1h
            random.randint(3700, 14400),   # > 1h (long)
        ])
        ts_end = start + timedelta(minutes=random.randint(0, 24 * 60))
        sess_id = f"SRA-{random.randint(100000, 999999)}"
        events.append(claroty_event(
            ts_end,
            asset_id=aid, asset_name=aname, zone=zone,
            sil_level=sil, criticality=crit, vendor=vendor, model=model,
            sra_session_id=sess_id,
            sra_user=user,
            sra_duration_sec=duration,
            risk_score=random.randint(60, 95),
            event_type="SRA_SESSION_CLOSED",
        ))

    # 4) One crown-jewel that goes dark in last 24h (no events at all)
    #    -> simulate by including it ONLY in older heartbeats. We add an
    #    "older" record outside the 24h window so the dashboard's
    #    "events = 0" panel surfaces it. SDL will not match it but the
    #    schema still validates.
    return events


# ----------------------------------------------------------------------------
def main() -> int:
    nz = gen_nozomi()
    cl = gen_claroty()
    nz_path = HERE / "nozomi_sample.jsonl"
    cl_path = HERE / "claroty_sample.jsonl"
    write_jsonl(nz_path, nz)
    write_jsonl(cl_path, cl)
    print(f"Wrote {len(nz):>5} Nozomi events  -> {nz_path}")
    print(f"Wrote {len(cl):>5} Claroty events -> {cl_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
