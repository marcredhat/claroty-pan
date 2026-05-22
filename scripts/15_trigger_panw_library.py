#!/usr/bin/env python3
"""Trigger the 7 existing PANW Library detection rules by ingesting events
matching each rule's s1ql filter (librarydetections-style)."""
from __future__ import annotations
import json, time
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parent.parent
sdl  = json.loads((ROOT / "config.json").read_text())
SDL_BASE  = sdl["base_url"].rstrip("/")
SDL_TOKEN = sdl["log_write_key"]
SERVER_HOST = "pan-library-trigger"
SESSION = int(time.time())

# (rule_name, attrs)
TRIGGERS = [
    ("PANW Firewall High Severity Correlation Event Detected", {
        "metadata.log_name": "CORRELATION",
        "unmapped.severity": "high",
        "message":           "Correlation: multiple high-severity events from 10.30.50.51",
        "src.ip.address":    "10.30.50.51",
    }),
    ("PANW Firewall Malware Allowed", {
        "metadata.log_name":   "THREAT",
        "unmapped.sub_type":   "virus",
        "unmapped.action":     "alert",
        "action":              "allow",
        "unmapped.threat_name":"Trojan.Win32.Demo",
        "src.ip.address":      "10.20.20.21",
    }),
    ("PANW Firewall Medium Severity Correlation Event Detected", {
        "metadata.log_name": "CORRELATION",
        "unmapped.severity": "medium",
        "message":           "Correlation: medium severity grouped events on plant-b",
        "src.ip.address":    "10.30.10.11",
    }),
    ("PANW Firewall TOR Traffic Allowed", {
        "metadata.log_name": "TRAFFIC",
        "app_name":          "tor",
        "unmapped.action":   "allow",
        "src.ip.address":    "10.20.30.31",
        "dst.ip.address":    "185.220.101.5",
    }),
    ("PANW Firewall Traffic to Malicious URL Allowed", {
        "metadata.log_name":         "THREAT",
        "unmapped.sub_type":         "url",
        "unmapped.url_category":     "malware",
        "unmapped.threat_category":  "malware",
        "unmapped.severity":         "high",
        "unmapped.action":           "alert",
        "action":                    "allow",
        "unmapped.url":              "http://evil-c2-demo.example/payload",
        "src.ip.address":            "10.30.50.51",
    }),
    ("PANW Firewall Traffic to Phishing URL Allowed", {
        "metadata.log_name":         "THREAT",
        "unmapped.sub_type":         "url",
        "unmapped.url_category":     "malware",      # query checks 'malware'
        "unmapped.threat_category":  "malware",
        "unmapped.severity":         "medium",
        "unmapped.action":           "alert",
        "action":                    "allow",
        "unmapped.url":              "https://phish-demo.example/login",
        "src.ip.address":            "10.30.50.51",
    }),
    ("PANW Firewall Unauthorized Config Change", {
        "unmapped.type":    "CONFIG",
        "unmapped.result":  "Unauthorized",
        "unmapped.admin":   "demo-attacker",
        "src.ip.address":   "10.20.99.99",
    }),
]

base_attrs = {
    "dataSource.name":     "Palo Alto Networks Firewall",
    "dataSource.vendor":   "Palo Alto Networks",
    "dataSource.category": "security",
    "serverHost":          SERVER_HOST,
    "session_id":          str(SESSION),
}

events = []
for i, (name, attrs) in enumerate(TRIGGERS):
    a = dict(base_attrs)
    a.update(attrs)
    a["library_rule"] = name
    events.append({
        "ts":    int((time.time() - 60 + i) * 1_000_000_000),
        "sev":   3,
        "attrs": a,
    })

batch = {"token": SDL_TOKEN, "session": f"panw-library-{SESSION}", "events": events}
r = requests.post(f"{SDL_BASE}/api/addEvents", json=batch, timeout=60)
print(f"[+] addEvents -> {r.status_code} {r.text[:200]}")
print(f"[+] ingested {len(events)} PANW trigger events to serverHost={SERVER_HOST}")
print("[+] Library rules evaluate every ~5 min. Watch Detect -> Findings (engine = Library).")
