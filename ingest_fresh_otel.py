#!/usr/bin/env python3
"""
Ingest Nozomi + Claroty fresh data as OpenTelemetry logs via grpcurl.

Usage:
    # 1) Quickest path - just pass the SentinelOne Data Pipelines endpoint:
    python3 ingest_fresh_otel.py --oteldest your-tenant.observo.ai:10020

    # 2) With a bearer token and/or extra headers (-H repeatable):
    python3 ingest_fresh_otel.py \
        --oteldest your-tenant.observo.ai:10020 \
        -H 'authorization: Bearer REPLACE_ME'

    # 3) Read everything (endpoint, headers, batch_size, ...) from a config:
    python3 ingest_fresh_otel.py --config config.json

`--oteldest` always wins over `otel.endpoint` from the config file.

Optional config (default: ./config.json, ignored if missing and --oteldest
is provided) may contain an `otel` block, e.g.:

    "otel": {
        "endpoint":          "your-tenant.observo.ai:10020",
        "headers":           {"authorization": "Bearer REPLACE_ME"},
        "service_name":      "claroty-pan-otel",
        "plaintext":         false,
        "insecure":          false,
        "proto_import_path": "/tmp/otlp",
        "batch_size":        100
    }

If `proto_import_path` does not exist this script will shallow-clone
https://github.com/open-telemetry/opentelemetry-proto into it.

Data sources (re-timed to "now" so they fall in standard dashboard windows):
  1. ot-ics-dashboards/sample_data/nozomi_sample.jsonl   (dataset=nozomi)
  2. ot-ics-dashboards/sample_data/claroty_sample.jsonl  (dataset=claroty)
  3. data/claroty_assets.csv                             (Claroty inventory)

Each event is sent as a single OTLP logRecord. Multiple records are
batched per Export call to keep the number of grpcurl invocations down.

No SentinelOne secrets are read from the config; only the `otel` block
is required. The script is safe to publish: it does not embed any
real endpoint, token, or tenant identifier.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parent

OTLP_PROTO_REPO = "https://github.com/open-telemetry/opentelemetry-proto"
LOGS_PROTO = "opentelemetry/proto/collector/logs/v1/logs_service.proto"
LOGS_METHOD = "opentelemetry.proto.collector.logs.v1.LogsService/Export"

# OTLP SeverityNumber mapping (see logs.proto)
SEV_MAP = {
    "TRACE":    1,
    "DEBUG":    5,
    "INFO":     9,
    "NOTICE":   10,
    "WARN":     13,
    "WARNING":  13,
    "ERROR":    17,
    "CRITICAL": 21,
    "FATAL":    21,
}


# --------------------------------------------------------------- helpers ---
def die(msg: str, code: int = 1) -> None:
    sys.stderr.write(f"[ingest_fresh_otel] ERROR: {msg}\n")
    sys.exit(code)


def load_config(path: Path, *, required: bool) -> Dict[str, Any]:
    """Load the `otel` block from a config file.

    If `required` is False and the file is missing, return an empty dict
    so CLI flags can fully drive the run.
    """
    if not path.exists():
        if required:
            die(f"config not found: {path}")
        return {}
    try:
        cfg = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        die(f"config is not valid JSON: {e}")
    return dict(cfg.get("otel") or {})


def parse_header_args(values: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in values or []:
        if ":" not in raw:
            die(f"invalid -H value (expected 'Key: Value'): {raw!r}")
        k, v = raw.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def apply_defaults(otel: Dict[str, Any]) -> Dict[str, Any]:
    if not otel.get("endpoint"):
        die(
            "missing OTLP endpoint - pass --oteldest HOST:PORT "
            "or set otel.endpoint in the config file"
        )
    otel.setdefault("headers", {})
    otel.setdefault("service_name", "claroty-pan-otel")
    otel.setdefault("plaintext", False)
    otel.setdefault("insecure", False)
    otel.setdefault("proto_import_path", "/tmp/otlp")
    otel.setdefault("batch_size", 100)
    return otel


def ensure_proto(import_path: str) -> Path:
    p = Path(import_path)
    proto_file = p / LOGS_PROTO
    if proto_file.exists():
        return p
    print(f"[+] OTLP proto not found at {p} - shallow-cloning...")
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        shutil.rmtree(p)
    subprocess.run(
        ["git", "clone", "--depth", "1", OTLP_PROTO_REPO, str(p)],
        check=True,
    )
    if not proto_file.exists():
        die(f"clone succeeded but {proto_file} is missing")
    return p


def ensure_grpcurl() -> None:
    if shutil.which("grpcurl") is None:
        die(
            "`grpcurl` is not installed or not on PATH. "
            "Install from https://github.com/fullstorydev/grpcurl"
        )


def iso_to_ns(iso: str) -> int:
    iso = iso.replace("Z", "+00:00")
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def chunked(lst: List[Any], n: int) -> Iterable[List[Any]]:
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# -------------------------------------------- OTLP payload construction ---
def _otel_attr(key: str, value: Any) -> Dict[str, Any]:
    """Convert a python value into an OTLP KeyValue."""
    if isinstance(value, bool):
        v = {"boolValue": value}
    elif isinstance(value, int):
        v = {"intValue": str(value)}
    elif isinstance(value, float):
        v = {"doubleValue": value}
    elif value is None:
        v = {"stringValue": ""}
    else:
        v = {"stringValue": str(value)}
    return {"key": key, "value": v}


def _log_record(ts_ns: int, severity: str, body: str,
                attrs: Dict[str, Any]) -> Dict[str, Any]:
    sev = severity.upper() if isinstance(severity, str) else "INFO"
    return {
        "timeUnixNano":   str(ts_ns),
        "severityNumber": SEV_MAP.get(sev, 9),
        "severityText":   sev,
        "body":           {"stringValue": body},
        "attributes":     [_otel_attr(k, v) for k, v in attrs.items()
                           if v is not None and v != ""],
    }


def _resource_logs(service_name: str, dataset: str,
                   records: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "resourceLogs": [{
            "resource": {
                "attributes": [
                    _otel_attr("service.name", service_name),
                    _otel_attr("dataset",      dataset),
                ],
            },
            "scopeLogs": [{
                "scope":      {"name": f"claroty-pan/{dataset}"},
                "logRecords": records,
            }],
        }],
    }


# ------------------------------------------------------- grpcurl invoke ---
def grpcurl_export(otel: Dict[str, Any], proto_root: Path,
                   payload: Dict[str, Any]) -> None:
    cmd: List[str] = [
        "grpcurl",
        "-import-path", str(proto_root),
        "-proto", LOGS_PROTO,
    ]
    if otel.get("plaintext"):
        cmd.append("-plaintext")
    if otel.get("insecure"):
        cmd.append("-insecure")
    for k, v in (otel.get("headers") or {}).items():
        cmd.extend(["-H", f"{k}: {v}"])
    cmd.extend(["-d", "@", otel["endpoint"], LOGS_METHOD])

    proc = subprocess.run(
        cmd,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        die(f"grpcurl exited {proc.returncode}")
    if proc.stdout.strip():
        # Successful Export usually returns "{}"
        print(f"      grpcurl: {proc.stdout.strip()[:120]}")


# ------------------------------------------------------- data shaping  ---
def load_jsonl_dataset(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        print(f"  [SKIP] {path} missing")
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def retime(events: List[Dict[str, Any]], now_ns: int) -> List[int]:
    """Return per-event ns timestamps shifted so the newest event = now_ns."""
    ts_ns_list: List[int] = []
    for e in events:
        try:
            ts_ns_list.append(iso_to_ns(e["timestamp"]))
        except Exception:
            ts_ns_list.append(now_ns)
    if not ts_ns_list:
        return ts_ns_list
    shift = now_ns - max(ts_ns_list)
    return [t + shift for t in ts_ns_list]


def build_nozomi(now_ns: int) -> List[Dict[str, Any]]:
    raw = load_jsonl_dataset(ROOT / "ot-ics-dashboards" / "sample_data"
                             / "nozomi_sample.jsonl")
    times = retime(raw, now_ns)
    records: List[Dict[str, Any]] = []
    for ts_ns, e in zip(times, raw):
        attrs = {k: v for k, v in e.items()
                 if k not in ("timestamp", "message", "severity")}
        attrs["dataset"]    = "nozomi"
        attrs["serverHost"] = "ot-ics-sample-nozomi"
        body = e.get("message") or (
            f"Nozomi {attrs.get('alert_type', 'event')} "
            f"{attrs.get('src_ip', '')} -> {attrs.get('dst_ip', '')} "
            f"({attrs.get('protocol', '')})"
        )
        records.append(_log_record(ts_ns, e.get("severity", "INFO"),
                                   body, attrs))
    return records


def build_claroty(now_ns: int) -> List[Dict[str, Any]]:
    raw = load_jsonl_dataset(ROOT / "ot-ics-dashboards" / "sample_data"
                             / "claroty_sample.jsonl")
    times = retime(raw, now_ns)
    records: List[Dict[str, Any]] = []
    for ts_ns, e in zip(times, raw):
        attrs = {k: v for k, v in e.items()
                 if k not in ("timestamp", "message", "severity")}
        attrs["dataset"]    = "claroty"
        attrs["serverHost"] = "ot-ics-sample-claroty"
        body = e.get("message") or (
            f"Claroty xDome {attrs.get('event_type', 'event')} "
            f"asset={attrs.get('asset_name', '')} "
            f"risk={attrs.get('risk_score', '')}"
        )
        records.append(_log_record(ts_ns, e.get("severity", "INFO"),
                                   body, attrs))
    return records


def build_claroty_inventory(now_ns: int) -> List[Dict[str, Any]]:
    path = ROOT / "data" / "claroty_assets.csv"
    if not path.exists():
        print(f"  [SKIP] {path} missing")
        return []
    records: List[Dict[str, Any]] = []
    with path.open() as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            ts_ns = now_ns + i * 1_000_000
            attrs = {
                "dataSource.name":       "Claroty",
                "dataSource.vendor":     "Claroty",
                "dataSource.category":   "asset_inventory",
                "event.type":            "inventory",
                "dataset":               "claroty_inventory",
                "serverHost":            "claroty-inventory",
                **{k: row.get(k) for k in (
                    "ip", "mac", "hostname", "site", "zone",
                    "device_type", "vendor", "model", "criticality",
                    "claroty_risk", "approved_policy_group",
                    "expected_edl", "expected_dag",
                )},
            }
            body = f"Claroty inventory: {row.get('hostname', '')}"
            records.append(_log_record(ts_ns, "INFO", body, attrs))
    return records


# -------------------------------------------------------- send pipeline ---
def send_dataset(otel: Dict[str, Any], proto_root: Path, dataset: str,
                 records: List[Dict[str, Any]]) -> None:
    if not records:
        print(f"  [SKIP] {dataset}: no records")
        return
    session = f"{dataset}-{uuid.uuid4().hex[:8]}"
    print(f"\n  [*] dataset={dataset}  records={len(records)}  "
          f"session={session}")
    batch_size = int(otel.get("batch_size", 100))
    for i, batch in enumerate(chunked(records, batch_size), 1):
        payload = _resource_logs(otel["service_name"], dataset, batch)
        print(f"      batch {i:>3}: {len(batch):>4} records -> "
              f"{otel['endpoint']}")
        grpcurl_export(otel, proto_root, payload)


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ingest_fresh_otel.py",
        description=(
            "Send Nozomi + Claroty sample data to a SentinelOne Data "
            "Pipelines (OTLP/gRPC) endpoint via grpcurl."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--oteldest",
        metavar="HOST:PORT",
        help="SentinelOne Data Pipelines OTLP/gRPC endpoint "
             "(overrides otel.endpoint in the config file).",
    )
    p.add_argument(
        "--config",
        default=str(ROOT / "config.json"),
        metavar="PATH",
        help="Path to config.json (default: ./config.json). "
             "Ignored if missing and --oteldest is provided.",
    )
    p.add_argument(
        "-H", "--header",
        action="append",
        metavar="'Key: Value'",
        help="Extra gRPC metadata header (repeatable). Merged on top of "
             "otel.headers from the config.",
    )
    p.add_argument(
        "--service-name",
        help="Override otel.service_name (resource attribute service.name).",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        help="Override otel.batch_size (log records per Export call).",
    )
    p.add_argument(
        "--plaintext",
        action="store_true",
        help="Use plaintext gRPC (no TLS).",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Use TLS but skip certificate verification.",
    )
    p.add_argument(
        "--proto-import-path",
        help="Directory holding opentelemetry-proto checkout "
             "(default: /tmp/otlp; auto-cloned if missing).",
    )
    p.add_argument(
        "config_positional",
        nargs="?",
        help=argparse.SUPPRESS,  # backward-compat: positional config path
    )
    return p


def resolve_otel(args: argparse.Namespace) -> Dict[str, Any]:
    cfg_path_str = args.config_positional or args.config
    cfg_path = Path(cfg_path_str)
    # Config is required only if --oteldest is NOT given.
    otel = load_config(cfg_path, required=not bool(args.oteldest))

    if args.oteldest:
        otel["endpoint"] = args.oteldest
    if args.service_name:
        otel["service_name"] = args.service_name
    if args.batch_size is not None:
        otel["batch_size"] = args.batch_size
    if args.plaintext:
        otel["plaintext"] = True
    if args.insecure:
        otel["insecure"] = True
    if args.proto_import_path:
        otel["proto_import_path"] = args.proto_import_path

    merged_headers = dict(otel.get("headers") or {})
    merged_headers.update(parse_header_args(args.header))
    otel["headers"] = merged_headers

    print(f"[+] using config: {cfg_path}"
          f"{'' if cfg_path.exists() else ' (not found, CLI-only run)'}")
    return apply_defaults(otel)


def main(argv: List[str]) -> int:
    args = build_argparser().parse_args(argv[1:])

    otel = resolve_otel(args)
    ensure_grpcurl()
    proto_root = ensure_proto(otel["proto_import_path"])
    print(f"[+] OTLP proto path: {proto_root}")
    print(f"[+] OTLP endpoint:   {otel['endpoint']}")
    print(f"[+] service.name:    {otel['service_name']}")
    print(f"[+] headers:         {sorted(otel['headers'].keys()) or '(none)'}")

    now_ns = int(time.time() * 1_000_000_000)

    print("\n" + "=" * 78)
    print("STEP 1 - Nozomi Guardian sample events")
    print("=" * 78)
    send_dataset(otel, proto_root, "nozomi", build_nozomi(now_ns))

    print("\n" + "=" * 78)
    print("STEP 2 - Claroty xDome sample events")
    print("=" * 78)
    send_dataset(otel, proto_root, "claroty", build_claroty(now_ns))

    print("\n" + "=" * 78)
    print("STEP 3 - Claroty inventory (data/claroty_assets.csv)")
    print("=" * 78)
    send_dataset(otel, proto_root, "claroty_inventory",
                 build_claroty_inventory(now_ns))

    print("\n" + "=" * 78)
    print("DONE - all Nozomi + Claroty data exported via OTLP/gRPC")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
