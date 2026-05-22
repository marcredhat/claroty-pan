#!/usr/bin/env python3
"""
Ingest the synthetic OT/ICS sample events into SDL via SDLClient.add_events.

One session per dataset. Each event keeps its original JSON in the 'message'
attribute (so the dashboards' '| parse "...$field..." from message' panels
populate) and ALSO promotes the most commonly queried fields as top-level
attributes (so panels that filter on dataset/zone/etc. work regardless of
parser).

Run:
    python ingest_samples.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent

# locate SDLClient (override with SDL_CLIENT_PATH if needed)
_default = Path.home() / "windsurf/shared/sentinelone-sdl-api/scripts"
SDL_CLIENT_PATH = Path(os.environ.get("SDL_CLIENT_PATH", _default))
if SDL_CLIENT_PATH.exists():
    sys.path.insert(0, str(SDL_CLIENT_PATH))

from sdl_client import SDLClient  # type: ignore  # noqa: E402


DATASETS = [
    ("nozomi",  HERE / "nozomi_sample.jsonl"),
    ("claroty", HERE / "claroty_sample.jsonl"),
]


SEV_MAP = {
    "INFO":     2,
    "LOW":      3,
    "MEDIUM":   4,
    "HIGH":     5,
    "CRITICAL": 6,
}


def load_events(path: Path) -> list[dict]:
    out: list[dict] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def iso_to_ns(iso: str) -> int:
    iso = iso.replace("Z", "+00:00")
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def to_addevents_form(events: list[dict], dataset: str) -> list[dict]:
    """
    Convert raw events (dicts with a 'message' JSON string and top-level
    attributes) into the addEvents wire format.
    """
    out: list[dict] = []
    now_ns = SDLClient.now_ns()
    for e in events:
        ts_iso = e.get("timestamp")
        try:
            ts_ns = iso_to_ns(ts_iso) if ts_iso else now_ns
        except Exception:
            ts_ns = now_ns
        sev_label = e.get("severity", "INFO")
        sev = SEV_MAP.get(sev_label, 2)

        # Build the flat attrs dict. Keep everything that's not 'message' or
        # 'timestamp', and keep 'message' (it's used by the dashboard parses).
        attrs = {k: v for k, v in e.items()
                 if k not in ("timestamp",) and v is not None}
        # Make sure dataset is set
        attrs["dataset"] = dataset

        out.append({"ts": ts_ns, "sev": sev, "attrs": attrs})
    return out


def chunked(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def main() -> int:
    client = SDLClient()
    print(f"Connected to: {client.base_url}")

    total_ok = True
    for dataset, path in DATASETS:
        if not path.exists():
            print(f"[SKIP] missing {path}")
            continue

        events = load_events(path)
        wire = to_addevents_form(events, dataset)
        print(f"\n[*] Ingesting {len(wire)} events  dataset={dataset}")

        session = SDLClient.new_session_id()
        session_info = {
            "serverHost": f"ot-ics-sample-{dataset}",
            "parser":     dataset,           # routes to dataset=<name>
            "dataset":    dataset,
            "source":     "ot-ics-dashboards/sample_data",
        }

        # addEvents has a body-size limit (~6 MB). 500-event chunks are safe.
        total_bytes = 0
        for i, chunk in enumerate(chunked(wire, 500), 1):
            try:
                res = client.add_events(
                    session=session,
                    events=chunk,
                    session_info=session_info,
                )
                total_bytes += int(res.get("bytesCharged", 0) or 0)
                print(f"    chunk {i:>2}: {len(chunk):>4} events  "
                      f"status={res.get('status')}  "
                      f"bytes={res.get('bytesCharged')}")
            except Exception as exc:
                print(f"    chunk {i:>2}: [FAIL] {exc}")
                total_ok = False
                break
        print(f"    total bytesCharged: {total_bytes}")

    print("\n" + "=" * 60)
    print("Done." if total_ok else "Done WITH ERRORS.")
    print("View dashboards: https://<your-xdr-host>/#/dashboards")
    return 0 if total_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
