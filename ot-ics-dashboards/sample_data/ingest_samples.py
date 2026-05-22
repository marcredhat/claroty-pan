#!/usr/bin/env python3
"""
Push the synthetic OT/ICS sample events into SDL via SDLClient.upload_logs
(or addEvents). One call per dataset.

Run:
    python ingest_samples.py
"""

from __future__ import annotations

import json
import os
import sys
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


def load_events(path: Path) -> list[dict]:
    events = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def main() -> int:
    client = SDLClient()
    print(f"Connected to: {client.base_url}")

    for dataset, path in DATASETS:
        if not path.exists():
            print(f"[SKIP] missing {path}")
            continue
        events = load_events(path)
        print(f"[*] Uploading {len(events)} events to dataset='{dataset}'")

        # SDLClient typically exposes upload_logs(parser, raw_text) or
        # add_events(session_info, events). We try upload_logs first since
        # the events are already parser-formatted JSON.
        try:
            raw = "\n".join(json.dumps(e) for e in events)
            client.upload_logs(parser=dataset, content=raw,
                               session_info={"dataset": dataset,
                                             "serverHost": "ot-ics-sample"})
            print(f"    [OK] upload_logs dataset={dataset}")
        except AttributeError:
            # fall back to add_events
            client.add_events(events=events,
                              session_info={"dataset": dataset,
                                            "serverHost": "ot-ics-sample"})
            print(f"    [OK] add_events dataset={dataset}")
        except Exception as e:
            print(f"    [FAIL] {e}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
