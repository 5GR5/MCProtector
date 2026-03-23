from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .events import PoCEvent


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter PoC observability logs by trace ID.")
    parser.add_argument("--trace", required=True, help="Trace ID to filter for.")
    parser.add_argument("--file", default="logs/poc.jsonl", help="Path to the JSONL log file.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    path = Path(args.file)
    if not path.exists():
        print(f"Log file not found: {path}", file=sys.stderr)
        return 1

    events: list[PoCEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                event = PoCEvent.model_validate(payload)
            except Exception as exc:
                print(f"Skipping invalid event on line {line_number}: {exc}", file=sys.stderr)
                continue
            if str(event.trace_id) == args.trace:
                events.append(event)

    events.sort(key=lambda event: event.timestamp)
    for event in events:
        print(event.model_dump_json(exclude_none=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
