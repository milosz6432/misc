#!/usr/bin/env python3
"""Load a sample investigation into a running HunterIntel API (standard library only).

    python scripts/load_sample.py samples/01-getting-started.json
    python scripts/load_sample.py samples/01-getting-started.json --enrich
    python scripts/load_sample.py samples/02-eicar-test-file.json --enrich --providers local,virustotal --yes

Creating the investigation and adding indicators makes NO outbound requests. Enrichment only
happens with --enrich, and any provider that sends data to a third party (or touches a target)
additionally requires --yes after the plan has been printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


def call(api: str, token: str | None, method: str, path: str, body: Any = None) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"{api}/api/v1{path}", data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - user-supplied API base
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        sys.exit(f"API error {exc.code} on {method} {path}: {detail}")
    except urllib.error.URLError as exc:
        sys.exit(f"cannot reach {api}: {exc.reason}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sample", help="path to a samples/*.json file")
    ap.add_argument("--api", default=os.environ.get("HUNTERINTEL_API", "http://127.0.0.1:8000"))
    ap.add_argument("--token", default=os.environ.get("HUNTERINTEL_API_TOKEN"))
    ap.add_argument("--enrich", action="store_true", help="run enrichment (outbound requests!)")
    ap.add_argument("--providers", help="comma-separated provider names (default: the sample's suggestion)")
    ap.add_argument("--yes", action="store_true", help="allow third-party / active providers")
    args = ap.parse_args()

    with open(args.sample, encoding="utf-8") as fh:
        sample = json.load(fh)
    wanted = [p for p in (args.providers.split(",") if args.providers else sample.get("suggested_providers", [])) if p]

    inv = call(args.api, args.token, "POST", "/investigations",
               {"title": sample["title"], "description": sample.get("description", ""), "tlp": sample.get("tlp", "amber")})
    print(f"created investigation #{inv['id']}: {inv['title']}  (TLP:{inv['tlp']})")

    for item in sample["indicators"]:
        # classify is local-only (no egress) and tells us the canonical value the server will store
        canonical = call(args.api, args.token, "POST", "/indicators/classify", {"value": item["value"]})["indicator"]["value"]
        detail = call(args.api, args.token, "POST", f"/investigations/{inv['id']}/indicators", {"value": item["value"]})
        member = next(i for i in detail["indicators"] if i["value"] == canonical)
        if item.get("note"):
            call(args.api, args.token, "POST", f"/investigations/{inv['id']}/notes",
                 {"body": item["note"], "indicator_id": member["id"], "author": "sample"})
        print(f"  + {member['type']:11} {member['value']}")
    for note in sample.get("notes", []):
        call(args.api, args.token, "POST", f"/investigations/{inv['id']}/notes", {"body": note, "author": "sample"})

    if not args.enrich:
        print("\nNo enrichment was run, so nothing was sent anywhere. Re-run with --enrich to collect evidence.")
        print(f"Open: {args.api.replace(':8000', ':8080') if ':8000' in args.api else args.api}/investigations/{inv['id']}")
        return

    print("\nQuery plan:")
    for item in sample["indicators"]:
        classified = call(args.api, args.token, "POST", "/indicators/classify", {"value": item["value"]})
        plan = {p["provider"]: p for p in classified["plan"]}
        chosen = [n for n in wanted if n in plan and plan[n]["state"] == "available"]
        skipped = [(n, plan[n]["state"]) for n in wanted if n in plan and plan[n]["state"] != "available"]
        risky = [n for n in chosen if plan[n]["tier"] in ("third_party", "active")]
        print(f"- {classified['indicator']['value']}")
        for n in chosen:
            print(f"    will run  {n:14} [{plan[n]['tier']}] {plan[n]['data_shared']}")
        for n, state in skipped:
            print(f"    skipped   {n:14} ({state})")
        if risky and not args.yes:
            sys.exit(f"\nRefusing to send data to {', '.join(risky)} without --yes. Nothing was enriched.")
        result = call(args.api, args.token, "POST", "/enrich",
                      {"value": item["value"], "providers": chosen or ["local"]})
        ind = result["indicator"]
        print(f"    => #{ind['id']} verdict={ind['assessment']['verdict']} "
              + ", ".join(f"{r['provider']}:{r['status']}" for r in result["runs"]))
    print(f"\nDone. Investigation #{inv['id']} is ready in the UI.")


if __name__ == "__main__":
    main()
