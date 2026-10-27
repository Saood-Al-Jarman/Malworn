"""
malworn.packing.batch_detect  -  run packing DETECTION over a folder of samples.

Detect-only and fully OFFLINE: nothing is unpacked, nothing is executed, no network. Purpose: produce the
numbers for your evaluation (detection rate, false-positive rate, runtime).

Typical use, with one folder per known ground truth:
    python -m malworn.packing.batch_detect --samples data/self_packed --out out/packed.csv --truth packed
    python -m malworn.packing.batch_detect --samples data/clean       --out out/clean.csv  --truth clean

Run it only inside the isolated lab VM. Keep --out OUTSIDE the git repo or in
data/ (ignored by git); results contain sample hashes and paths.

AI-assistance note (team norm): first draft generated with Claude (Anthropic).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

from malworn.packing import indicators as ind

FIELDS = ["sha256", "file", "status", "level", "needs_unpacking", "packed_sections",
          "suspected_packers", "top_reasons", "seconds"]


def sha256_file(path: Path) -> str:
    """Hash in 1 MB chunks so large files never have to fit in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_one(path_str: str) -> Dict[str, Any]:
    """Analyze ONE file. Must never raise: a crash becomes an 'error' row so a
    single malformed sample cannot stop a long run. Top-level function with
    simple arguments so multiprocessing can pickle it."""
    t0 = time.time()
    p = Path(path_str)
    row: Dict[str, Any] = {"sha256": "", "file": p.name, "status": "", "level": "",
                           "needs_unpacking": "", "packed_sections": "", "suspected_packers": "",
                           "top_reasons": "", "seconds": 0}
    try:
        row["sha256"] = sha256_file(p)
        r = ind.analyze(str(p))
        if "error" in r:
            row["status"] = r["error"]
        else:
            row["status"] = "ok"
            row["level"] = r["packing_indicators_level"]
            row["needs_unpacking"] = r["needs_unpacking"]
            row["packed_sections"] = ";".join(f"{s['name']}:{s['level']}" for s in r["packed_sections"])
            row["suspected_packers"] = ";".join(sp["packer"] for sp in r["suspected_packers"])
            highs = [i["id"] for i in r["indicators"] if i["severity"] == "high"]
            row["top_reasons"] = ";".join(sorted(set(highs)))
    except Exception as e:  # noqa: BLE001  (deliberate: see docstring)
        row["status"] = f"error:{type(e).__name__}"
    row["seconds"] = round(time.time() - t0, 3)
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description="Batch packing detection (detect-only)")
    ap.add_argument("--samples", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="CSV file to write")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--truth", choices=["packed", "clean"], default=None,
                    help="if the whole folder has one known label, print detection stats against it")
    args = ap.parse_args()

    files: List[Path] = sorted(p for p in args.samples.rglob("*") if p.is_file() and not p.is_symlink())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []

    with open(args.out, "w", newline="", encoding="utf-8") as fc, \
         ProcessPoolExecutor(max_workers=args.workers) as pool:
        w = csv.DictWriter(fc, fieldnames=FIELDS)
        w.writeheader()
        # as_completed yields each result as soon as it finishes, so rows are
        # written immediately and an interrupted run keeps what it has.
        for fut in as_completed([pool.submit(detect_one, str(p)) for p in files]):
            row = fut.result()
            w.writerow(row)
            fc.flush()
            rows.append(row)

    ok = [r for r in rows if r["status"] == "ok"]
    flagged = [r for r in ok if r["needs_unpacking"] is True]
    print(f"{len(rows)} files, {len(ok)} analyzed, {len(rows) - len(ok)} skipped/errors, "
          f"{len(flagged)} flagged as packed")
    if args.truth and ok:
        if args.truth == "packed":
            print(f"Detection rate (recall): {len(flagged) / len(ok):.3f}")
        else:
            print(f"False-positive rate: {len(flagged) / len(ok):.3f}")
    if ok:
        print(f"Mean time per file: {sum(r['seconds'] for r in ok) / len(ok):.3f}s")
    print(f"Results: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
