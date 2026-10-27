"""
Train the offline code-likeness models from BENIGN PE files (run in the lab VM).

    python -m malworn.packing.train_codeness --benign-dir <folder of benign PEs>

Writes models/codeness_x86_32.json and/or codeness_x86_64.json next to this
package (or into --out). Use ONLY benign, unpacked files (for example Windows
system files and clean installers' payloads). Packed samples in the training set
would teach the model that packed data looks like code.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

import pefile

from malworn.packing import structure as st


def exec_bytes(pe: pefile.PE) -> bytes:
    return b"".join(s.get_data() for s in pe.sections if s.Characteristics & 0x20000000)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-dir", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=st.model_dir())
    ap.add_argument("--max-windows-per-file", type=int, default=60)
    ap.add_argument("--fpr", type=float, default=0.05, help="benign window false-positive target")
    a = ap.parse_args()

    blobs: Dict[int, List[bytes]] = {32: [], 64: []}
    for p in sorted(a.benign_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            pe = pefile.PE(str(p), fast_load=True)
            bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
            code = exec_bytes(pe)[: a.max_windows_per_file * st.WINDOW]
            if len(code) >= st.WINDOW:
                blobs[bits].append(code)
        except Exception:  # noqa: BLE001
            continue
    for bits, bl in blobs.items():
        if len(bl) < 5:
            print(f"{bits}-bit: only {len(bl)} files, skipped (need >= 5)")
            continue
        model = st.train(bl, bits, a.fpr)
        st.save(model, a.out / f"codeness_x86_{bits}.json")
        print(f"{bits}-bit: trained on {len(bl)} files, {model.meta['windows']} windows, "
              f"threshold {model.threshold:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
