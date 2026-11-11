"""Sub-objective O2: is each tool's output correct?

Owner: Saood

Runs the static tools on every sample and compares each tool's output with an
independent reference:

  hashes          sha256sum / md5sum / sha1sum (the system programs)
  file_type       the MZ and PE signatures read straight from the header bytes
  sections        section table parsed from the raw header with struct, entropy
                  computed here (names, addresses, sizes, entropy within 0.01)
  imports         pefile (DLL names compared case-insensitively, function sets)
  strings         a separate regex over the raw bytes (recall and precision)
  extra_checks    pefile imphash; overlay from the raw section table
  version_info    pefile's version resource and security directory
  packer_signatures / packing_indicators
                  Detect It Easy (diec) when it is installed: the packer DIE
                  names must be reported by packer_signatures. Skipped when
                  diec is missing (the report says so).

The tools use pefile too, so imports, imphash and version_info are only a
check that the tool wraps pefile correctly; the hashes, file type, sections,
overlay and strings references do not depend on pefile. Detect It Easy is the
one independent opinion on packing.

A mismatch is reported, not hidden: open the sample and decide whether the tool
or the reference is wrong. VirusTotal is not covered (it is a lookup, not a
computation).

Usage (inside the VM; files and/or folders):

    PYTHONPATH=src python3 -m malworn.agent.evaluate_tools ~/demo-files
    PYTHONPATH=src python3 -m malworn.agent.evaluate_tools ~/samples --out ~/outbox

Output: runs/tools_eval_<time>/summary.md and results.json. Only these two
files are meant to leave the VM. Nothing here executes a sample.
"""

import argparse
import hashlib
import json
import math
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from malworn.agent.tools import load_tools
from malworn.contract import run_tool

CHECKED_TOOLS = ("hashes", "file_type", "sections", "imports", "strings",
                 "extra_checks", "version_info", "packer_signatures")
PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".bin", ""}
ENTROPY_TOLERANCE = 0.011
MIN_STRING = 4


# --- references --------------------------------------------------------------
def system_hashes(path):
    """MD5, SHA-1 and SHA-256 from the system's coreutils programs."""
    out = {}
    for key, prog in (("md5", "md5sum"), ("sha1", "sha1sum"), ("sha256", "sha256sum")):
        if shutil.which(prog) is None:
            return None
        text = subprocess.run([prog, str(path)], capture_output=True, text=True, check=True).stdout
        out[key] = text.split()[0].lower()
    return out


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def raw_pe(data):
    """Parse the PE header and section table with struct. Returns None if the
    file has no valid MZ + PE signature."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    n_sections, = struct.unpack_from("<H", data, e_lfanew + 6)
    opt_size, = struct.unpack_from("<H", data, e_lfanew + 20)
    table = e_lfanew + 24 + opt_size
    sections = []
    for i in range(n_sections):
        off = table + 40 * i
        if off + 40 > len(data):
            break
        name = data[off:off + 8].split(b"\0")[0].decode("latin-1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"name": name, "virtual_address": vaddr, "virtual_size": vsize,
                         "raw_size": rawsize, "raw_pointer": rawptr,
                         "entropy": entropy(data[rawptr:rawptr + rawsize])})
    return {"sections": sections}


def reference_strings(data):
    ascii_found = set(m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{%d,}" % MIN_STRING, data))
    wide_found = set(m.decode("utf-16-le") for m in re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING, data))
    return ascii_found | wide_found


def pefile_reference(path):
    import pefile
    pe = pefile.PE(str(path), fast_load=False)
    try:
        imports = {}
        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in getattr(pe, attr, []) or []:
                dll = entry.dll.decode("latin-1").lower()
                funcs = imports.setdefault(dll, set())
                for imp in entry.imports:
                    funcs.add(imp.name.decode("latin-1") if imp.name else f"ord{imp.ordinal}")
        version = {}
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for table in getattr(entry, "StringTable", []) or []:
                    for k, v in table.entries.items():
                        version[k.decode("latin-1")] = v.decode("latin-1")
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        return {"imports": imports, "imphash": pe.get_imphash() or None,
                "version": version, "has_signature": sec.Size > 0}
    finally:
        pe.close()


def run_die(path):
    """Packers named by Detect It Easy, or None when diec isn't installed."""
    exe = shutil.which("diec")
    if exe is None:
        return None
    try:
        text = subprocess.run([exe, "--json", str(path)], capture_output=True, text=True,
                              timeout=60).stdout
        doc = json.loads(text)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return None
    names = set()
    for det in doc.get("detects", []):
        for v in det.get("values", []):
            if str(v.get("type", "")).lower() in ("packer", "protector"):
                names.add(str(v.get("name", "")).lower())
    return names


# --- comparisons: each returns a list of (check, passed, detail) -------------
def compare_hashes(data, ref):
    if ref is None:
        return [("hashes", None, "md5sum/sha1sum/sha256sum not available")]
    return [(f"hash {k}", data.get(k) == v, f"{data.get(k)} vs {v}") for k, v in ref.items()]


def compare_file_type(data, raw):
    says_pe = bool(re.search(r"\bPE\b", str(data.get("description", ""))))
    return [("file_type PE-ness", says_pe == (raw is not None),
             f"tool: {data.get('description')!r}; header says PE: {raw is not None}")]


def compare_sections(data, raw):
    if raw is None:
        return [("sections", None, "not a PE")]
    got, want = data.get("sections") or [], raw["sections"]
    checks = [("section count", len(got) == len(want), f"{len(got)} vs {len(want)}")]
    for g, w in zip(got, want):
        same = all(g.get(k) == w[k] for k in ("name", "virtual_address", "virtual_size", "raw_size"))
        close = abs((g.get("entropy") or 0) - w["entropy"]) <= ENTROPY_TOLERANCE
        checks.append((f"section {w['name']}", same and close,
                       f"tool {g.get('name')} ent {g.get('entropy')}; ref ent {w['entropy']:.3f}"))
    return checks


def compare_imports(data, ref):
    got = {d["dll"].lower(): set(d["functions"]) for d in data.get("dlls") or []}
    checks = [("import DLL set", set(got) == set(ref["imports"]),
               f"tool-only {sorted(set(got) - set(ref['imports']))}; ref-only {sorted(set(ref['imports']) - set(got))}")]
    missing = {d: sorted(ref["imports"][d] - got.get(d, set())) for d in ref["imports"]}
    extra = {d: sorted(got[d] - ref["imports"].get(d, set())) for d in got}
    missing = {d: v for d, v in missing.items() if v}
    extra = {d: v for d, v in extra.items() if v}
    checks.append(("import functions", not missing and not extra,
                   f"missing {sum(map(len, missing.values()))}; extra {sum(map(len, extra.values()))}"))
    total = sum(len(v) for v in ref["imports"].values())
    checks.append(("function_count", data.get("function_count") == total, f"{data.get('function_count')} vs {total}"))
    return checks


def compare_strings(data, ref):
    got = set(data.get("strings") or [])
    recall = len(got & ref) / len(ref) if ref else 1.0
    precision = len(got & ref) / len(got) if got else 1.0
    return [("strings recall", recall >= 0.99, f"{recall:.3f} ({len(ref)} reference strings)"),
            ("strings precision", precision >= 0.99, f"{precision:.3f} ({len(got)} tool strings)")]


def compare_extra(data, ref, raw, size):
    checks = [("imphash", data.get("imphash") == ref["imphash"], f"{data.get('imphash')} vs {ref['imphash']}")]
    if raw is not None:
        end = max((s["raw_pointer"] + s["raw_size"] for s in raw["sections"]), default=0)
        want = max(size - end, 0)
        checks.append(("overlay size", data.get("overlay_size") == want, f"{data.get('overlay_size')} vs {want}"))
    return checks


def compare_version(data, ref):
    got = data.get("version_info") or {}
    flat = {str(v) for v in got.values()} if isinstance(got, dict) else set()
    want = set(ref["version"].values())
    checks = [("signature present", data.get("has_signature") == ref["has_signature"],
               f"{data.get('has_signature')} vs {ref['has_signature']}")]
    if want:
        missing = sorted(want - flat)
        checks.append(("version strings", not missing, f"missing {missing[:3]}"))
    else:
        checks.append(("version strings", not flat, "reference has none; tool reported "
                       f"{len(flat)}"))
    return checks


def compare_packers(data, die_names):
    if die_names is None:
        return [("DIE packer agreement", None, "diec not installed; independent packing check not run")]
    reported = " ".join(str(p).lower() for p in data.get("suspected_packers") or [])
    reported += " " + json.dumps(data.get("detect_it_easy") or {}).lower()
    if not die_names:
        return [("DIE packer agreement", not (data.get("suspected_packers") or []),
                 f"DIE names no packer; tool suspects {data.get('suspected_packers')}")]
    missing = [n for n in die_names if n.split()[0] not in reported]
    return [("DIE packer agreement", not missing, f"DIE: {sorted(die_names)}; not reported: {missing}")]


# --- driver -------------------------------------------------------------------
def find_samples(paths):
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += [f for f in sorted(p.rglob("*")) if f.is_file() and f.suffix.lower() in PE_SUFFIXES]
        elif p.is_file():
            files.append(p)
    return files


def evaluate_file(path, tools):
    data_bytes = Path(path).read_bytes()
    raw = raw_pe(data_bytes)
    results = {}
    for name, tool in tools.items():
        res = run_tool(tool.spec, tool.run, str(path)).to_dict()
        results[name] = res
    rows = []

    def add(tool, checks):
        for check, ok, detail in checks:
            rows.append({"tool": tool, "check": check, "passed": ok, "detail": detail})

    def ok_data(name):
        res = results.get(name)
        if res is None or res["status"] != "success":
            add(name, [(f"{name} ran", False, f"status {res and res['status']}: {res and res['error']}")])
            return None
        return res["data"]

    if (d := ok_data("hashes")) is not None:
        add("hashes", compare_hashes(d, system_hashes(path)))
    if (d := ok_data("file_type")) is not None:
        add("file_type", compare_file_type(d, raw))
    if raw is not None:
        ref = pefile_reference(path)
        if (d := ok_data("sections")) is not None:
            add("sections", compare_sections(d, raw))
        if (d := ok_data("imports")) is not None:
            add("imports", compare_imports(d, ref))
        if (d := ok_data("extra_checks")) is not None:
            add("extra_checks", compare_extra(d, ref, raw, len(data_bytes)))
        if (d := ok_data("version_info")) is not None:
            add("version_info", compare_version(d, ref))
        if (d := ok_data("packer_signatures")) is not None:
            add("packer_signatures", compare_packers(d, run_die(path)))
    if (d := ok_data("strings")) is not None:
        add("strings", compare_strings(d, reference_strings(data_bytes)))
    timings = {n: r["duration_ms"] for n, r in results.items()}
    return {"file": Path(path).name, "sha256": hashlib.sha256(data_bytes).hexdigest(),
            "size": len(data_bytes), "is_pe": raw is not None, "checks": rows, "duration_ms": timings}


def summarise(evals):
    per_tool = {}
    for e in evals:
        for r in e["checks"]:
            t = per_tool.setdefault(r["tool"], {"pass": 0, "fail": 0, "skipped": 0})
            t["skipped" if r["passed"] is None else "pass" if r["passed"] else "fail"] += 1
    lines = ["# O2: tool output vs independent reference", "",
             f"Samples: {len(evals)} ({sum(e['is_pe'] for e in evals)} valid PE)", "",
             "| Tool | Passed | Failed | Skipped | Agreement |", "|---|---|---|---|---|"]
    for tool, c in per_tool.items():
        n = c["pass"] + c["fail"]
        pct = f"{100 * c['pass'] / n:.1f}%" if n else "n/a"
        lines.append(f"| {tool} | {c['pass']} | {c['fail']} | {c['skipped']} | {pct} |")
    fails = [(e["file"], r) for e in evals for r in e["checks"] if r["passed"] is False]
    lines += ["", f"## Mismatches ({len(fails)})", ""]
    lines += [f"- `{f}` / {r['tool']} / {r['check']}: {r['detail']}" for f, r in fails] or ["None."]
    skipped = sorted({(r["tool"], r["detail"]) for e in evals for r in e["checks"] if r["passed"] is None})
    if skipped:
        lines += ["", "## Not checked", ""] + [f"- {t}: {d}" for t, d in skipped]
    return "\n".join(lines) + "\n", per_tool


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+", help="sample files or folders (PE files)")
    ap.add_argument("--out", default="runs", help="folder for the results (default: runs)")
    args = ap.parse_args(argv)
    samples = find_samples(args.paths)
    if not samples:
        print("no files found", file=sys.stderr)
        return 2
    tools = {t.name: t for t in load_tools()[0] if t.name in CHECKED_TOOLS}
    evals = []
    for i, s in enumerate(samples, 1):
        print(f"[{i}/{len(samples)}] {s.name}", flush=True)
        evals.append(evaluate_file(s, tools))
    summary, per_tool = summarise(evals)
    out = Path(args.out) / f"tools_eval_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(summary)
    (out / "results.json").write_text(json.dumps({"per_tool": per_tool, "samples": evals}, indent=2))
    print(summary)
    print(f"Saved to {out}")
    return 0 if all(c["fail"] == 0 for c in per_tool.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
