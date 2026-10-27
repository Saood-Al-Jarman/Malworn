"""
malworn.packing.indicators  -  OFFLINE packing detection for Windows PE files (FR5)

SCOPE: DETECT ONLY, with EVIDENCE. The module reports whether a file (and which
sections) look packed AND lists every piece of evidence for and against. It
never unpacks anything. If packing is suspected, the user is asked to unpack
the sample and re-upload it.

OFFLINE BY DESIGN: no network access, no external programs, no rule downloads.
All thresholds are in THRESHOLDS below; all signatures and name patterns are
bundled in this package (see signatures.py). The only third-party dependency is
the pure-Python library `pefile`. The file is only READ; it is never executed.

Design rules (Report 1):
  * FR7  : no malicious/benign verdict. Packing is an indicator, not proof.
  * NFR4 : every claim is a deterministic output (observed value + threshold).
  * NFR7 : every indicator names the component that produced it.
  * NFR8 : one function, analyze(path) -> dict, for the agent to register.
  * NFR9 : every threshold is in THRESHOLDS with where it came from.

AI-assistance note (team norm): first draft generated with Claude (Anthropic);
to be reviewed, tested and owned by the team member responsible (FR5).

CLI:  python -m malworn.packing.indicators sample.exe
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

import pefile

from malworn.packing import die as die_mod
from malworn.packing import signatures as sigs
from malworn.packing import structure as struct
from malworn.packing import yara_rules

TOOL_NAME = "packing_indicators"
TOOL_VERSION = "0.6.0"

# ---------------------------------------------------------------------------
# Thresholds. ALL are starting points to be TUNED on your own test set (NFR9).
# ---------------------------------------------------------------------------
THRESHOLDS = {
    # 7.0 (Lyda & Hamrock; Ugarte-Pedrero) and 6.5 (DIE >= 2.05). Pack-ALM Appx B
    # shows 6.5 raises benign false positives sharply.
    "entropy_high": 7.0,
    "entropy_medium": 6.5,
    # Pack-ALM uses 2,048-byte windows for entropy (Appx B).
    "window_size": 2048,
    "window_step": 1024,
    "min_section_bytes_for_entropy": 512,
    # Bertrand Van Ouytsel et al.: raw/virtual size ratio features rank highly.
    "ep_raw_to_virtual_ratio_low": 0.1,
    "import_count_low": 10,
    # Points needed for a LEVEL (applies to a whole file and to a single section).
    "points_possible": 3,
    "points_likely": 6,
    "max_file_bytes": 200 * 1024 * 1024,
}

STANDARD_CODE_SECTIONS = {".text", "code", ".code", "text"}
STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc", ".pdata",
    ".bss", ".tls", ".crt", ".didat", ".gfids", ".00cfg", "code", "data", "bss",
    ".xdata", ".sdata", ".CRT", ".orpc",
}

# Bundled offline name patterns. UPX0/UPX1, .themida/.winlice and .vmp come from
# the PackGenome paper (DIE rules; APT41 renaming .vmp). The rest are common
# names from memory: VERIFY each against your own packed samples and the
# Alkhateeb et al. dictionary before trusting it.
KNOWN_PACKER_SECTION_PATTERNS = {
    "UPX": r"^\.?upx\d*$",
    "MPRESS": r"^\.mpress\d$",
    "ASPack": r"^\.(aspack|adata)$",
    "PECompact": r"^(pec\d*|pec1|pec2|pecompact\d*)$",
    "Petite": r"^\.petite$",
    "Themida/WinLicense": r"^\.(themida|winlice)$",
    "VMProtect": r"^\.vmp\d$",
    "NsPack": r"^\.?nsp\d$",
    "Enigma": r"^\.enigma\d$",
    "FSG": r"^fsg!?$",
    "kkrunchy": r"^kkrunchy$",
}

LOADER_APIS = {
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
    "getprocaddress", "virtualalloc", "virtualprotect", "virtualfree",
}

SEV_POINTS = {"info": 0, "low": 0, "medium": 1, "high": 3}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _ind(id_: str, value: Any, severity: str, why: str, source: str = "pefile",
         section: Optional[Dict[str, Any]] = None, **extra: Any) -> Dict[str, Any]:
    """Build one piece of evidence.
      value     : what was actually observed
      threshold : (in extra) the limit it was compared with, when there is one
      points    : how much it adds to the score (0 for weak/info items)
      location  : the section name, or 'file' for file-level evidence
      section   : section name/index it belongs to (None = file-level)"""
    d = {"id": id_, "value": value, "severity": severity, "points": SEV_POINTS[severity],
         "why": why, "source": source,
         "location": section["name"] if section else "file",
         "section": section["name"] if section else None,
         "section_index": section["index"] if section else None}
    d.update(extra)
    return d


def _clean_name(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("latin-1", errors="replace")


def _perm_str(ch: int) -> str:
    return (("R" if ch & 0x40000000 else "-") + ("W" if ch & 0x80000000 else "-")
            + ("X" if ch & 0x20000000 else "-"))


def _level_from_points(points: int) -> str:
    if points >= THRESHOLDS["points_likely"]:
        return "likely"
    if points >= THRESHOLDS["points_possible"]:
        return "possible"
    return "none_detected"


def _section_for_offset(sections: List[Dict[str, Any]], off: int) -> Optional[Dict[str, Any]]:
    for s in sections:
        if s["raw_size"] and s["_raw_off"] <= off < s["_raw_off"] + s["raw_size"]:
            return s
    return None


# ---------------------------------------------------------------------------
# Layer 1: PE structure evidence (each piece tagged to its section if it has one)
# ---------------------------------------------------------------------------
def _section_table(pe: pefile.PE, data: bytes) -> List[Dict[str, Any]]:
    rows = []
    for i, s in enumerate(pe.sections):
        raw = data[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
        vsize = s.Misc_VirtualSize
        rows.append({
            "index": i, "name": _clean_name(s.Name),
            "virtual_address": hex(s.VirtualAddress), "virtual_size": vsize,
            "raw_size": s.SizeOfRawData,
            "raw_to_virtual_ratio": round(s.SizeOfRawData / vsize, 3) if vsize else None,
            "entropy": round(shannon_entropy(raw), 3),
            "perms": _perm_str(s.Characteristics),
            "_va": s.VirtualAddress, "_span": max(vsize, s.SizeOfRawData),
            "_raw_off": s.PointerToRawData,
        })
    return rows


def _structure_indicators(pe: pefile.PE, sections: List[Dict[str, Any]],
                          data: bytes) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    out: List[Dict[str, Any]] = []
    T = THRESHOLDS

    fe = round(shannon_entropy(data), 3)
    out.append(_ind("FILE_ENTROPY", fe, "medium" if fe >= T["entropy_high"] else "info",
                    "Whole-file entropy. Weak alone: compressed resources in benign files also raise it, "
                    "and low-entropy packers keep it low.", threshold=T["entropy_high"]))

    for s in sections:
        nm = s["name"]
        if s["raw_size"] >= T["min_section_bytes_for_entropy"]:
            if s["entropy"] >= T["entropy_high"]:
                sev = "high" if "X" in s["perms"] else "medium"
                out.append(_ind("SECTION_ENTROPY_HIGH", s["entropy"], sev,
                                "Entropy this high suggests compressed or encrypted content "
                                "(scored higher when the section is executable).",
                                section=s, threshold=T["entropy_high"]))
            elif s["entropy"] >= T["entropy_medium"]:
                out.append(_ind("SECTION_ENTROPY_ELEVATED", s["entropy"], "low",
                                "Ambiguous: common in benign resources, so it adds no score.",
                                section=s, threshold=T["entropy_medium"]))

        if s["raw_size"] == 0 and s["virtual_size"] > 0 and "W" in s["perms"]:
            out.append(_ind("EMPTY_WRITABLE_SECTION", s["virtual_size"], "high",
                            "Writable section with zero bytes on disk but non-zero size in memory: "
                            "space a stub unpacks into.", section=s))
        elif s["raw_size"] > 0 and s["virtual_size"] > 2 * s["raw_size"]:
            out.append(_ind("VSIZE_MUCH_GREATER_THAN_RAW", s["raw_to_virtual_ratio"], "medium",
                            "Raw/virtual size ratio is below the threshold: the section is more than twice as "
                            "large in memory as on disk (Bertrand Van Ouytsel et al., feature 39).",
                            section=s, threshold=0.5))

        if s["perms"] == "RWX":
            out.append(_ind("RWX_SECTION", s["perms"], "high",
                            "Section is readable, writable AND executable (self-modifying code).",
                            section=s))

        hit = next((p for p, rx in KNOWN_PACKER_SECTION_PATTERNS.items() if re.match(rx, nm, re.I)), None)
        if hit:
            out.append(_ind("PACKER_SECTION_NAME", {"name": nm, "packer": hit}, "high",
                            "Section name matches a known packer. Names are trivially renamed by "
                            "adversaries (APT41 did this), so absence proves nothing.", section=s,
                            source="bundled_name_patterns"))
        elif nm not in STANDARD_SECTION_NAMES and nm.lower() not in STANDARD_SECTION_NAMES:
            out.append(_ind("NONSTANDARD_SECTION_NAME", nm, "low",
                            "Name is not one of the common compiler-generated names (weak).", section=s))

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_sec = next((s for s in sections if s["_va"] <= ep < s["_va"] + s["_span"]), None)
    if ep == 0:
        out.append(_ind("EP_ZERO", 0, "info", "No entry point (typical for DLL resources/drivers)."))
    elif ep_sec is None:
        out.append(_ind("EP_OUTSIDE_SECTIONS", hex(ep), "high",
                        "Entry point lies outside every section (header-stub or tampered layout)."))
    else:
        out.append(_ind("EP_SECTION", ep_sec["name"], "info", "Section containing the entry point.",
                        section=ep_sec))
        if ep_sec["name"].lower() not in STANDARD_CODE_SECTIONS:
            out.append(_ind("EP_NONSTANDARD_SECTION", ep_sec["name"], "high",
                            "Entry point is not in a standard code section; unpacking stubs often live "
                            "in a dedicated section (Bertrand Van Ouytsel et al., feature 35).",
                            section=ep_sec))
        if len(sections) > 1 and ep_sec is sections[-1]:
            out.append(_ind("EP_IN_LAST_SECTION", ep_sec["name"], "medium",
                            "Entry point in the last section is a common stub placement.", section=ep_sec))
        r = ep_sec["raw_to_virtual_ratio"]
        if r is not None and r < T["ep_raw_to_virtual_ratio_low"]:
            out.append(_ind("EP_SECTION_MOSTLY_EMPTY_ON_DISK", r, "high",
                            "Entry-point section is much larger in memory than on disk: it is filled at "
                            "runtime (Bertrand feature 37).", section=ep_sec,
                            threshold=T["ep_raw_to_virtual_ratio_low"]))

    out.append(_ind("WRITABLE_SECTION_COUNT", sum(1 for s in sections if "W" in s["perms"]), "info",
                    "Count of writable sections (Bertrand feature 29)."))

    names: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    names.append(imp.name.decode("latin-1", "replace"))
    n_imp = len(names)
    loader_hits = sorted({n for n in names if n.lower() in LOADER_APIS})
    if n_imp < T["import_count_low"]:
        out.append(_ind("FEW_IMPORTS", {"count": n_imp, "loader_apis": loader_hits},
                        "high" if loader_hits else "medium",
                        "Very small import table. Packers resolve most APIs at runtime via "
                        "LoadLibrary/GetProcAddress.", threshold=T["import_count_low"]))
    else:
        out.append(_ind("IMPORT_COUNT", n_imp, "info", "Number of named imports.",
                        threshold=T["import_count_low"]))

    overlay_off = pe.get_overlay_data_start_offset()
    if overlay_off is not None and overlay_off < len(data):
        out.append(_ind("OVERLAY_PRESENT", {"offset": hex(overlay_off), "size": len(data) - overlay_off},
                        "low", "Data appended after the last section (installers/packers often do this; weak)."))
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        out.append(_ind("TLS_DIRECTORY_PRESENT", True, "low",
                        "TLS callbacks run before the entry point; sometimes used by stubs (weak)."))
    out.append(_ind("STACK_RESERVE_SIZE", pe.OPTIONAL_HEADER.SizeOfStackReserve, "info",
                    "Reported as a value (Bertrand feature 19); no fixed threshold."))
    return out, ep_sec


# ---------------------------------------------------------------------------
# Layer 2: bundled offline signatures (see signatures.py)
# ---------------------------------------------------------------------------
def _signature_indicators(pe: pefile.PE, data: bytes,
                          sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    try:
        ep_off = pe.get_offset_from_rva(ep) if ep else None
    except Exception:  # noqa: BLE001
        ep_off = None
    out = []
    for m in sigs.match_signatures(data, ep_off):
        sec = _section_for_offset(sections, m["offset"])
        out.append(_ind(
            "SIGNATURE_MATCH",
            {"signature": m["id"], "packer": m["packer"], "offset": hex(m["offset"]), "where": m["where"]},
            m["severity"],
            f"Bytes at the {'entry point' if m['where'] == 'entry_point' else 'file (any offset)'} "
            f"match bundled signature {m['id']} "
            f"({'verified in lab' if m['verified'] else 'NOT yet reproduced locally'}; source: {m['source']})",
            section=sec, source="bundled_signatures"))
    return out


# ---------------------------------------------------------------------------
# Layer 0: Detect It Easy, run FIRST (see die.py)
# ---------------------------------------------------------------------------
def _die_indicators(die_res: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    generic_types = []
    for d in die_res.get("packers", []):
        if d["name"] == "Generic":            # DIE's heuristic "something is packed/protected"
            generic_types.append(d["type"])
            continue
        label = f"{d['name']} {d['version']}".strip()
        extra = f" [{d['info']}]" if d["info"] else ""
        out.append(_ind(
            "DIE_PACKER_DETECTED",
            {"type": d["type"], "name": d["name"], "version": d["version"], "info": d["info"],
             "heuristic": d["heuristic"]}, "medium" if d["heuristic"] else "high",
            f"Detect It Easy reports {d['type']} {label}{extra}"
            + (" (heuristic)" if d["heuristic"] else "")
            + ". DIE is signature-based and can be evaded or fooled by custom packers.",
            source="detect_it_easy"))
    if generic_types:                          # one indicator, however many generic hits
        out.append(_ind("DIE_GENERIC_HEURISTIC", sorted(set(generic_types)), "medium",
                        "Detect It Easy's heuristic scan flagged the file as packed/protected without "
                        "naming a packer (useful for unknown packers; heuristics can be wrong).",
                        source="detect_it_easy"))
    return out


# ---------------------------------------------------------------------------
# Layer 2b: optional local YARA rules (e.g. PackGenome-generated), offline
# ---------------------------------------------------------------------------
YARA_KEYWORDS = {"upx": "UPX", "mpress": "MPRESS", "aspack": "ASPack", "pecompact": "PECompact",
                 "petite": "Petite", "themida": "Themida/WinLicense", "winlicense": "Themida/WinLicense",
                 "vmprotect": "VMProtect", "nspack": "NsPack", "enigma": "Enigma", "fsg": "FSG",
                 "mew": "MEW", "kkrunchy": "kkrunchy", "obsidium": "Obsidium"}


def _yara_indicators(path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    res = yara_rules.scan(path)
    out = []
    for rule in res["matches"]:
        packer = next((c for k, c in YARA_KEYWORDS.items() if k in rule.lower()), None)
        out.append(_ind("SIGNATURE_MATCH", {"signature": rule, "packer": packer, "offset": "n/a",
                                           "where": "yara"}, "high",
                        f"Local YARA rule '{rule}' matched (rule files are read from disk; no network).",
                        source="local_yara_rules"))
    return out, res


# ---------------------------------------------------------------------------
# Layer 2c: instruction-structure ("code-likeness") of EXECUTABLE sections
# ---------------------------------------------------------------------------
def _codeness_indicators(pe: pefile.PE, data: bytes,
                         sections: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Pack-ALM-inspired check (see structure.py). Applied ONLY to executable
    sections: in our proxy test, benign non-code data (strings, tables) was
    flagged 100% of the time, so using it on data sections would be wrong."""
    bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
    status: Dict[str, Any] = {"ran": False, "bits": bits}
    try:
        import capstone  # noqa: F401
    except ImportError:
        status["reason"] = "capstone not installed"
        return [_ind("CODENESS_CHECK_NOT_RUN", status["reason"], "info",
                     "Instruction-structure check skipped.", source="structure")], status
    model = struct.load(bits)
    if model is None:
        status["reason"] = f"no trained {bits}-bit model (run train_codeness.py on benign PEs)"
        return [_ind("CODENESS_CHECK_NOT_RUN", status["reason"], "info",
                     "Instruction-structure check skipped.", source="structure")], status
    status.update(ran=True, threshold=round(model.threshold, 3))
    out: List[Dict[str, Any]] = []
    for s in sections:
        if "X" not in s["perms"] or s["raw_size"] < struct.WINDOW:
            continue
        blob = data[s["_raw_off"]: s["_raw_off"] + s["raw_size"]]
        r = struct.score_region(model, blob)
        frac = r["fraction_not_code_like"]
        if frac >= 0.5:
            out.append(_ind("EXEC_SECTION_NOT_CODE_LIKE", r, "high",
                            "Most windows of this EXECUTABLE section disassemble into implausible "
                            "instruction sequences, as packed or encoded data does (Pack-ALM's "
                            "real/pseudo-instruction idea; catches low-entropy packing that entropy misses).",
                            section=s, source="structure", threshold=0.5))
        elif frac >= 0.25:
            out.append(_ind("EXEC_SECTION_PARTLY_NOT_CODE_LIKE", r, "medium",
                            "A quarter or more of this executable section does not look like code "
                            "(could be embedded data tables or partly packed data).",
                            section=s, source="structure", threshold=0.25))
        else:
            out.append(_ind("EXEC_SECTION_CODE_LIKE", r, "info",
                            "This executable section disassembles into plausible code.",
                            section=s, source="structure"))
    return out, status


# ---------------------------------------------------------------------------
# Layer 3: windowed entropy map, mapped back onto sections
# ---------------------------------------------------------------------------
def high_entropy_regions(data: bytes, sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Slide a window over the file, merge overlapping high-entropy windows into
    regions, and say which section(s) each region falls in (or 'overlay')."""
    w, step, thr = THRESHOLDS["window_size"], THRESHOLDS["window_step"], THRESHOLDS["entropy_high"]
    raw_regions: List[List[float]] = []
    cur: Optional[List[float]] = None
    for off in range(0, max(len(data) - w, 0) + 1, step):
        e = shannon_entropy(data[off: off + w])
        if e >= thr:
            if cur and off <= cur[1]:
                cur[1], cur[2] = off + w, max(cur[2], e)
            else:
                if cur:
                    raw_regions.append(cur)
                cur = [off, off + w, e]
        elif cur and off > cur[1]:
            raw_regions.append(cur)
            cur = None
    if cur:
        raw_regions.append(cur)

    last_end = max((s["_raw_off"] + s["raw_size"] for s in sections), default=0)
    out = []
    for start, end, mx in raw_regions:
        start, end = int(start), int(end)
        hit = [s for s in sections
               if s["raw_size"] and start < s["_raw_off"] + s["raw_size"] and end > s["_raw_off"]]
        names = [s["name"] for s in hit] + (["overlay"] if end > last_end else [])
        out.append({"offset": hex(start), "size": end - start, "max_entropy": round(mx, 3),
                    "sections": names, "section_indexes": [s["index"] for s in hit]})
    return out


# ---------------------------------------------------------------------------
# Evidence AGAINST packing (so a "clean" answer is also backed by evidence)
# ---------------------------------------------------------------------------
def _counter_evidence(sections: List[Dict[str, Any]], ep_sec: Optional[Dict[str, Any]],
                      inds: List[Dict[str, Any]], die_res: Optional[Dict[str, Any]] = None
                      ) -> List[Dict[str, Any]]:
    ids = {i["id"] for i in inds}
    out: List[Dict[str, Any]] = []

    def add(id_: str, value: Any, why: str, loc: str = "file") -> None:
        out.append({"id": id_, "value": value, "why": why, "location": loc})

    if die_res and die_res.get("ran") and not die_res.get("packers"):
        add("DIE_NO_PACKER", True, "Detect It Easy ran first and reported no packer or protector "
            "(weak: custom and low-entropy packers are not in its database).")
    if ep_sec is not None and ep_sec["name"].lower() in STANDARD_CODE_SECTIONS:
        add("EP_IN_STANDARD_CODE_SECTION", ep_sec["name"],
            "Entry point is inside a standard code section, as in normal compiler output.", ep_sec["name"])
    imp = next((i for i in inds if i["id"] == "IMPORT_COUNT"), None)
    if imp:
        add("NORMAL_IMPORT_COUNT", imp["value"],
            f"Import table has at least {THRESHOLDS['import_count_low']} named imports; stubs usually have very few.")
    big = [s["entropy"] for s in sections if s["raw_size"] >= THRESHOLDS["min_section_bytes_for_entropy"]]
    if big and "SECTION_ENTROPY_HIGH" not in ids:
        add("NO_HIGH_ENTROPY_SECTION", round(max(big), 3),
            f"The highest section entropy is below {THRESHOLDS['entropy_high']}, the usual compressed/encrypted level.")
    for i in inds:
        if i["id"] == "EXEC_SECTION_CODE_LIKE":
            add("EXEC_SECTION_CODE_LIKE", i["value"]["fraction_not_code_like"],
                "Executable section disassembles into plausible code (fraction of windows that do not "
                "look like code is shown).", i["location"])
    if "PACKER_SECTION_NAME" not in ids:
        add("NO_PACKER_SECTION_NAMES", [s["name"] for s in sections],
            "No section name matches a known packer (weak: names are easy to change).")
    if not ids & {"RWX_SECTION", "EMPTY_WRITABLE_SECTION"}:
        add("NO_RWX_OR_RESERVE_SECTIONS", True,
            "No read-write-execute section and no empty writable reserve section.")
    if not any(i["id"] == "SIGNATURE_MATCH" and i["points"] > 0 for i in inds):
        add("NO_BUNDLED_SIGNATURE_MATCH", True,
            "No scoring signature from the bundled database matched (weak: signatures are easy to evade).")
    return out


# ---------------------------------------------------------------------------
# Aggregation and the evidence-first message (deterministic; no LLM involved)
# ---------------------------------------------------------------------------
def _assess_sections(sections, indicators) -> List[Dict[str, Any]]:
    res = []
    for s in sections:
        mine = [i for i in indicators if i["section_index"] == s["index"]]
        pts = sum(i["points"] for i in mine)
        res.append({"name": s["name"], "index": s["index"], "points": pts,
                    "level": _level_from_points(pts),
                    "reasons": [i["id"] for i in mine if i["points"] > 0]})
    return res


def _suspected_packers(indicators) -> List[Dict[str, Any]]:
    """Packers named by name-pattern or signature evidence, with the evidence ids."""
    found: Dict[str, List[str]] = defaultdict(list)
    for i in indicators:
        if i["id"] == "PACKER_SECTION_NAME":
            found[i["value"]["packer"]].append(f"PACKER_SECTION_NAME({i['value']['name']})")
        elif i["id"] == "DIE_PACKER_DETECTED" and i["value"]["name"] != "Generic":
            nm = i["value"]["name"]
            canon = next((c for k, c in YARA_KEYWORDS.items() if k in nm.lower()), nm)
            note = f" {i['value']['info']}" if i["value"]["info"] else ""
            found[canon].append(f"DIE_PACKER_DETECTED({nm}{note})")
        elif i["id"] == "SIGNATURE_MATCH" and i["value"]["packer"] and i["points"] > 0:
            found[i["value"]["packer"]].append(f"SIGNATURE_MATCH({i['value']['signature']})")
    return [{"packer": p, "evidence": ev} for p, ev in found.items()]


# Independent EVIDENCE FAMILIES. Agreement between families (not the raw point total) drives confidence.
FAMILIES = {
    "detect_it_easy": {"DIE_PACKER_DETECTED", "DIE_GENERIC_HEURISTIC"},
    "signatures_and_names": {"SIGNATURE_MATCH", "PACKER_SECTION_NAME"},
    "entropy": {"SECTION_ENTROPY_HIGH", "FILE_ENTROPY", "HIGH_ENTROPY_REGION"},
    "layout_and_imports": {"EMPTY_WRITABLE_SECTION", "VSIZE_MUCH_GREATER_THAN_RAW", "RWX_SECTION",
                           "EP_OUTSIDE_SECTIONS", "EP_NONSTANDARD_SECTION", "EP_IN_LAST_SECTION",
                           "EP_SECTION_MOSTLY_EMPTY_ON_DISK", "FEW_IMPORTS"},
    "instruction_structure": {"EXEC_SECTION_NOT_CODE_LIKE", "EXEC_SECTION_PARTLY_NOT_CODE_LIKE"},
}
CONF_DOWN = {"high": "medium", "medium": "low", "low": "low"}


def final_assessment(level: str, score: int, indicators: List[Dict[str, Any]],
                     die_res: Dict[str, Any], code_status: Dict[str, Any]) -> Dict[str, Any]:
    """The single final answer: packed / not_packed / uncertain, with a confidence TIER.

    Rules (deterministic; thresholds are tunable starting points, NFR9):
      * count the independent evidence families that contribute points;
      * likely level : 3+ families -> packed/high, 2 -> packed/medium, 1 -> packed/low
      * possible     : uncertain (borderline), confidence low
      * none_detected: not_packed; confidence = how many strong checks actually ran
                       (Detect It Easy, instruction structure), lowered one step if weak signals exist
    The tier is NOT a calibrated probability: it has not been validated on a large
    labelled set. Report it as 'confidence tier', and evaluate it before quoting numbers."""
    fam = {n: sorted({i["id"] for i in indicators if i["id"] in ids and i["points"] > 0})
           for n, ids in FAMILIES.items()}
    firing = [n for n, v in fam.items() if v]
    checked = ["signatures_and_names", "entropy", "layout_and_imports"]
    if die_res.get("ran"):
        checked.append("detect_it_easy")
    if code_status.get("ran"):
        checked.append("instruction_structure")
    n = len(firing)
    if level == "likely":
        det, conf = "packed", ("high" if n >= 3 else "medium" if n == 2 else "low")
    elif level == "possible":
        det, conf = "uncertain", "low"
    else:
        strong_ran = sum(c in checked for c in ("detect_it_easy", "instruction_structure"))
        conf = {2: "high", 1: "medium", 0: "low"}[strong_ran]
        if score > 0 or n:
            conf = CONF_DOWN[conf]
        det = "not_packed"
    label = {"packed": f"PACKED ({conf} confidence)",
             "not_packed": f"NOT PACKED ({conf} confidence)",
             "uncertain": "UNCERTAIN: borderline packing evidence (low confidence)"}[det]
    basis = [f"Score {score} gives level '{level}' ('possible' needs {THRESHOLDS['points_possible']}+, "
             f"'likely' needs {THRESHOLDS['points_likely']}+).",
             f"{n} of {len(checked)} independent evidence families support packing"
             + (f": {', '.join(firing)}." if firing else "."),
             "Checks that ran: " + ", ".join(checked) + "."]
    skipped = [c for c in ("detect_it_easy", "instruction_structure") if c not in checked]
    if skipped:
        basis.append("Checks that did NOT run: " + ", ".join(skipped) + " (lowers confidence in a 'not packed' answer).")
    caveat = ("Confidence tiers are not calibrated probabilities. Low-entropy, custom and heavily obfuscated "
              "packers can evade these checks, so 'not packed' is never a guarantee.")
    return {"determination": det, "confidence": conf, "label": label,
            "evidence_families_supporting": firing, "evidence_families_checked": checked,
            "basis": basis, "caveat": caveat}


def classify_packer(level: str, suspected: List[Dict[str, Any]],
                    indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Known / modified-known / unknown, using only the evidence collected.

    known_packer                  >= 2 kinds of evidence agree (name + signature)
    known_packer_modified_variant a stub/loop signature matches but the packer's
                                  names/markers are missing: the pattern PackGenome reports
                                  for custom variants that reuse the original unpacking code
    known_packer_weak             only a section name or only a marker string; both are
                                  easy to forge or to leave behind
    unknown_packer                packed-looking (entropy / structure / layout) but nothing
                                  names a packer: generic detection, as in Pack-ALM and the
                                  entropy papers
    none_detected                 nothing convincing
    """
    if level == "none_detected":
        return {"status": "none_detected", "packer": None,
                "why": "No convincing packing evidence, so no packer is named."}
    if not suspected:
        generic = sorted({i["id"] for i in indicators if i["points"] > 0})
        return {"status": "unknown_packer", "packer": None,
                "why": "The file looks packed but no bundled signature, name pattern or local rule names a "
                       f"packer. Generic evidence: {', '.join(generic)}. It may be an unknown, custom or "
                       "low-entropy packer."}
    sp = suspected[0]
    ev = sp["evidence"]
    has_name = any(e.startswith("PACKER_SECTION_NAME") for e in ev)
    strong_sig = any(e.startswith(("SIGNATURE_MATCH", "DIE_PACKER_DETECTED")) and "MARKER" not in e
                     for e in ev)
    die_modified = any(e.startswith("DIE_PACKER_DETECTED") and "modified" in e.lower() for e in ev)
    if die_modified:
        st_, why = ("known_packer_modified_variant",
                    "Detect It Easy reports this packer as MODIFIED: a custom variant of a known packer.")
    elif has_name and strong_sig:
        st_, why = "known_packer", "Section names and byte signatures agree."
    elif strong_sig:
        st_, why = ("known_packer_modified_variant",
                    "A stub signature matches but the packer's section names are missing or changed: "
                    "likely a modified or custom variant that reuses the original unpacking code.")
    else:
        st_, why = ("known_packer_weak",
                    "Only a section name or marker string points to this packer; both are easy to forge.")
    return {"status": st_, "packer": sp["packer"], "why": why, "evidence": ev}


def _fmt(v: Any) -> str:
    if isinstance(v, dict):
        return ", ".join(f"{k}={_fmt(x)}" for k, x in v.items())
    if isinstance(v, list):
        return "[" + ", ".join(_fmt(x) for x in v) + "]"
    return str(v)


def _line(i: Dict[str, Any]) -> str:
    thr = f" (threshold {i['threshold']})" if "threshold" in i else ""
    return f"  [{i['severity'].upper()} +{i['points']}] {i['location']}: {i['id']} = {_fmt(i['value'])}{thr}. {i['why']}"


def build_user_message(level: str, score: int, evidence_for, evidence_weak, counter,
                       sec_assess, suspected, classification=None, die_res=None, final=None) -> str:
    """Plain-text report for the analyst: verdict line, ALL evidence for, weak
    observations, evidence against, how the confidence was reached, and (if
    packed) the request to unpack and re-upload. Never claims maliciousness (FR7)."""
    L: List[str] = []
    if final:
        L.append(f"FINAL ANSWER: {final['label']}")
        L += [f"  - {b}" for b in final["basis"]]
        L.append("")
    if die_res is not None:
        if die_res.get("ran"):
            found = [f"{d['name']} {d['version']}".strip() + (f" [{d['info']}]" if d["info"] else "")
                     + (" (heuristic)" if d["heuristic"] else "") for d in die_res["packers"]]
            L.append(f"Detect It Easy ({die_res.get('version') or 'version unknown'}) ran first: "
                     + (", ".join(found) if found else "no packer or protector reported") + ".")
        else:
            L.append(f"WARNING: Detect It Easy was NOT run ({die_res.get('error')}). "
                     "Results below rely on the other checks only.")
    if level == "none_detected":
        L.append("No strong packing indicators were found.")
    else:
        L.append(f"This file appears to be packed (confidence: {level}).")

    if evidence_for:
        L.append(f"\nEvidence for packing ({len(evidence_for)} items):")
        L += [_line(i) for i in evidence_for]
    if evidence_weak:
        L.append("\nWeak or contextual observations (add no score):")
        L += [_line(i) for i in evidence_weak]
    if classification and level != "none_detected":
        label = {"known_packer": "KNOWN packer", "known_packer_modified_variant":
                 "likely MODIFIED variant of a known packer", "known_packer_weak":
                 "possible known packer (weak evidence)", "unknown_packer": "UNKNOWN packer"}[classification["status"]]
        L.append(f"\nPacker classification: {label}"
                 + (f" - {classification['packer']}" if classification.get("packer") else "")
                 + f". {classification['why']}")
    if suspected:
        L.append("\nSuspected packer(s):")
        L += [f"  {s['packer']}, supported by {', '.join(s['evidence'])}" for s in suspected]
    flagged = [s for s in sec_assess if s["level"] != "none_detected"]
    if flagged:
        L.append("\nSections that look packed:")
        L += [f"  {s['name']}: {s['level']} ({s['points']} points from {', '.join(s['reasons'])})"
              for s in flagged]
    if counter:
        L.append("\nEvidence against packing (checked and found normal):")
        L += [f"  {c['location']}: {c['id']} = {_fmt(c['value'])}. {c['why']}" for c in counter]

    T = THRESHOLDS
    L.append(f"\nHow the confidence was reached: total score {score}; 'possible' needs {T['points_possible']} "
             f"or more, 'likely' needs {T['points_likely']} or more. Thresholds are tunable starting points.")
    if level == "none_detected":
        L.append("This does not guarantee the file is unpacked: low-entropy and custom packers can "
                 "evade these checks.")
    else:
        L.append("Static results for this file, such as imports and strings, may be incomplete. "
                 "Please unpack the sample and re-upload it for further analysis.")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Public entry point (this is what the agent registers as a tool)
# ---------------------------------------------------------------------------
def analyze(path: str, die_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"tool": TOOL_NAME, "version": TOOL_VERSION, "offline": True,
                              "file": os.path.basename(path)}
    # CHECK ZERO: Detect It Easy runs before anything else (cached; see die.py).
    die_res = die_result if die_result is not None else die_mod.run_die(path)
    result["detect_it_easy"] = die_res
    try:
        size = os.path.getsize(path)
        if size > THRESHOLDS["max_file_bytes"]:
            return {**result, "error": "file_too_large", "size": size}
        with open(path, "rb") as f:          # read-only; never executed
            data = f.read()
        pe = pefile.PE(data=data)            # parse from memory
    except pefile.PEFormatError as e:
        return {**result, "error": "not_a_valid_pe", "detail": str(e)[:200]}
    except OSError as e:
        return {**result, "error": "io_error", "detail": str(e)[:200]}

    sections = _section_table(pe, data)
    indicators = _die_indicators(die_res)
    struct_inds, ep_sec = _structure_indicators(pe, sections, data)
    indicators += struct_inds
    indicators += _signature_indicators(pe, data, sections)
    yara_inds, yara_status = _yara_indicators(path)
    indicators += yara_inds
    code_inds, code_status = _codeness_indicators(pe, data, sections)
    indicators += code_inds

    regions = high_entropy_regions(data, sections)
    for reg in regions:
        for idx in reg["section_indexes"]:
            s = sections[idx]
            if s["entropy"] < THRESHOLDS["entropy_high"]:    # avoid double-counting
                indicators.append(_ind(
                    "HIGH_ENTROPY_REGION",
                    {"max_entropy": reg["max_entropy"], "offset": reg["offset"], "size": reg["size"]},
                    "medium",
                    "A high-entropy window sits inside a section whose overall entropy looks normal "
                    "(partly packed data).", section=s, source="windowed_entropy",
                    threshold=THRESHOLDS["entropy_high"]))

    score = sum(i["points"] for i in indicators)
    level = _level_from_points(score)
    sec_assess = _assess_sections(sections, indicators)
    evidence_for = [i for i in indicators if i["points"] > 0]
    evidence_weak = [i for i in indicators if i["points"] == 0 and i["severity"] == "low"]
    counter = _counter_evidence(sections, ep_sec, indicators, die_res)
    suspected = _suspected_packers(indicators)
    classification = classify_packer(level, suspected, indicators)
    final = final_assessment(level, score, indicators, die_res, code_status)

    result.update({
        "sections": [{k: v for k, v in s.items() if not k.startswith("_")} for s in sections],
        "indicators": indicators,
        "evidence_for": evidence_for,
        "evidence_weak": evidence_weak,
        "counter_evidence": counter,
        "suspected_packers": suspected,
        "packer_classification": classification,
        "final_assessment": final,
        "optional_checks": {"detect_it_easy": {k: die_res.get(k) for k in ("available", "ran", "version", "error")},
                            "local_yara_rules": yara_status, "instruction_structure": code_status},
        "high_entropy_regions": regions,
        "section_assessments": sec_assess,
        "packed_sections": [s for s in sec_assess if s["level"] != "none_detected"],
        "score": score,
        "packing_indicators_level": level,
        "needs_unpacking": level != "none_detected",
        "static_evidence_reliability": "reduced" if level != "none_detected" else "normal",
        "user_message": build_user_message(level, score, evidence_for, evidence_weak, counter,
                                           sec_assess, suspected, classification, die_res, final),
        "thresholds_used": {k: v for k, v in THRESHOLDS.items() if k != "max_file_bytes"},
    })
    pe.close()
    return result


def signature_report(path: str, die_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Everything SIGNATURE-based, for the `packer_signatures` tool: DIE first, then
    section-name patterns, bundled byte signatures and optional local YARA rules.
    Works even if the file is not a PE (DIE can still say what it is)."""
    die_res = die_result if die_result is not None else die_mod.run_die(path)      # CHECK ZERO
    out: Dict[str, Any] = {"detect_it_easy": die_res, "section_name_matches": [],
                           "bundled_signature_matches": [], "local_yara": {"used": False, "matches": []},
                           "pe_checks": "not_run"}
    try:
        with open(path, "rb") as f:
            data = f.read()
        pe = pefile.PE(data=data)
    except (pefile.PEFormatError, OSError) as e:
        out["pe_checks"] = f"skipped: {str(e)[:100]}"
        out["suspected_packers"] = _suspected_packers(_die_indicators(die_res))
        return out
    sections = _section_table(pe, data)
    inds = _die_indicators(die_res)
    name_inds = [i for i in _structure_indicators(pe, sections, data)[0] if i["id"] == "PACKER_SECTION_NAME"]
    sig_inds = _signature_indicators(pe, data, sections)
    y_inds, y_status = _yara_indicators(path)
    out["section_name_matches"] = [{"section": i["section"], **i["value"]} for i in name_inds]
    out["bundled_signature_matches"] = [{**i["value"], "section": i["section"], "severity": i["severity"],
                                         "why": i["why"]} for i in sig_inds]
    out["local_yara"] = y_status | {"matches": [i["value"]["signature"] for i in y_inds]}
    out["suspected_packers"] = _suspected_packers(inds + name_inds + sig_inds + y_inds)
    out["pe_checks"] = "run"
    pe.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Malworn packing detection (offline, static, detect-only)")
    ap.add_argument("file")
    ap.add_argument("--message", action="store_true", help="print only the analyst-facing evidence report")
    args = ap.parse_args()
    r = analyze(args.file)
    print(r.get("user_message") if args.message and "user_message" in r else json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
