"""
malworn.packing.signatures  -  OFFLINE signature data + matcher (no YARA, no DIE).

Everything needed to match packer signatures lives in this file. There is no
network access, no external program and no rules download. To add a rule, add
an entry to SIGNATURES (and a test).

Pattern syntax (a tiny subset of YARA hex strings):
    "60 BE ?? ?? ?? ?? 8D BE"   two hex digits = exact byte
                                ??           = any one byte (wildcard)
                                [4]          = any 4 bytes (a "jump")

Each entry says WHERE it must match:
    "entry_point" : the bytes must start exactly at the program's entry point
    "anywhere"    : the bytes may appear at any file offset

HONESTY FIELDS (important for NFR4/NFR9):
    source   : where the rule came from
    verified : True  = reproduced by us on real packer output in the lab
               False = taken from a paper or heuristic, NOT yet reproduced

Signatures are only EVIDENCE. Adversaries edit entry-point bytes and strings
(Li et al., PackGenome, CCS 2023), so a missing match proves nothing.

AI-assistance note (team norm): first draft generated with Claude (Anthropic);
review and own it. Re-verify every entry marked verified=False.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern

SIGNATURES: List[Dict[str, Any]] = [
    {
        "id": "UPX_EP_STUB_PUSHAD_MOV_LEA",
        "packer": "UPX",
        "pattern": "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57",
        "where": "entry_point",
        "severity": "high",
        "source": "Observed at the entry point of PE32 files packed with UPX 4.2.4 "
                  "(--best, --lzma, --brute, -1) in a lab test.",
        "verified": True,
    },
    {
        "id": "UPX_MARKER_STRING",
        "packer": "UPX",
        "pattern": "55 50 58 21",          # ASCII "UPX!"
        "where": "anywhere",
        "severity": "high",
        "source": "Marker string stored by UPX; found once in UPX 4.2.4 output in a lab test. "
                  "Custom UPX variants remove it.",
        "verified": True,
    },
    {
        "id": "UPX_EP_STUB_CALL_POP",
        "packer": "UPX",
        "pattern": "60 E8 00 00 00 00 58 83 E8 3D",
        "where": "entry_point",
        "severity": "high",
        "source": "PackGenome (Li et al., CCS 2023), Fig. 2, UPX rule string $b. "
                  "Not reproduced locally.",
        "verified": False,
    },
    {
        "id": "UPX_DECOMPRESSION_LOOP",
        "packer": "UPX",
        "pattern": "EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB",
        "where": "anywhere",
        "severity": "medium",
        "source": "PackGenome (Li et al., CCS 2023), Fig. 2, UPX rule string $c "
                  "(decompression loop). Not reproduced locally.",
        "verified": False,
    },
    {
        "id": "GENERIC_PUSHAD_AT_ENTRY",
        "packer": None,
        "pattern": "60",
        "where": "entry_point",
        "severity": "low",
        "source": "Common analyst heuristic: many stubs begin with PUSHAD to save registers. "
                  "Not from the supplied papers; weak on its own.",
        "verified": False,
    },
    {
        "id": "GENERIC_CALL_NEXT_AT_ENTRY",
        "packer": None,
        "pattern": "E8 00 00 00 00",
        "where": "entry_point",
        "severity": "low",
        "source": "Common analyst heuristic: 'call $+5' used to find the current address. "
                  "Not from the supplied papers; weak on its own.",
        "verified": False,
    },
]

_TOKEN = re.compile(r"\?\?|\[\d+\]|[0-9A-Fa-f]{2}")


def compile_pattern(pattern: str) -> Pattern[bytes]:
    """Turn a hex pattern string into a compiled byte regex."""
    parts: List[bytes] = []
    for tok in _TOKEN.findall(pattern):
        if tok == "??":
            parts.append(b".")                       # any one byte
        elif tok.startswith("["):
            parts.append(b".{%d}" % int(tok[1:-1]))  # any n bytes
        else:
            parts.append(re.escape(bytes([int(tok, 16)])))
    if not parts:
        raise ValueError(f"empty/invalid pattern: {pattern!r}")
    return re.compile(b"".join(parts), re.DOTALL)    # DOTALL: '.' also matches 0x0A


_COMPILED = {s["id"]: compile_pattern(s["pattern"]) for s in SIGNATURES}


def match_signatures(data: bytes, ep_offset: Optional[int]) -> List[Dict[str, Any]]:
    """Return every bundled signature that matches. ep_offset is the entry
    point's FILE offset (or None if it cannot be located)."""
    found: List[Dict[str, Any]] = []
    for sig in SIGNATURES:
        rx = _COMPILED[sig["id"]]
        offset: Optional[int] = None
        if sig["where"] == "entry_point":
            if ep_offset is not None and rx.match(data, ep_offset):
                offset = ep_offset
        else:
            m = rx.search(data)
            offset = m.start() if m else None
        if offset is not None:
            found.append({"id": sig["id"], "packer": sig["packer"], "offset": offset,
                          "where": sig["where"], "severity": sig["severity"],
                          "source": sig["source"], "verified": sig["verified"]})
    return found
