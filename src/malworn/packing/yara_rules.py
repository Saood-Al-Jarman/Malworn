"""
malworn.packing.yara_rules  -  OPTIONAL local YARA rule support (offline).

Lets you drop packer rules (for example the YARA rules PackGenome generated,
which are in the authors' Zenodo artifact) into a LOCAL folder and have them
used as extra evidence. Nothing is downloaded: the rules directory is read from
disk only. If `yara-python` is not installed, or the folder is empty, this
module simply reports that it was not used.

Rules folder:  src/malworn/packing/rules/  (or env MALWORN_PACKING_RULES)
Check each rule file's licence before committing it to the repository.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

RULES_ENV = "MALWORN_PACKING_RULES"


def rules_dir() -> Path:
    return Path(os.environ.get(RULES_ENV) or Path(__file__).parent / "rules")


def scan(path: str) -> Dict[str, Any]:
    """Return {'used': bool, 'reason': str, 'matches': [rule names]}."""
    d = rules_dir()
    files = sorted(list(d.glob("*.yar")) + list(d.glob("*.yara"))) if d.is_dir() else []
    if not files:
        return {"used": False, "reason": "no local rule files", "matches": []}
    try:
        import yara  # type: ignore
    except ImportError:
        return {"used": False, "reason": "yara-python not installed", "matches": []}
    try:
        rules = yara.compile(filepaths={f.stem: str(f) for f in files})
        return {"used": True, "reason": f"{len(files)} rule file(s)",
                "matches": sorted({m.rule for m in rules.match(path)})}
    except Exception as e:  # noqa: BLE001  (a bad rule file must not break analysis)
        return {"used": False, "reason": f"rule error: {str(e)[:120]}", "matches": []}
