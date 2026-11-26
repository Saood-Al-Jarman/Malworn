"""Tool `capa`: capabilities in the code, mapped to MITRE ATT&CK.

Owner: Saood

Runs Mandiant's capa (static: it disassembles the file, never runs it) and
reports the capabilities it finds, each with the ATT&CK techniques capa's
rules map it to. On top of that, and deterministically (no model involved),
it places those techniques on ATT&CK's Enterprise tactic chain:

  tactic_chain          the 14 tactics in ATT&CK order, each marked observed
                        or not, with the technique IDs behind it
  furthest_tactic       the observed tactic latest in that order
  look_for_next         later tactics with no evidence in this file: where
                        ATT&CK says an intrusion usually goes next, so what to
                        look for in other files, the network and the host

What this can and cannot say (also sent to the model in `limitations`):
  - a capability present in the code is not proof that it runs
  - one file is usually one stage of an intrusion (droppers, loaders and
    payloads are often separate files), so look_for_next is a checklist from
    ATT&CK's order, not a prediction about this attacker
  - packed files hide their code: capa then finds little until unpacked

Settings (environment variables):
    MALWORN_CAPA          capa executable (default: `capa` on PATH)
    MALWORN_CAPA_RULES    rules folder (needed for the pip version; the
                          standalone capa binary, as on REMnux, has them built in)
    MALWORN_CAPA_SIGS     library-signature folder (pip version)
    MALWORN_CAPA_TIMEOUT  seconds (default 180)
"""

import json
import os
import re
import shutil
import subprocess

from malworn.contract import ToolSpec, failure, skipped, success

SPEC = ToolSpec(
    name="capa",
    description=("Find capabilities in the program's code with Mandiant capa (static; the file is never "
                 "run) and map them to MITRE ATT&CK techniques and tactics. Places the observed tactics on "
                 "ATT&CK's tactic chain (where this file's capabilities sit in an intrusion) and lists the "
                 "later tactics with no evidence in this file as what to look for next. Windows PE files."),
    data_keys=("capa_version", "capability_count", "capabilities", "attack_techniques", "tactic_chain",
               "observed_tactics", "furthest_tactic", "look_for_next", "packed_limitation",
               "limitations", "summary"),
    requirement="FR12",
    owner="Saood",
)

# MITRE ATT&CK Enterprise tactics in their matrix order.
TACTIC_ORDER = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)
# What each later tactic would look like, for the analyst's checklist.
LOOK_FOR = {
    "Persistence": "autostart entries (Run keys, services, scheduled tasks) on the host",
    "Privilege Escalation": "attempts to gain higher privileges (token manipulation, UAC bypass)",
    "Defense Evasion": "hiding or disabling defences (injection, unhooking, log tampering)",
    "Credential Access": "credential theft (LSASS access, browser or credential-store reads)",
    "Discovery": "system, network or account enumeration",
    "Lateral Movement": "spread to other hosts (remote services, shares, remote execution)",
    "Collection": "gathering data (screenshots, keystrokes, files, clipboard)",
    "Command and Control": "network contact with a controller: domains, IPs or URLs in other files or traffic",
    "Exfiltration": "data leaving the network (uploads, unusual outbound transfers)",
    "Impact": "destructive or disruptive actions (encryption, deletion, service stops)",
}
MAX_CAPABILITIES = 60
TIMEOUT = 180
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _command(file_path):
    exe = os.environ.get("MALWORN_CAPA") or shutil.which("capa")
    if not exe:
        return None
    cmd = [exe, "--json"]
    if os.environ.get("MALWORN_CAPA_RULES"):
        cmd += ["-r", os.environ["MALWORN_CAPA_RULES"]]
    if os.environ.get("MALWORN_CAPA_SIGS"):
        cmd += ["-s", os.environ["MALWORN_CAPA_SIGS"]]
    return cmd + [str(file_path)]


def _last_error_line(stderr):
    lines = [" ".join(_ANSI.sub("", l).split()) for l in (stderr or "").splitlines()]
    lines = [l for l in lines if l and not set(l) <= set("-─ ")]
    for l in reversed(lines):
        if "error" in l.lower() or "unsupported" in l.lower() or "not supported" in l.lower():
            return l[:300]
    return lines[-1][:300] if lines else "no error message"


def parse(doc):
    """Turn capa's JSON document into this tool's data (pure function, tested without capa)."""
    rules = doc.get("rules") or {}
    capabilities, techniques, packed = [], {}, False
    for name, rule in rules.items():
        meta = rule.get("meta") or {}
        namespace = meta.get("namespace") or ""
        if namespace.startswith("internal/limitation"):
            if "pack" in name.lower() or "pack" in namespace:
                packed = True
            continue
        if meta.get("lib") or namespace.startswith("internal/"):
            continue     # helper rules, not capabilities
        attack_ids = []
        for a in meta.get("attack") or []:
            tid = a.get("id")
            if not tid:
                continue
            attack_ids.append(tid)
            t = techniques.setdefault(tid, {"id": tid, "tactic": a.get("tactic"),
                                            "technique": a.get("technique"),
                                            "subtechnique": a.get("subtechnique") or None, "capabilities": []})
            t["capabilities"].append(name)
        capabilities.append({"name": name, "namespace": namespace or None,
                             "matches": len(rule.get("matches") or []), "attack": attack_ids})
    capabilities.sort(key=lambda c: (not c["attack"], c["namespace"] or "~", c["name"]))

    by_tactic = {}
    for t in techniques.values():
        by_tactic.setdefault(t["tactic"], []).append(t["id"])
    known = [x for x in TACTIC_ORDER]
    extra = sorted(x for x in by_tactic if x not in TACTIC_ORDER)
    chain = [{"tactic": x, "observed": x in by_tactic, "techniques": sorted(by_tactic.get(x, []))}
             for x in known + extra]
    observed = [c["tactic"] for c in chain if c["observed"]]
    order = {x: i for i, x in enumerate(TACTIC_ORDER)}
    in_order = [x for x in observed if x in order]
    furthest = max(in_order, key=order.get) if in_order else None
    if furthest:
        later = TACTIC_ORDER[order[furthest] + 1:]
    else:
        later = ()
    look_for_next = [{"tactic": x, "look_for": LOOK_FOR.get(x)} for x in later if x not in observed]

    limitations = ["A capability present in the code is not proof that it runs.",
                   "One file is often one stage of an intrusion; look_for_next follows ATT&CK's tactic "
                   "order and is a checklist, not a prediction about this attacker."]
    if packed:
        limitations.insert(0, "capa reports the file appears packed: most of its code is hidden, so "
                              "capabilities are incomplete until it is unpacked.")
    if observed:
        summary = (f"{len(capabilities)} capabilities; ATT&CK tactics observed: {', '.join(observed)}"
                   + (f"; furthest along the chain: {furthest}." if furthest else "."))
    else:
        summary = f"{len(capabilities)} capabilities; none map to an ATT&CK technique."
    return {
        "capa_version": (doc.get("meta") or {}).get("version"),
        "capability_count": len(capabilities),
        "capabilities": capabilities[:MAX_CAPABILITIES],
        "attack_techniques": sorted(techniques.values(), key=lambda t: (order.get(t["tactic"], 99), t["id"])),
        "tactic_chain": chain,
        "observed_tactics": observed,
        "furthest_tactic": furthest,
        "look_for_next": look_for_next,
        "packed_limitation": packed,
        "limitations": limitations,
        "summary": summary,
    }


def run(file_path):
    try:
        with open(file_path, "rb") as fh:
            if fh.read(2) != b"MZ":
                return skipped(SPEC, "capa analyses Windows executables; this file has no MZ header")
    except OSError as exc:
        return failure(SPEC, f"Could not read the file: {exc}")
    cmd = _command(file_path)
    if cmd is None:
        return failure(SPEC, "capa is not installed (set MALWORN_CAPA or put capa on PATH)")
    timeout = int(os.environ.get("MALWORN_CAPA_TIMEOUT", TIMEOUT))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return failure(SPEC, f"capa did not finish within {timeout} seconds")
    except OSError as exc:
        return failure(SPEC, f"capa could not be started: {exc}")
    try:
        doc = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return failure(SPEC, f"capa failed (exit {proc.returncode}): {_last_error_line(proc.stderr)}")
    data = parse(doc)
    warnings = ["capa reports the file appears packed; unpack it for a fuller capability list."] \
        if data["packed_limitation"] else []
    return success(SPEC, data, warnings)
