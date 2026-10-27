# malworn.packing  (owner: Viha)

**Scope: detect only, with evidence.** Decides whether a Windows PE file looks
packed, which sections look packed, and lists ALL the evidence for and against.
It never unpacks or executes anything. If packing is suspected, the user is
asked to unpack the sample and re-upload it.

## Fully offline
- No network access and no rule downloads. The ONLY external program is Detect It Easy (`diec`), a local
  binary already installed in the REMnux VM; only `die.py` starts it.
- Thresholds: `THRESHOLDS` in `indicators.py`. Signatures and name patterns:
  bundled in `signatures.py` / `indicators.py`. A pure-Python matcher replaces YARA.
- Required dependency: `pefile` (pure Python). Optional: `capstone` (instruction-structure
  check) and `yara-python` (local rule files only). Missing optional pieces switch off cleanly
  and the output says so (`optional_checks`). To install on a machine with no internet,
  run `pip download pefile -d wheels/` once on a connected machine, copy `wheels/`
  over, then `pip install --no-index --find-links wheels/ pefile`.
  (`pefile` is a single MIT-licensed file, so you can also vendor it.)
- `tests/test_packing_indicators.py` blocks sockets and scans the source to prove it.

## Interface (for the agent / app)
    from malworn.packing.indicators import analyze
    result = analyze("sample.exe")          # dict, JSON-serialisable

| field | meaning |
|---|---|
| `user_message` | analyst-facing evidence report (see below). Quote it; do not paraphrase claims away from it |
| `needs_unpacking` | True if level is `possible`/`likely` |
| `packing_indicators_level` | `none_detected` / `possible` / `likely`. NOT a malware verdict (FR7) |
| `score` | total points; `possible` >= 3, `likely` >= 6 |
| `evidence_for` | every indicator that adds points: `id, value, threshold, points, severity, location, why, source` |
| `evidence_weak` | low-severity observations (0 points) |
| `counter_evidence` | what was checked and looked NORMAL (so "clean" is evidence-backed too) |
| `suspected_packers` | packer name + the evidence ids that support it |
| `packed_sections` / `section_assessments` | per-section level, points and reasons |
| `high_entropy_regions` | byte ranges, mapped onto sections (or `overlay`) |
| `indicators` | everything, including info-only items |
| `error` | present instead of the above if the file is not a valid PE |

`user_message` contains: the verdict line; evidence for (value, threshold, points,
location, why); weak observations; suspected packers; sections that look packed;
evidence against; how the score became a level; and, if packed, the request to
unpack and re-upload.

## Run
    python -m malworn.packing.indicators sample.exe            # full JSON
    python -m malworn.packing.indicators sample.exe --message  # evidence report only
    python -m malworn.packing.batch_detect --samples <dir> --out <csv> --truth packed|clean
    pytest tests/test_packing_indicators.py

## Adding a rule
Add an entry to `SIGNATURES` (`signatures.py`) with `source` and `verified`, plus a
test. `verified=True` only if you reproduced it on real packer output in the lab.
Entries marked `verified=False` (PackGenome paper rules, generic heuristics) and the
section-name patterns not seen in the supplied papers must be checked before you
rely on them.

## Safety
Samples only inside the isolated Linux VM. Never commit samples or batch output.
The tests build fake PE files in code; nothing binary is committed.

## Known limitations (state these in the report)
- Section names, entry-point bytes and markers are easy for adversaries to change.
- Low-entropy packers evade entropy checks; structure checks may still fire.
- Thresholds and point weights are starting points, not tuned values (NFR9).
- "Looks packed" is not "is malicious". PE (x86/x64) only.
- Tested on synthetic PEs and UPX 4.2.4 output only, not real packed malware.


## Known and unknown packers (what the output says)
`packer_classification.status`:
| status | meaning | papers it follows |
|---|---|---|
| `known_packer` | section names and byte signatures agree on one packer | PackGenome (unpacking-stub signatures); Ugarte-Pedrero names |
| `known_packer_modified_variant` | a stub signature matches but names/markers are gone | PackGenome: custom UPX variants reuse the original unpacking code |
| `known_packer_weak` | only a name or marker string | names are trivially forged (APT41 example) |
| `unknown_packer` | looks packed (entropy / layout / instruction structure) but nothing names a packer | generic packed-data detection: entropy papers, Pack-ALM |
| `none_detected` | no convincing evidence | |

## Paper tool code: what can run offline here
| Tool | Offline use | Status |
|---|---|---|
| PackGenome rules | Rules are in the authors' Zenodo artifact (record 10030074). Download on a connected machine, copy `.yar` files into `rules/`, install `yara-python`. Check licence first. | Supported through `yara_rules.py`; not tested with the real rules |
| PackGenome generator | Needs Intel Pin, dynamic analysis, large Docker image | Not integrated (dynamic; out of scope) |
| PackHero | Repo exists (github.com/necst/packhero); conda + CUDA/torch + radare2, ~2 GB, no licence file seen | Not integrated; could be run separately as a second opinion |
| Pack-ALM | Released on Zenodo (not reachable from our sandbox); RoBERTa/fairseq + training data | Not integrated; `structure.py` is a lightweight CPU alternative, NOT a reimplementation |
| Entropy heuristics, section/EP/import features (Bertrand, Alkhateeb, Lyda) | Reimplemented in `indicators.py` | Done |

## Research position (read before writing the paper)
Reimplemented from the papers: entropy thresholds, section/entry-point/import indicators,
signature and name matching, windowed entropy. This is NOT new on its own.

Candidate contributions, in order of how well the evidence supports them today:
1. **Structure vs entropy on low-entropy packing (preliminary result, needs Windows data).**
   Proxy test on Linux x86-64 benign code (train/test disjoint, 2,048-byte windows):
   entropy>=7.0 detected 0% of byte-substituted, shuffled and base64-encoded windows;
   a bigram instruction-structure model trained only on benign code detected 100% at 7%
   false positives on benign code. BUT it flagged 100% of benign non-code data (.rodata),
   so it is only valid for executable sections. Next steps: repeat on benign Windows PEs
   with `experiments/entropy_vs_structure.py`, then on real low-entropy and real packed
   samples, and compare against Pack-ALM's published numbers or code.
2. **Packing-aware agent behaviour (system-level).** The papers evaluate detectors, not what
   packing detection does to a downstream LLM analyst. Hypothesis: gating other static
   findings on `static_evidence_reliability` reduces unsupported claims on packed samples.
   Needs an experiment: same samples packed vs unpacked, agent with vs without the gate.
3. **Packing evidence as a feature for malware detection** (Hassan's stage), echoing
   ViPER's packing-aware idea but on tabular static features. Needs an experiment.
Novelty claims must be checked against the literature before you make them.


## Integration with the Malworn pipeline (read this, Saood)
Two aggregator-ready tools, same `run(file_path)` contract as `static_analysis.*`
(`{tool, status, data, warnings, provenance}`; `status` is `success`, `skipped` for non-PE, or `failure`):

| tool name | module | what it reports |
|---|---|---|
| `packer_signatures` | `malworn.packing.packer_signatures` | Detect It Easy detections, section-name matches, bundled byte signatures, optional local YARA |
| `packing_indicators` | `malworn.packing.packing_indicators` | per-section packing evidence, packer classification (known / modified / unknown), evidence for and against, `message_for_analyst` |

Registry helper: `malworn.packing.tools()`; ordered run: `malworn.packing.run_packing_checks(path)`
(returns the results in `PACKING_TOOL_ORDER`, ready for `aggregate_results`).

**Detect It Easy runs first.** Nothing else in the repo ran DIE, so the packing tools do: both call
`die.run_die(path)` before any other check, and it is cached per file, so DIE runs once whichever packing tool
the agent selects first. If `diec` is missing, the result carries a warning and the analyst message says DIE was
NOT run; nothing is silently skipped. Configure with `MALWORN_DIEC` (path) and `MALWORN_DIE_DB` (signature
folder, normally found automatically). Verified against DIE 3.21 (`diec --json --heuristicscan`).

**Report generator compatibility.** `packing_indicators.data.per_section` feeds the Sections table
(name, raw_size, virtual_size, entropy; extra fields appear under additional section fields). Virtual
addresses and imports are left to Ahmed's `sections` and `imports` tools. Values contain no NaN/Infinity
(aggregator uses `allow_nan=False`).

**Agent guidance.** Quote `message_for_analyst`; cite evidence ids; if `needs_unpacking` is true, ask the
analyst to unpack and re-upload; treat `static_evidence_reliability == "reduced"` as a reason to caveat the
`imports`/`strings` results.
