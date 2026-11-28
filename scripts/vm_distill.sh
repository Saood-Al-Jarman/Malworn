#!/usr/bin/env bash
# v3 training data (see src/malworn/finetune/distill.py): the base model answers questions about
# every training file and only answers that pass every check are kept. Run in the VM after
# scripts/vm_build_training_set.sh (it reuses ~/malworn-train and its manifest). Needs the model
# (Ollama on Windows), the VirusTotal bridge, Detect It Easy and capa. Takes several hours; if it
# stops, run it again: finished jobs are kept in data/finetune_v3/raw.jsonl and skipped.
#
#   bash scripts/vm_distill.sh            # or LIMIT=5 bash scripts/vm_distill.sh for a quick try
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="${WORK:-$HOME/malworn-train}"
export MALWORN_CAPA_TIMEOUT="${MALWORN_CAPA_TIMEOUT:-400}"
CHECK=$(PYTHONPATH=src python3 -m malworn.app.check 2>&1 || true)
echo "$CHECK"
for need in "Model" "VirusTotal" "Detect It Easy" "capa"; do
  if echo "$CHECK" | grep -q "\[FAIL\] $need"; then
    echo "FAIL: $need must be ok (the base model writes the answers here)."
    exit 1
  fi
done
[ -f "$WORK/manifest.csv" ] || { echo "FAIL: no $WORK/manifest.csv: run scripts/vm_build_training_set.sh first"; exit 1; }
PYTHONPATH=src python3 -m malworn.finetune.distill "$WORK/manifest.csv" --out data/finetune_v3 \
  --exclude-hashes data/test_hashes.txt --per-file "${PER_FILE:-5}" ${LIMIT:+--limit "$LIMIT"} ${RETRY:+--retry "$RETRY"}
echo "Done. Dataset in data/finetune_v3 (stats.md, train.jsonl, val.jsonl)."
