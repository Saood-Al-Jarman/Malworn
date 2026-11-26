#!/usr/bin/env bash
# Malworn fine-tuning: build the training set INSIDE the REMnux VM, so the examples come from
# exactly the tools the app runs (DIE, capa, the VirusTotal bridge).
#     bash scripts/vm_build_training_set.sh ~/malworn-train.zip
# Unzips the benign training files, adds UPX-packed copies of up to 14 of the .exe files, writes
# a manifest (all "train"), and runs the dataset builder with the default prompt, real
# VirusTotal lookups (hash only) and the test-hash exclusion list. Output: data/finetune/.
set -euo pipefail
cd "$(dirname "$0")/.."
ZIP="${1:?usage: bash scripts/vm_build_training_set.sh <path to malworn-train.zip>}"
WORK="$HOME/malworn-train"
PER_FILE="${PER_FILE:-5}"

if [ "${MALWORN_VT_MODE:-}" = "mock" ]; then
  echo "FAIL: MALWORN_VT_MODE=mock is set; run  unset MALWORN_VT_MODE  so VirusTotal answers are real"; exit 1
fi
command -v upx >/dev/null || { echo "FAIL: upx not found"; exit 1; }
command -v capa >/dev/null || [ -n "${MALWORN_CAPA:-}" ] || { echo "FAIL: capa not found"; exit 1; }
PYTHONPATH=src python3 -m malworn.app.check || echo "(Model may show FAIL: the build does not need Ollama. VirusTotal, Detect It Easy and capa must be ok.)"

rm -rf "$WORK" && mkdir -p "$WORK/packed"
unzip -q "$ZIP" -d "$WORK"
n=0
for f in "$WORK"/*.exe; do
  [ $n -ge 14 ] && break
  base=$(basename "$f" .exe)
  case $((n % 3)) in 0) opt="" ;; 1) opt="--best" ;; 2) opt="--lzma" ;; esac
  if upx -q $opt -o "$WORK/packed/${base}_upx.exe" "$f" >/dev/null 2>&1; then n=$((n+1)); fi
done
echo "Made $n UPX copies"

MANIFEST="$WORK/manifest.csv"
echo "path,split" > "$MANIFEST"
for f in "$WORK"/*.exe "$WORK"/*.dll "$WORK"/packed/*.exe; do [ -f "$f" ] && echo "$f,train" >> "$MANIFEST"; done
echo "$(($(wc -l < "$MANIFEST") - 1)) training files"

PYTHONPATH=src python3 -m malworn.finetune.build_dataset "$MANIFEST" --out data/finetune \
  --exclude-hashes data/test_hashes.txt --per-file "$PER_FILE"
cut -d, -f1 "$MANIFEST" | tail -n +2 | xargs sha256sum > data/finetune/train_hashes.txt
echo "Done. Training-file hashes in data/finetune/train_hashes.txt (to keep test files separate)."
