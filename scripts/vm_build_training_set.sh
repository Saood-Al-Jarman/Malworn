#!/usr/bin/env bash
# Malworn fine-tuning: build the training set INSIDE the REMnux VM, so the examples come from
# exactly the tools the app runs (DIE, capa, the VirusTotal bridge).
#     bash scripts/vm_build_training_set.sh ~/malworn-train.zip     (or the unzipped malworn-train folder)
# Unzips the benign training files, adds UPX-packed copies of up to 14 of the .exe files, writes
# a manifest (all "train"), and runs the dataset builder with the default prompt, real
# VirusTotal lookups (hash only) and the test-hash exclusion list. Output: data/finetune/.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:?usage: bash scripts/vm_build_training_set.sh <malworn-train.zip or the malworn-train folder>}"
WORK="$HOME/malworn-train"
PER_FILE="${PER_FILE:-5}"

if [ "${MALWORN_VT_MODE:-}" = "mock" ]; then
  echo "FAIL: MALWORN_VT_MODE=mock is set; run  unset MALWORN_VT_MODE  so VirusTotal answers are real"; exit 1
fi
command -v upx >/dev/null || { echo "FAIL: upx not found"; exit 1; }
command -v capa >/dev/null || [ -n "${MALWORN_CAPA:-}" ] || { echo "FAIL: capa not found"; exit 1; }
CHECK=$(PYTHONPATH=src python3 -m malworn.app.check 2>&1 || true)
echo "$CHECK"
for need in "VirusTotal" "Detect It Easy" "capa"; do
  if echo "$CHECK" | grep -q "\[FAIL\] $need"; then
    echo "FAIL: $need must be ok for the training set (the Model line doesn't matter here)."
    [ "$need" = "VirusTotal" ] && echo "      On Windows start the bridge:  cd \$HOME\\Malworn; \$env:PYTHONPATH=\"src\"; python -m malworn.agent.vt_bridge"
    exit 1
  fi
done

rm -rf "$WORK" && mkdir -p "$WORK/packed"
if [ -d "$SRC" ]; then
  cp "$SRC"/* "$WORK"/
elif [ -f "$SRC" ]; then
  unzip -q "$SRC" -d "$WORK"
else
  echo "FAIL: $SRC is neither a folder nor a zip file"; exit 1
fi
n=0
for f in "$WORK"/*.exe; do
  [ $n -ge 14 ] && break
  base=$(basename "$f" .exe)
  case $((n % 3)) in 0) opt="" ;; 1) opt="--best" ;; 2) opt="--lzma" ;; esac
  out="$WORK/packed/${base}_upx.exe"
  # Windows programs are built with Control Flow Guard, which UPX refuses without --force.
  # Fine here: the packed copies are only analysed, never run.
  if upx -q $opt -o "$out" "$f" >/dev/null 2>"$WORK/upx_err.txt" \
     || { rm -f "$out"; upx -q --force $opt -o "$out" "$f" >/dev/null 2>>"$WORK/upx_err.txt"; }; then
    n=$((n+1))
  else
    rm -f "$out"
    echo "  upx could not pack $(basename "$f"): $(tail -1 "$WORK/upx_err.txt" | cut -c1-120)"
  fi
done
echo "Made $n UPX copies"
if [ "$n" -lt 5 ]; then
  echo "FAIL: fewer than 5 packed copies; the training set needs packed examples (see the upx messages above)"
  exit 1
fi

MANIFEST="$WORK/manifest.csv"
echo "path,split" > "$MANIFEST"
for f in "$WORK"/*.exe "$WORK"/*.dll "$WORK"/packed/*.exe; do [ -f "$f" ] && echo "$f,train" >> "$MANIFEST"; done
echo "$(($(wc -l < "$MANIFEST") - 1)) training files"

PYTHONPATH=src python3 -m malworn.finetune.build_dataset "$MANIFEST" --out data/finetune \
  --exclude-hashes data/test_hashes.txt --per-file "$PER_FILE"
cut -d, -f1 "$MANIFEST" | tail -n +2 | xargs sha256sum > data/finetune/train_hashes.txt
echo "Done. Training-file hashes in data/finetune/train_hashes.txt (to keep test files separate)."
