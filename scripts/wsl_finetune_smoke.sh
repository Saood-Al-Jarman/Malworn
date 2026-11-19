#!/usr/bin/env bash
# M9 smoke test: does QLoRA on Qwen 3 8B fit on this GPU?
# Run INSIDE WSL2 Ubuntu on the Windows host, from the repo folder:
#     cd /mnt/c/Users/<you>/Malworn && bash scripts/wsl_finetune_smoke.sh
# Needs data/finetune/train.jsonl and val.jsonl (from malworn.finetune.build_dataset).
# Everything it prints also goes to runs/smoke/smoke_log.txt.
set -u
cd "$(dirname "$0")/.."
mkdir -p runs/smoke
LOG=runs/smoke/smoke_log.txt
exec > >(tee "$LOG") 2>&1
echo "== $(date -Is) Malworn QLoRA smoke test"

echo "== GPU"
if ! nvidia-smi; then
  echo "FAIL: nvidia-smi does not work in WSL. Update the NVIDIA driver on Windows, then 'wsl --shutdown' and retry."
  exit 1
fi

echo "== Python 3.12 environment (via uv, no sudo needed)"
VENV="$HOME/malworn-ft"
if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh || { echo "FAIL: could not install uv"; exit 1; }
fi
export PATH="$HOME/.local/bin:$PATH"
if [ ! -x "$VENV/bin/python" ] || ! "$VENV/bin/python" -c "import sys; assert sys.version_info[:2] == (3, 12)" 2>/dev/null; then
  rm -rf "$VENV"
  uv venv --python 3.12 --seed "$VENV" || { echo "FAIL: uv could not create a Python 3.12 environment"; exit 1; }
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python --version

echo "== Installing the training stack (first run only, several GB)"
python -c "import unsloth" 2>/dev/null || uv pip install unsloth || { echo "FAIL: pip install unsloth"; exit 1; }

echo "== Data"
for f in data/finetune/train.jsonl data/finetune/val.jsonl; do
  [ -f "$f" ] || { echo "FAIL: $f missing"; exit 1; }
  echo "$f: $(wc -l < "$f") examples"
done

echo "== Smoke test (10 longest examples, 10 steps)"
export PYTHONPATH=src
python -m malworn.finetune.train_qlora data/finetune --smoke --out runs/smoke
status=$?
echo "== exit status $status"
[ -f runs/smoke/train_summary.json ] && python - <<'P'
import json; s = json.load(open("runs/smoke/train_summary.json"))
print({k: s[k] for k in ("peak_gpu_gb", "gpu_total_gb", "seconds_per_step", "final_train_loss", "max_len")})
P
exit $status
