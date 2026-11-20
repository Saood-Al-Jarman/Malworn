#!/usr/bin/env bash
# Turn a trained LoRA adapter into a small GGUF adapter that Ollama loads on top of
# the qwen3:8b it already has (~200 MB instead of a 16 GB merged model + 16 GB GGUF).
# Run INSIDE WSL2 Ubuntu, from the repo folder, with the training env active:
#     source ~/malworn-ft/bin/activate
#     bash scripts/wsl_export_adapter.sh runs/qlora_trial
# Then on Windows (PowerShell, in the same folder):
#     ollama create malworn-trial -f runs/qlora_trial/Modelfile
set -euo pipefail
cd "$(dirname "$0")/.."
RUN="${1:?usage: bash scripts/wsl_export_adapter.sh runs/<run-folder>}"
NAME="${2:-$(basename "$RUN")}"
ADAPTER="$RUN/adapter"
[ -f "$ADAPTER/adapter_config.json" ] || { echo "FAIL: no adapter in $ADAPTER"; exit 1; }

LLAMA="$HOME/llama.cpp-src"
if [ ! -f "$LLAMA/convert_lora_to_gguf.py" ]; then
  echo "== Getting llama.cpp's conversion scripts (once)"
  git clone --depth 1 https://github.com/ggml-org/llama.cpp "$LLAMA"
fi
python -c "import gguf" 2>/dev/null || uv pip install -e "$LLAMA/gguf-py"

echo "== Converting the adapter to GGUF"
python "$LLAMA/convert_lora_to_gguf.py" "$ADAPTER" --base-model-id Qwen/Qwen3-8B \
  --outtype f16 --outfile "$RUN/adapter.gguf"

WIN_PATH=$(wslpath -w "$(realpath "$RUN/adapter.gguf")")
cat > "$RUN/Modelfile" <<M
# Base model already in Ollama + the Malworn adapter. The chat template and tool
# calling come from qwen3:8b, unchanged.
FROM qwen3:8b
ADAPTER $WIN_PATH
M
echo "== Done: $RUN/adapter.gguf ($(du -h "$RUN/adapter.gguf" | cut -f1))"
echo "Now in PowerShell:  cd $(wslpath -w "$(pwd)")"
echo "                    ollama create malworn-$NAME -f $RUN/Modelfile"
