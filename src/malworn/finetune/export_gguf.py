"""Export a trained adapter as ONE merged Q4_K_M GGUF that Ollama can load.

Owner: Saood

Ollama no longer accepts LoRA adapters (`ADAPTER` in a Modelfile), so the
adapter is merged into Qwen 3 8B and quantised to Q4_K_M, the same
quantisation as the base `qwen3:8b`, which keeps base-vs-tuned comparisons fair.

Run in WSL2 with the training env active (no retraining; ~15-25 min; needs
~40 GB free on the output drive while it runs, ~5 GB after clean-up):

    python -m malworn.finetune.export_gguf runs/qlora_trial

Writes <run>/merged/<name>.Q4_K_M.gguf and deletes the 16-bit intermediates
(merged safetensors and the BF16 GGUF). Then, in PowerShell, build the Ollama
model with qwen3:8b's own template so tool calling is unchanged:

    (ollama show qwen3:8b --modelfile) -replace '^FROM .*', 'FROM <path to the .gguf>' | Set-Content Modelfile.merged
    ollama create malworn-<name> -f Modelfile.merged

(the script prints both lines with the right path).
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m malworn.finetune.export_gguf",
                                 description=__doc__.split("\n\n")[0])
    ap.add_argument("run", help="training run folder containing adapter/ (e.g. runs/qlora_trial)")
    ap.add_argument("--quant", default="q4_k_m", help="quantisation (default: %(default)s, like qwen3:8b)")
    ap.add_argument("--keep-16bit", action="store_true", help="keep the 16-bit intermediates (~32 GB)")
    args = ap.parse_args(argv)

    run = Path(args.run)
    adapter = run / "adapter"
    if not (adapter / "adapter_config.json").is_file():
        print(f"error: no adapter in {adapter}", file=sys.stderr)
        return 2
    free_gb = shutil.disk_usage(run).free / 1024 ** 3
    if free_gb < 40:
        print(f"error: only {free_gb:.0f} GB free on the output drive; the export needs ~40 GB while it runs",
              file=sys.stderr)
        return 2

    try:
        from unsloth import FastLanguageModel
    except ImportError as exc:
        print(f"error: {exc}. Activate the training env first (source ~/malworn-ft/bin/activate).",
              file=sys.stderr)
        return 2

    out = run / "merged"
    model, tokenizer = FastLanguageModel.from_pretrained(model_name=str(adapter), max_seq_length=8192,
                                                         load_in_4bit=True)
    model.save_pretrained_gguf(str(out), tokenizer, quantization_method=args.quant)

    candidates = sorted(p for p in run.rglob("*.gguf") if args.quant.lower() in p.name.lower())
    if not candidates:
        print(f"error: export finished but no {args.quant} GGUF was found under {run}", file=sys.stderr)
        return 1
    gguf = candidates[0]
    if not args.keep_16bit:
        for p in list(run.rglob("*.gguf")):
            if p != gguf and ("bf16" in p.name.lower() or p.name.lower().endswith(".f16.gguf")):
                p.unlink(missing_ok=True)
        for p in out.glob("*.safetensors"):
            p.unlink(missing_ok=True)
    size_gb = gguf.stat().st_size / 1024 ** 3
    try:
        win = subprocess.run(["wslpath", "-w", str(gguf.resolve())], capture_output=True, text=True,
                             check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        win = str(gguf.resolve())
    name = run.name.replace("qlora_", "")
    print(f"\n[malworn] merged model: {gguf} ({size_gb:.1f} GB)")
    print("[malworn] now in PowerShell, in the repo folder:")
    print(f"  (ollama show qwen3:8b --modelfile) -replace '^FROM .*', 'FROM {win}' | Set-Content Modelfile.merged")
    print(f"  ollama create malworn-{name} -f Modelfile.merged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
