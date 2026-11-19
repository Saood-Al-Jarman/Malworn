# Fine-tuning Malworn's model (M9)

Goal: teach Qwen 3 8B to **call the tool instead of recommending it** (O3: 13 of 24 base-model
answers recommended a tool, VirusTotal in 10), while keeping the rules: cite every fact, no
verdict, "not available" when a tool fails, file text treated as data.

The steps run in this order. Steps 1–2 work anywhere with benign files; step 3 onwards needs the
Windows host's GPU (in WSL2), never the VM.

## 1. Build the dataset

```bash
# manifest.csv: path,split  (split from the corpus sheet; only "train" rows are used)
PYTHONPATH=src python3 -m malworn.finetune.build_dataset manifest.csv --out data/finetune \
    --exclude-hashes test_hashes.txt
```

- `test_hashes.txt`: one SHA-256 per line for every test file: every `test` row of the corpus
  and any malware test samples. The demo files `launcher.exe` and `launcher_upx.exe` are refused
  automatically.
- Run it with the **real VirusTotal bridge** (`unset MALWORN_VT_MODE`), or every VirusTotal answer
  will teach "no live lookup was made (mock mode)". Only hashes leave the machine.
- Files derived from real malware: build inside the VM; the output is sample-derived and stays
  with the local model.
- Add phrasings with `--questions extra.json` (`{"packed": ["...", "..."]}`); any phrasing too close
  to an O3 test question is dropped and listed in `stats.md`.

Every answer is generated from the real tool results and passed through `agent/verify.py`; the
build stops if one fails. Still **read 20 random examples** before training.

## 2. Check the size

`stats.md` gives the longest example in rough tokens. Above 8,192 tokens, examples are dropped by
the trainer; if many are, lower `--max-len` only after the smoke test shows memory to spare.

## 3. Set up the GPU (once)

In WSL2 Ubuntu on the Windows host (NVIDIA driver installed on Windows; `nvidia-smi` works in WSL):

```bash
python3 -m venv ~/ft && source ~/ft/bin/activate
pip install unsloth          # pulls torch, transformers, trl, peft, bitsandbytes
cd ~/Malworn && export PYTHONPATH=src
```

Stop Ollama on Windows while training (`ollama stop qwen3:8b`): it holds about 7.5 GB of the 12 GB.

## 4. Smoke test (answers "does 8B fit?")

```bash
python -m malworn.finetune.train_qlora data/finetune --smoke
```

It trains on the 10 longest examples for 10 steps and prints peak GPU memory and an estimate for
the full run. If it runs out of memory, retry with `--max-len 6144`, then `4096`. If 4096 still
fails, use the fallback (university GPU lab or a rented GPU) or `--base unsloth/Qwen3-4B` and
report the change.

## 5. Train

```bash
python -m malworn.finetune.train_qlora data/finetune --out runs/qlora_v1 --gguf
```

Defaults: rank 16, 2 epochs, learning rate 2e-4, effective batch 8. Watch `train_summary.json`:
validation loss should fall with training loss. If training loss keeps falling while validation
loss rises, it is memorising: use 1 epoch or more data.

## 6. Load into Ollama

Use the base model's template so tool calling works exactly as before:

```powershell
ollama show qwen3:8b --modelfile > Modelfile
# edit Modelfile: replace the FROM line with the GGUF path, e.g.
# FROM C:\path\to\runs\qlora_v1\gguf\unsloth.Q4_K_M.gguf
ollama create malworn-qwen3-8b-ft -f Modelfile
```

## 7. Compare base vs tuned (TC11, O5)

Same commands, `--model` changes only:

```bash
PYTHONPATH=src python3 -m malworn.agent.evaluate_questions FILES... --runs 2 --model qwen3:8b
PYTHONPATH=src python3 -m malworn.agent.evaluate_questions FILES... --runs 2 --model malworn-qwen3-8b-ft
```

Test files only. Report: correct tool selection, exact, answers recommending a tool instead of
calling it (read by hand, as on Nov 9), citing unrun tools, verdict language, and seconds. Run
TC10 (`evaluate_injection`) on both too: tuning must not weaken injection resistance.
