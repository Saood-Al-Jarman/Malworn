"""QLoRA fine-tuning of Qwen 3 8B on the Malworn dataset (M9), with Unsloth.

Owner: Saood

Runs on the Windows host's RTX 3060 (12 GB) inside WSL2, never in the VM.
Start with the smoke test: it trains on the 10 LONGEST examples for 10 steps and
reports peak GPU memory, which answers "does 8B fit in 12 GB?" in minutes.

    python -m malworn.finetune.train_qlora data/finetune --smoke
    python -m malworn.finetune.train_qlora data/finetune --out runs/qlora_v1
    python -m malworn.finetune.train_qlora data/finetune --out runs/qlora_v1 --gguf

What it does:
  - loads Qwen 3 8B in 4-bit (NF4) and adds LoRA adapters (rank 16) to every
    attention and MLP projection
  - renders each example with Qwen's own chat template, including the tool
    definitions, tool calls and tool results, exactly as at inference
  - trains ONLY on the assistant turns (tool calls and answers): the system
    prompt, question and tool results are context, not targets
  - evaluates on val.jsonl (other files than training) every epoch
  - saves the adapter (~180 MB). For Ollama, convert it with
    scripts/wsl_export_adapter.sh (a small GGUF adapter on top of qwen3:8b);
    --gguf instead writes a full merged model (needs ~35 GB of free disk)

Setup (WSL2 Ubuntu, NVIDIA driver on Windows): see docs/finetune.md.
"""

import argparse
import json
import sys
import time
from pathlib import Path

BASE_MODEL = "unsloth/Qwen3-8B"
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def to_text(tokenizer, record):
    """One example as the exact text Qwen sees (chat template with tools)."""
    return tokenizer.apply_chat_template(record["messages"], tools=record.get("tools"), tokenize=False,
                                         add_generation_prompt=False)


def fit_examples(tokenizer, records, max_len):
    """Render the examples and drop any longer than max_len tokens (they'd be cut)."""
    kept, dropped = [], 0
    for r in records:
        text = to_text(tokenizer, r)
        if len(tokenizer(text, add_special_tokens=False)["input_ids"]) > max_len:
            dropped += 1
            continue
        kept.append({"text": text})
    return kept, dropped


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m malworn.finetune.train_qlora", description=__doc__.split("\n\n")[0])
    ap.add_argument("data", help="folder with train.jsonl and val.jsonl (from build_dataset)")
    ap.add_argument("--out", default="runs/qlora")
    ap.add_argument("--smoke", action="store_true", help="10 longest examples, 10 steps: memory and speed check")
    ap.add_argument("--base", default=BASE_MODEL)
    ap.add_argument("--max-len", type=int, default=8192, help="max tokens per example (default %(default)s)")
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--grad-accum", type=int, default=8, help="examples per update (batch size is 1)")
    ap.add_argument("--gguf", action="store_true",
                    help="also export a merged Q4_K_M GGUF (needs ~35 GB free disk; usually use "
                         "scripts/wsl_export_adapter.sh instead)")
    ap.add_argument("--seed", type=int, default=3407)
    args = ap.parse_args(argv)

    try:
        from unsloth import FastLanguageModel                  # import first: it patches transformers
        from unsloth.chat_templates import train_on_responses_only
        import torch
        from datasets import Dataset
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        print(f"error: {exc}. Install the training stack first (docs/finetune.md).", file=sys.stderr)
        return 2
    if not torch.cuda.is_available():
        print("error: no CUDA GPU visible. Run this in WSL2 with the NVIDIA driver installed.", file=sys.stderr)
        return 2

    data = Path(args.data)
    train_records, val_records = load_jsonl(data / "train.jsonl"), load_jsonl(data / "val.jsonl")
    if args.smoke:
        train_records = sorted(train_records, key=lambda r: len(json.dumps(r["messages"])), reverse=True)[:10]
        val_records = val_records[:2]

    model, tokenizer = FastLanguageModel.from_pretrained(model_name=args.base, max_seq_length=args.max_len,
                                                         load_in_4bit=True, dtype=None)
    model = FastLanguageModel.get_peft_model(model, r=args.rank, lora_alpha=args.rank, lora_dropout=0,
                                             target_modules=TARGET_MODULES, bias="none",
                                             use_gradient_checkpointing="unsloth", random_state=args.seed)

    train_rows, dropped = fit_examples(tokenizer, train_records, args.max_len)
    val_rows, val_dropped = fit_examples(tokenizer, val_records, args.max_len)
    print(f"[malworn] {len(train_rows)} train / {len(val_rows)} validation examples "
          f"({dropped + val_dropped} dropped as longer than {args.max_len} tokens)", file=sys.stderr)
    if not train_rows:
        print("error: no training examples left", file=sys.stderr)
        return 2

    config = SFTConfig(
        output_dir=args.out, dataset_text_field="text", max_seq_length=args.max_len,
        per_device_train_batch_size=1, gradient_accumulation_steps=1 if args.smoke else args.grad_accum,
        num_train_epochs=args.epochs, max_steps=10 if args.smoke else -1,
        learning_rate=args.lr, lr_scheduler_type="cosine", warmup_ratio=0.05,
        optim="adamw_8bit", weight_decay=0.01, logging_steps=1 if args.smoke else 5,
        eval_strategy="no" if args.smoke or not val_rows else "epoch",
        save_strategy="no", seed=args.seed, report_to="none",   # only the final adapter is kept
        bf16=torch.cuda.is_bf16_supported(), fp16=not torch.cuda.is_bf16_supported(),
    )
    trainer = SFTTrainer(model=model, tokenizer=tokenizer, args=config,
                         train_dataset=Dataset.from_list(train_rows),
                         eval_dataset=Dataset.from_list(val_rows) if val_rows else None)
    # Learn only the assistant turns. Qwen wraps tool results in user turns, so
    # they are masked too.
    trainer = train_on_responses_only(trainer, instruction_part="<|im_start|>user\n",
                                      response_part="<|im_start|>assistant\n")

    torch.cuda.reset_peak_memory_stats()
    started = time.monotonic()
    stats = trainer.train()
    seconds = time.monotonic() - started
    peak = torch.cuda.max_memory_reserved() / 1024 ** 3
    total = torch.cuda.get_device_properties(0).total_memory / 1024 ** 3
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {"smoke": args.smoke, "base": args.base, "train_examples": len(train_rows),
               "val_examples": len(val_rows), "dropped_too_long": dropped + val_dropped,
               "max_len": args.max_len, "rank": args.rank, "epochs": args.epochs, "lr": args.lr,
               "seconds": round(seconds, 1), "seconds_per_step": round(seconds / max(stats.global_step, 1), 1),
               "peak_gpu_gb": round(peak, 2), "gpu_total_gb": round(total, 2),
               "final_train_loss": round(stats.training_loss, 4), "log": trainer.state.log_history}
    (out / "train_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[malworn] {stats.global_step} steps in {seconds:.0f} s ({summary['seconds_per_step']} s/step); "
          f"peak GPU memory {peak:.1f} of {total:.1f} GB; train loss {stats.training_loss:.3f}", file=sys.stderr)
    if args.smoke:
        full = len(load_jsonl(data / "train.jsonl"))
        est = summary["seconds_per_step"] * full * args.epochs / 60
        print(f"[malworn] smoke test passed. A full run on {full} examples x {args.epochs} epochs "
              f"would take roughly {est:.0f} minutes.", file=sys.stderr)
        return 0

    model.save_pretrained(out / "adapter")
    tokenizer.save_pretrained(out / "adapter")
    print(f"[malworn] adapter saved to {out / 'adapter'}", file=sys.stderr)
    if args.gguf:
        model.save_pretrained_gguf(str(out / "gguf"), tokenizer, quantization_method="q4_k_m")
        print(f"[malworn] GGUF saved under {out / 'gguf'}; see docs/finetune.md to load it into Ollama",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
