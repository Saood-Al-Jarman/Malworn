"""
malworn.packing.structure  -  instruction-structure ("code-likeness") scoring.

WHY THIS EXISTS
Entropy measures the byte DISTRIBUTION. Low-entropy packing tricks (byte
substitution, transposition, encoding; Mantovani et al.) keep or reduce entropy
while still hiding the code, so a threshold on entropy misses them. Pack-ALM
(Li et al., CCS 2025) observed that packed data, when disassembled, turns into
"pseudo instructions" (odd mnemonics, invalid bytes) while real code produces
plausible instruction sequences, and trained a RoBERTa model to tell them apart.

This module is a LIGHTWEIGHT, CPU-ONLY, INTERPRETABLE take on that idea:
  1. linear-sweep disassemble a window of bytes (capstone, offline);
  2. turn it into a mnemonic sequence ("(bad)" for undecodable bytes);
  3. score it with a mnemonic-BIGRAM model trained on benign code;
  4. call a window "not code-like" if its score falls below a threshold
     calibrated on benign windows.
It is NOT Pack-ALM (no learned embeddings, no fine-tuning on packed data) and
has not been shown to match it. See README "Research position".

OFFLINE: capstone is a local library; the model is a small JSON file you train
from benign binaries in your own lab (train_codeness.py). No network.

AI-assistance note (team norm): first draft generated with Claude (Anthropic).
"""

from __future__ import annotations

import json
import math
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

WINDOW = 2048            # bytes per window (also used for entropy in Pack-ALM Appx B)
MAX_WINDOWS_PER_SECTION = 400   # sample cap so huge sections stay fast
BAD = "(bad)"
START = "<s>"
SMOOTHING_K = 0.5

MODEL_ENV = "MALWORN_PACKING_MODELS"


def model_dir() -> Path:
    return Path(os.environ.get(MODEL_ENV) or Path(__file__).parent / "models")


def _cs(mode_bits: int):
    import capstone  # lazy: the rest of the package works without it
    return capstone.Cs(capstone.CS_ARCH_X86,
                       capstone.CS_MODE_64 if mode_bits == 64 else capstone.CS_MODE_32)


def mnemonic_sequence(window: bytes, mode_bits: int) -> List[str]:
    """Linear sweep: decode instructions; on an undecodable byte emit '(bad)'
    and move one byte forward (this mirrors how a naive disassembler reads data)."""
    md = _cs(mode_bits)
    seq: List[str] = []
    i, n = 0, len(window)
    while i < n:
        for ins in md.disasm(window[i:], i):   # decodes until the first invalid byte
            seq.append(ins.mnemonic)
            i += ins.size
        if i < n:                              # decoder stopped: byte at i is not valid code
            seq.append(BAD)
            i += 1
    return seq


# ----------------------------- model ---------------------------------------
class CodenessModel:
    """Mnemonic bigram model with add-k smoothing."""

    def __init__(self, mode_bits: int, counts: Dict[str, Dict[str, int]],
                 vocab: List[str], threshold: float, meta: Dict[str, Any]):
        self.mode_bits, self.counts, self.vocab = mode_bits, counts, vocab
        self.threshold, self.meta = threshold, meta
        self._tot = {a: sum(d.values()) for a, d in counts.items()}
        self._v = len(vocab) + 1                           # +1 for unseen tokens

    def score_seq(self, seq: List[str]) -> float:
        """Mean log2-probability per bigram (higher = more code-like)."""
        if not seq:
            return -99.0
        toks = [START] + seq
        lp = 0.0
        for a, b in zip(toks, toks[1:]):
            c_ab = self.counts.get(a, {}).get(b, 0)
            lp += math.log2((c_ab + SMOOTHING_K) / (self._tot.get(a, 0) + SMOOTHING_K * self._v))
        return lp / (len(toks) - 1)

    def score_window(self, window: bytes) -> float:
        return self.score_seq(mnemonic_sequence(window, self.mode_bits))

    def is_code_like(self, window: bytes) -> bool:
        return self.score_window(window) >= self.threshold

    def to_json(self) -> Dict[str, Any]:
        return {"mode_bits": self.mode_bits, "vocab": self.vocab, "counts": self.counts,
                "threshold": self.threshold, "meta": self.meta}

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "CodenessModel":
        return cls(d["mode_bits"], d["counts"], d["vocab"], d["threshold"], d.get("meta", {}))


def windows_of(blob: bytes, size: int = WINDOW) -> List[bytes]:
    return [blob[i:i + size] for i in range(0, len(blob) - size + 1, size)]


def train(code_blobs: Iterable[bytes], mode_bits: int, benign_fpr: float = 0.05) -> CodenessModel:
    """Train on BENIGN code. The threshold is the benign_fpr-quantile of benign
    window scores, so about 5% of benign windows fall below it (tunable)."""
    counts: Dict[str, Counter] = defaultdict(Counter)
    seqs: List[List[str]] = []
    for blob in code_blobs:
        for w in windows_of(blob):
            seq = mnemonic_sequence(w, mode_bits)
            seqs.append(seq)
            toks = [START] + seq
            for a, b in zip(toks, toks[1:]):
                counts[a][b] += 1
    vocab = sorted({t for d in counts.values() for t in d} | set(counts))
    model = CodenessModel(mode_bits, {a: dict(d) for a, d in counts.items()}, vocab, 0.0, {})
    scores = sorted(model.score_seq(s) for s in seqs)
    if not scores:
        raise ValueError("no training windows (need code blobs of at least 2048 bytes)")
    model.threshold = scores[int(len(scores) * benign_fpr)]
    model.meta = {"windows": len(scores), "benign_fpr_target": benign_fpr, "window": WINDOW,
                  "note": "trained by train_codeness.py on benign code"}
    return model


def save(model: CodenessModel, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model.to_json()), encoding="utf-8")


def load(mode_bits: int) -> Optional[CodenessModel]:
    """Load the trained model for 32- or 64-bit code, or None if absent."""
    p = model_dir() / f"codeness_x86_{mode_bits}.json"
    if not p.exists():
        return None
    return CodenessModel.from_json(json.loads(p.read_text(encoding="utf-8")))


def score_region(model: CodenessModel, blob: bytes) -> Dict[str, Any]:
    """Score all (sampled) windows of a region. Returns counts and fractions."""
    wins = windows_of(blob)
    if len(wins) > MAX_WINDOWS_PER_SECTION:
        step = len(wins) / MAX_WINDOWS_PER_SECTION
        wins = [wins[int(i * step)] for i in range(MAX_WINDOWS_PER_SECTION)]
    if not wins:
        return {"windows": 0, "not_code_like": 0, "fraction_not_code_like": 0.0, "mean_score": None}
    scores = [model.score_window(w) for w in wins]
    low = sum(1 for s in scores if s < model.threshold)
    return {"windows": len(wins), "not_code_like": low,
            "fraction_not_code_like": round(low / len(wins), 3),
            "mean_score": round(sum(scores) / len(scores), 3),
            "threshold": round(model.threshold, 3)}
