"""Prompts for the Malworn LLM agent.

Owner: Saood

Each prompt version is kept (never edited in place) so results stay comparable:
rerun the same report with each version and compare the saved answers.

- v0: the exact wording used for the first manual Qwen 3 8B baseline
  (notebooks/Baseline_qwen3:8b). No system prompt; the instruction is sent as
  part of the user message.
"""

# ---------------------------------------------------------------------------
# v0 - baseline (no system prompt)
# ---------------------------------------------------------------------------
V0_SYSTEM = None

V0_USER_INSTRUCTION = (
    "You are a malware analyst assistant. Explain this static analysis report "
    "to a junior analyst in plain language, and say what the analyst should "
    "check next:"
)

PROMPTS = {
    "v0": {"system": V0_SYSTEM, "user_instruction": V0_USER_INSTRUCTION},
}

DEFAULT_PROMPT_VERSION = "v0"
