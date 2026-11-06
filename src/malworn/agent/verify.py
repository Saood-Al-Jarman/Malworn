"""Check the model's answer against what actually happened (NFR4, NFR7).

Owner: Saood

Deliverable 1 promised that "model statements are checked against tool
output". A prompt can only ask the model to cite honestly; this checks it.
After the model answers, check_answer() looks for:

  - cited_not_run:      [tool] citations (or `tool` mentions) of tools that did
                        not run in this analysis, so the claim has no evidence
                        behind it, or the model is recommending a tool instead
                        of calling it
  - unknown_citations:  [name] citations that look like a tool but aren't one
  - verdict:            verdict language (malicious, benign, legitimate, safe,
                        clean...) used as a judgement, not negated

The loop then gives the model one correction turn (agent.loop.converse_checked).
"""

import re

from malworn.contract import _NEGATION_RE

# [tool] or [tool, tool] citations
_CITATION = re.compile(r"\[([a-z][a-z0-9_]*(?:\s*,\s*[a-z][a-z0-9_]*)*)\]")
# `tool` mentions
_BACKTICK = re.compile(r"`([a-z][a-z0-9_]*)`")
# Names safe to spot as plain words (common words like "strings" or "imports" are not)
_DISTINCT = re.compile(r"(?<![A-Za-z0-9_])([a-z]+_[a-z0-9_]+|virustotal)(?![A-Za-z0-9_])", re.IGNORECASE)

VERDICT_WORDS = ("malicious", "benign", "legitimate", "safe", "clean", "harmless", "trustworthy")
_VERDICT = re.compile(r"\b(" + "|".join(VERDICT_WORDS) + r")\b", re.IGNORECASE)


def tools_mentioned(answer, known_tools):
    """Tool names the answer cites or names, in order of first appearance."""
    known = set(known_tools)
    found = []

    def add(name):
        name = name.strip().lower()
        if name in known and name not in found:
            found.append(name)

    for m in _CITATION.finditer(answer or ""):
        for name in m.group(1).split(","):
            add(name)
    for m in _BACKTICK.finditer(answer or ""):
        add(m.group(1))
    for m in _DISTINCT.finditer(answer or ""):
        add(m.group(1))
    return found


def unknown_citations(answer, known_tools):
    """Bracketed names that look like tool names (contain "_") but aren't tools."""
    known = set(known_tools)
    out = []
    for m in _CITATION.finditer(answer or ""):
        for name in m.group(1).split(","):
            name = name.strip()
            if "_" in name and name not in known and name not in out:
                out.append(name)
    return out


def verdict_phrases(answer):
    """Verdict words used as a judgement (a negation earlier in the sentence excuses them)."""
    text = answer or ""
    found = []
    for m in _VERDICT.finditer(text):
        start = max(text.rfind(".", 0, m.start()), text.rfind("\n", 0, m.start())) + 1
        end = text.find(".", m.end())
        sentence = text[start:end if end != -1 else len(text)]
        if _NEGATION_RE.search(text[start:m.start()]):
            continue
        if re.search(r"virustotal|engines?\b|threat label", sentence, re.IGNORECASE):
            continue  # reporting VirusTotal's own finding, credited to it, is allowed
        found.append(" ".join(text[start:end if end != -1 else len(text)].split())[:160])
    return found


def check_answer(answer, ran_tools, available_tools):
    """Problems with an answer. Empty lists everywhere means it passed."""
    ran = set(ran_tools)
    mentioned = tools_mentioned(answer, available_tools)
    return {
        "cited_not_run": [t for t in mentioned if t not in ran],
        "unknown_citations": unknown_citations(answer, available_tools),
        "verdict": verdict_phrases(answer),
    }


def has_problems(problems):
    return any(problems.values())


def correction_message(problems):
    """What the model is told when its answer fails the check."""
    lines = ["Before your answer is shown to the analyst, it was checked against this analysis:"]
    if problems["cited_not_run"]:
        names = ", ".join(problems["cited_not_run"])
        lines.append(f"- You cite or mention {names}, but these tools were not run in this analysis. "
                     "Call them now if they are relevant (do not recommend a tool you can call), "
                     "otherwise remove every claim and citation that depends on them.")
    if problems["unknown_citations"]:
        lines.append(f"- You cite {', '.join(problems['unknown_citations'])}, which are not tools. "
                     "Cite only the tools that produced each fact.")
    if problems["verdict"]:
        quoted = "; ".join(f'"{p}"' for p in problems["verdict"][:3])
        lines.append(f"- Your answer uses verdict language ({quoted}). Malworn gives no verdict: "
                     "report the evidence and how strong it is, and leave the judgement to the analyst.")
    lines.append("Then write your complete answer again, in the same format.")
    return "\n".join(lines)
