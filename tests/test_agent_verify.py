"""The answer check (agent/verify.py), on sentences from the first real runs (Nov 4)."""

import pytest

from malworn.agent import verify

TOOLS = ["hashes", "file_type", "packing_indicators", "packer_signatures", "sections", "imports",
         "strings", "extra_checks", "version_info", "virustotal"]


def test_real_upx_answer_cites_tools_that_never_ran():
    # Real a2 answer on launcher_upx.exe: only file_type and packing_indicators ran.
    answer = ("- Section UPX1 has high entropy (7.576), consistent with compressed data [sections].\n"
              "- The file contains no strings or imports directly indicating malicious activity [strings, imports].\n"
              "3. Check the SHA-256 hash on VirusTotal [virustotal].\n"
              "4. Compute the imphash to search for related samples [extra_checks].")
    problems = verify.check_answer(answer, ["file_type", "packing_indicators"], TOOLS)
    assert problems["cited_not_run"] == ["sections", "strings", "imports", "virustotal", "extra_checks"]


def test_real_benign_answer_recommends_tools_and_leans_to_a_verdict():
    # Real a2 answer on launcher.exe
    answer = ("The file is a Windows PE executable that appears to be a legitimate application, as no "
              "packing indicators were found.\n"
              "4. Check for additional metadata via version_info [version_info] and overlay analysis [extra_checks].")
    ran = ["file_type", "packing_indicators", "sections", "imports", "strings", "virustotal"]
    problems = verify.check_answer(answer, ran, TOOLS)
    assert problems["cited_not_run"] == ["version_info", "extra_checks"]
    assert len(problems["verdict"]) == 1 and "legitimate" in problems["verdict"][0]


@pytest.mark.parametrize("text", [
    "VirusTotal does not flag the hash (0/75 engines) [virustotal].",
    "41 of 72 VirusTotal engines flag this hash as malicious [virustotal].",
    "Packing is not evidence that a file is malicious [packing_indicators].",
    "Malworn gives no verdict on whether the file is safe.",
    "Unpack it safely in the VM.",
])
def test_allowed_wording_is_not_flagged_as_a_verdict(text):
    assert verify.verdict_phrases(text) == []


def test_plain_common_words_are_not_treated_as_tool_mentions():
    text = "Re-run the analysis on the unpacked file to inspect its imports, strings and sections."
    assert verify.tools_mentioned(text, TOOLS) == []


def test_backticks_and_distinct_names_count_as_mentions():
    text = "Run `strings`, then packer_signatures and VirusTotal."
    assert verify.tools_mentioned(text, TOOLS) == ["strings", "packer_signatures", "virustotal"]


def test_unknown_citations():
    problems = verify.check_answer("Entropy is high [entropy_tool]. Hash [hashes].", ["hashes"], TOOLS)
    assert problems["unknown_citations"] == ["entropy_tool"]
    assert problems["cited_not_run"] == []


def test_correction_message_names_each_problem():
    msg = verify.correction_message({"cited_not_run": ["strings"], "unknown_citations": ["x_y"],
                                     "verdict": ["It appears legitimate"]})
    assert "strings" in msg and "x_y" in msg and "legitimate" in msg
    assert msg.rstrip().endswith("same format.")


# False alarms from the Nov 6 comparison: categories and open questions, not judgements
@pytest.mark.parametrize("text", [
    "Short strings like `dasee` may be false positives or benign obfuscation [strings].",
    "Verify the file's authenticity by comparing it to known legitimate binaries.",
    "Compare the imphash against known benign samples [extra_checks].",
    "Whether the UPX stub contains malicious code or is a legitimate packer.",
    "Check whether it is part of a known legitimate application or installer.",
    "Legitimate software is often packed too [packing_indicators].",
    # Nov 7 run
    "The purpose of the file (legitimate or malicious) requires dynamic analysis or additional context.",
    "Inspect strings and resources in the unpacked file to identify potential malicious indicators.",
    "Inspect imports and strings of the unpacked file to identify potential malicious activity.",
    "Analyze the unpacked file to identify potential indicators of malicious behavior.",
    # Nov 7 evening run
    "Consider running `strings` or `imports` to examine potential malicious APIs, embedded data.",
    "Short strings like `dasee` appear random and may be packing artifacts or benign data.",
])
def test_categories_and_open_questions_are_not_verdicts(text):
    assert verify.verdict_phrases(text) == []


@pytest.mark.parametrize("text", [
    "The file is a Windows PE executable that appears to be a legitimate application.",
    "This file is malicious.",
    "Overall the sample looks benign [strings].",
    "It is safe to open.",
    "The analysis shows standard imports and strings consistent with a legitimate application.",
])
def test_real_verdicts_are_still_caught(text):
    assert verify.verdict_phrases(text)
