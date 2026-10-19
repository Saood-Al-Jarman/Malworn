# Malworn

An LLM-powered assistant for static malware analysis. An analyst uploads a sample, Malworn runs static analysis, packing/obfuscation detection, and ML-based detection on it, then an LLM agent turns the results into a report the analyst can question in a follow-up chat.

Capstone project, BS Cybersecurity, RIT Dubai (Fall 2026).

## Team

| Member | Area | Folder |
|---|---|---|
| Saood Aljerman | LLM agent & fine-tuning | `src/malworn/agent/` |
| Ahmed Abd Elaal | Static analysis & feature extraction | `src/malworn/static_analysis/` |
| Viha Agrawal | Packing / obfuscation detection | `src/malworn/packing/` |
| Hassan Al-Hasani | ML detection & threat intelligence | `src/malworn/detection/` |

Mentor: Mohammed M. Al Ani

## ⚠️ Safety

- **This repository contains no live malware and must never contain any.**
- Malware samples are handled **only inside an isolated Linux VM**, never on a host machine.
- Samples, datasets, and model weights are blocked by `.gitignore`. Do not force-add them.

## How it fits together

```
sample ──► static_analysis ──► packing ──► detection ──► agent ──► report + chat (app)
```

## Project layout

```
malworn/
├── docs/                  # deliverables, architecture notes, lit review
├── data/                  # NOT committed — see data/README.md
├── notebooks/             # experiments and scratch work
├── src/malworn/
│   ├── static_analysis/   # PE parsing, feature extraction
│   ├── packing/           # packing/obfuscation detection
│   ├── detection/         # ML classification + threat intel
│   ├── agent/             # LLM agent, prompts, fine-tuning
│   └── app/               # upload + follow-up chat interface
└── tests/
```

## Setup

```bash
git clone <repo-url>
cd malworn
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in your own values
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: never push to `main` directly — branch, open a pull request, get one approval, merge.
