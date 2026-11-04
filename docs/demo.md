# Running the Malworn demo

How to set up and run the full system: upload a file in the VM, watch the agent choose and run tools, read the report, ask follow-up questions.

## What runs where

```
Windows PC (host)                                   REMnux VM (host-only network, no internet)
─────────────────────────────                       ─────────────────────────────────────────────
Ollama + Qwen 3 8B     192.168.5.1:11434  ◄─────────  agent loop  (malworn.agent.loop)
VirusTotal bridge      192.168.5.1:8770   ◄── hash ─  10 tools, incl. virustotal (sends only the SHA-256)
  └─ VT_API_KEY lives here                            web app  127.0.0.1:8080  (open in the VM's browser)
                                                      samples + reports in ~/malworn-data/
```

The sample never leaves the VM. Only text (tool descriptions and results) goes to Ollama, and only the SHA-256 goes to the bridge.

## One-time setup

### Windows

1. **Ollama** is already set up (`docs/ollama-setup.md`): `OLLAMA_HOST=192.168.5.1:11434` and the firewall rule "Ollama - Malworn VM only".
2. **Python 3.11 or newer.** Check with `python --version` in PowerShell; if it's missing, install it from python.org and tick "Add python.exe to PATH".
3. **A copy of the repo** (code only; samples never go on Windows):
   ```powershell
   cd $HOME
   git clone https://github.com/Saood-Al-Jarman/Malworn.git
   ```
   Or download the ZIP from GitHub and unzip it to `C:\Users\<you>\Malworn`.
4. **The VirusTotal API key**, as a Windows environment variable (never in the repo, never in the VM):
   ```powershell
   setx VT_API_KEY "paste-your-key-here"
   ```
   Close PowerShell and open a new one so it sees the variable. (Free key: virustotal.com → sign in → API key.)
5. **Firewall rule for the bridge.** In PowerShell **as Administrator**:
   ```powershell
   New-NetFirewallRule -DisplayName "Malworn VT bridge - VM only" -Direction Inbound -Protocol TCP `
     -LocalPort 8770 -RemoteAddress 192.168.5.0/24 -Action Allow
   ```

### VM (only while it's clean: no sample has been opened since the snapshot)

1. In VMware, switch the network adapter to **NAT**.
2. Update the code and install Flask:
   ```bash
   cd ~/Malworn
   git fetch && git checkout saood/agent-loop && git pull     # main, once PR #8 is merged
   python3 -m pip install --user flask || python3 -m pip install --user --break-system-packages flask
   ```
3. Make two **harmless** test files: a small Windows launcher program that ships inside the official setuptools package on PyPI, and a UPX-packed copy of it.
   ```bash
   mkdir -p ~/demo-files && cd ~/demo-files
   python3 -m pip download --no-deps --only-binary :all: setuptools==69.5.1 -d .
   python3 -c "import zipfile, glob; z = zipfile.ZipFile(glob.glob('setuptools-*.whl')[0]); open('launcher.exe', 'wb').write(z.read('setuptools/cli-32.exe'))"
   upx -o launcher_upx.exe launcher.exe
   rm setuptools-*.whl && cd ~/Malworn
   ```
4. Switch the adapter back to **host-only** and take a new snapshot (e.g. `demo-ready`).

## Before each demo

**Windows**, in PowerShell:
```powershell
cd $HOME\Malworn
$env:PYTHONPATH = "src"
python -m malworn.agent.vt_bridge
```
Leave it open: it prints one line per lookup. Make sure Ollama is running (tray icon).

**VM**, in a terminal:
```bash
cd ~/Malworn
PYTHONPATH=src python3 -m malworn.app.check
```
Every line should say `ok`. Then start the app:
```bash
PYTHONPATH=src python3 -m malworn.app.web
```
Open **http://127.0.0.1:8080** in the VM's browser (Firefox).

The first analysis takes longer while Ollama loads the model onto the GPU (10–20 s extra).

## Suggested demo (about 5 minutes)

1. **Home page:** point out the ten tools the agent can choose from, and that only the hash leaves the VM.
2. **Upload `launcher.exe`** (benign). Watch the live panel: the model's reasoning and each tool call appear as they happen.
3. **Read the explanation:** facts with the tool in brackets, no malicious/benign verdict, "what we cannot tell yet", next steps. Show the full report below it.
4. **Upload `launcher_upx.exe`** (the packed copy). The packing tools rate packing as likely, and the explanation should say the imports belong to the UPX stub and suggest `upx -d` and re-uploading.
5. **Ask a follow-up**, e.g. "Which sections look packed, and why?" or "What does the imphash tell me?". The model may run a tool it hasn't run yet; the report updates.
6. **Safety points:** the sample is stored under its SHA-256, read-only and not executable; the model runs locally; the VirusTotal key never enters the VM.

## Without the bridge or a key

To demo without VirusTotal, in the VM:
```bash
export MALWORN_VT_MODE=mock
```
The tool then returns a mock "not found" result, and the page labels it "Mock VirusTotal result: no real lookup was made."

## Command line (no web page)

```bash
PYTHONPATH=src python3 -m malworn.agent.loop ~/demo-files/launcher_upx.exe
PYTHONPATH=src python3 -m malworn.agent.loop file.exe --request "Is this file packed?"
```
Output goes to `runs/agent_<sha>_<time>/` (report.json, report.html, explanation.md, transcript.json, agent_run.json).

## If something goes wrong

| What you see | Fix |
|---|---|
| `check`: can't reach Ollama | Ollama running on Windows? `OLLAMA_HOST=192.168.5.1:11434` set? VM adapter on host-only? |
| `check`: qwen3:8b isn't pulled | On Windows: `ollama pull qwen3:8b` |
| `check`: can't reach the VirusTotal bridge | Bridge running in PowerShell? Firewall rule for 8770? Or use `MALWORN_VT_MODE=mock` |
| Bridge prints "VT_API_KEY is not set" | `setx VT_API_KEY "..."`, then open a **new** PowerShell |
| `virustotal` fails with 401 or 403 | Wrong key, or the free quota is used up for the day |
| `virustotal` fails with "rate limit" | Free keys allow 4 lookups a minute; wait a minute (repeat lookups come from the cache) |
| Packing tools warn "Detect It Easy was NOT run" | `which diec` in the VM; REMnux should include it |
| An analysis takes more than a minute or two | Normal for the first run (model loading). Thinking mode is slower; the CLI has `--no-think` to compare |
| Page says "The app was stopped before this analysis finished" | The app was restarted mid-analysis; upload the file again |

## After a session with real samples

Copy out only the results you need (`~/malworn-data/runs/<id>/report.json` or `report.html`) as in `docs/vm-setup.md`, then **revert to the clean snapshot**.
