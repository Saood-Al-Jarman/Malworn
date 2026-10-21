# LLM Setup: Ollama on Windows, reachable from the VM

The LLM runs on **Windows** because VMware can't give the VM access to the GPU. The VM sends JSON reports to it over the **host-only network**: a private network between your PC and the VM only.

```
REMnux VM (192.168.x.131)  ──JSON over host-only network──►  Windows + GPU (192.168.x.1:11434)
       samples stay here      ◄──────── answer text ────────      Ollama + Qwen 3 8B
```

Do `vm-setup.md` first.

Time needed: about 30–45 minutes.

## 1. Install Ollama

1. Download **only** from the official site, **ollama.com** (or github.com/ollama/ollama).
2. Install with defaults. Models are stored in `C:\Users\<you>\.ollama\models` (not in OneDrive, which is good).
3. When it asks you to create an account, click **"No thanks, I'll use Ollama locally."** The account is for cloud models, and we run everything locally.
4. If Windows shows a **firewall popup** for Ollama, click **Cancel**. We add a tighter rule ourselves in step 5 (but see the warning there).

> **Low on C: drive space?** Each model is ~5 GB. To store them elsewhere, add a user environment variable `OLLAMA_MODELS` = e.g. `D:\ollama-models` (same method as step 3).

## 2. Download and test the model

In PowerShell:

```powershell
ollama pull qwen3:8b
ollama run qwen3:8b
```

Ask it something, then type `/bye` to exit.

**Check it uses the GPU:** while it's answering, Task Manager → **Performance → GPU** → the **3D** graph should hit ~100% and **Dedicated GPU memory** should jump by ~5–6 GB.

## 3. Find your PC's host-only address

```powershell
ipconfig
```

Find **Ethernet adapter VMware Network Adapter VMnet1** and note its **IPv4 Address**, e.g. `192.168.5.1`.
Below, this is called `WIN_IP`. Your network is the same first three numbers + `.0/24` (e.g. `192.168.5.0/24`).

> Ignore **VMnet8**. That's the NAT network. Everyone's numbers will be different.

## 4. Make Ollama listen on the VM network

By default Ollama only accepts connections from your own PC.

1. Press Windows key → type `environment` → open **"Edit environment variables for your account"** (not "system").
2. In the **top** box (User variables) → **New…**
   - Name: `OLLAMA_HOST`
   - Value: `WIN_IP:11434` (e.g. `192.168.5.1:11434`)
3. Click **OK** in the small box **and OK in the Environment Variables window**. The change isn't saved until you do.
4. **Close every PowerShell / Terminal window** (the whole app, not just a tab). Open windows don't see the new setting.
5. Fully restart Ollama:
   - Right-click the llama icon in the system tray → **Quit Ollama**
   - Task Manager → **Details** → end any remaining `ollama.exe` / `ollama app.exe`
   - Open Ollama from the Start menu and wait ~10 seconds
6. Check, in a **new** PowerShell:
   ```powershell
   echo $env:OLLAMA_HOST
   netstat -an | findstr 11434
   ```
   You want `WIN_IP:11434 ... LISTENING`.
   - `127.0.0.1:11434` → Ollama didn't restart properly; repeat step 5.
   - Nothing printed → Ollama isn't running; open it from the Start menu.

> Don't use the Ollama app's **"Expose Ollama to the network"** setting. It listens on all networks, including your home Wi-Fi. `OLLAMA_HOST` limits it to the VM network only.

## 5. Firewall: allow only the VM

Open **PowerShell as Administrator** and run (replace both addresses with yours):

```powershell
New-NetFirewallRule -DisplayName "Ollama - Malworn VM only" -Direction Inbound -Protocol TCP -LocalPort 11434 -LocalAddress 192.168.5.1 -RemoteAddress 192.168.5.0/24 -Action Allow
```

It should end with `PrimaryStatus : OK`.

> ⚠️ **Important gotcha:** if the Ollama firewall popup was cancelled, Windows creates **Block** rules for `ollama.exe` on Public networks, and VMware networks count as Public. **Block rules override Allow rules**, so the VM's connection silently times out.
>
> Check for them:
> ```powershell
> Get-NetFirewallRule -Direction Inbound -Action Block | Where-Object DisplayName -like "*ollama*" | Select-Object DisplayName, Enabled, Profile
> ```
> If any show `Enabled: True`, disable them:
> ```powershell
> Get-NetFirewallRule -Direction Inbound -Action Block | Where-Object DisplayName -like "*ollama*" | Disable-NetFirewallRule
> ```
> This is still safe: Ollama only listens on the VM network, and our Allow rule only accepts the VM's addresses. If the popup appears again later and recreates them, run the disable command again.

## 6. Test from the VM

Start the REMnux VM (network: **Host-only**) and open its terminal.

1. **The VM has an address on the same network:**
   ```bash
   ip -4 addr
   ```
   Look for e.g. `192.168.5.131` under `ens33`.

2. **The VM can reach Ollama:**
   ```bash
   curl --max-time 5 http://192.168.5.1:11434
   ```
   Should print `Ollama is running`.

3. **The VM can ask the model a question:**
   ```bash
   curl http://192.168.5.1:11434/api/generate -d '{"model": "qwen3:8b", "prompt": "In one sentence, what is UPX?", "stream": false, "think": false}'
   ```
   Returns JSON with the answer in `"response"`. The first request takes a few extra seconds while the model loads onto the GPU.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `curl` hangs / times out | Firewall | Check the Block-rule gotcha in step 5 |
| `Connection refused` | Ollama not listening on `WIN_IP` | Redo step 4, especially the full restart |
| `ip -4 addr` shows no `192.168.x.x` address | VM not on Host-only | VM → Settings → Network Adapter → Host-only |
| `echo $env:OLLAMA_HOST` prints nothing | Variable not saved, or old terminal | Click OK on both windows; close and reopen the whole terminal app |
| `ollama list` can't connect on Windows | Old terminal window | Open a new PowerShell window |
| Answers very slow, GPU idle | Running on CPU | Check GPU drivers; tell the team lead |

## Reference timings (Saood's PC, RTX 3060 12 GB)

- First request (includes loading the model): ~3.4 s
- Generation speed: ~56 tokens/second
