# Malware Analysis VM Setup (REMnux on VMware)

Every team member who handles malware samples needs this VM. **Samples are only ever downloaded, unzipped, or analyzed inside it. Never on Windows.**

Time needed: about 1–2 hours, mostly waiting for downloads and updates.

## What you get

- **REMnux**: a free Linux distro made for malware analysis. It already includes the tools we use:

  | Tool | Command / import | Used by |
  |---|---|---|
  | pefile | `python3 -c "import pefile"` | static analysis |
  | capa | `capa` | static analysis, detection |
  | Detect It Easy | `diec` | packing |
  | UPX | `upx` | packing |
  | YARA | `yara` | detection |

- A VM with **no internet** that can only talk to your own PC (for reaching the LLM; see `ollama-setup.md`).
- A **clean snapshot** to roll back to after every session with samples.

## 1. Check virtualization is enabled

Task Manager → **Performance → CPU** → bottom right should say **Virtualization: Enabled**.
If it says Disabled, turn on Intel VT-x / AMD-V (SVM) in your BIOS.

## 2. Download REMnux

1. Go to **remnux.org** → install docs → download the **virtual appliance (OVA)**. Pick the VMware version if offered.
2. Verify the file's hash against the one listed on the site.

## 3. Import into VMware Workstation

1. **File → Open** → select the OVA.
2. Name it (e.g. `REMnux-Malworn`) and choose the storage location.

> ⚠️ **Do NOT store the VM inside OneDrive** (or Google Drive, Dropbox, etc.). On many PCs, `Documents` and `Desktop` are synced by OneDrive. Once samples are inside the VM, its disk file contains malware, and OneDrive would upload it to the cloud. Syncing a running VM's disk can also corrupt it.
>
> Use a path like `C:\Users\<you>\VMs\` or `C:\VMs\`. Check the address bar in File Explorer: if the path contains `OneDrive`, move it.

3. If VMware warns the file doesn't meet the OVF spec, click **Retry**. That's normal.

**If you need to move the VM later:** power it off → close VMware → move the whole VM folder → in VMware, right-click the old entry → **Remove** → **File → Open** the `.vmx` in the new location → choose **I Moved It**.

## 4. Hardware settings

With the VM **powered off**, open **VM → Settings → Hardware**:

| Setting | Value | Why |
|---|---|---|
| Memory | 8 GB (4 GB if your PC has 16 GB or less) | |
| Processors | 1 processor × 4 cores (2 if your PC has fewer than 8 cores) | |
| Hard disk | Default is fine | Only uses space as it fills |
| Network Adapter | **NAT** for now (changed later) | Needed for the first update |
| USB Controller | **Remove** | Fewer paths out of the VM |
| Sound Card / Printer | **Remove** if present | Same reason |
| Display → Accelerate 3D graphics | **Unchecked** | 3D drivers are a known VM-escape path |
| Processors → Virtualize VT-x/EPT | **Unchecked** | Not needed |

## 5. Isolation settings

**VM → Settings → Options**:

- **Guest Isolation:** uncheck **Enable drag and drop** and **Enable copy and paste**.
- **Shared Folders:** **Disabled**.

## 6. First boot and update

Start the VM. REMnux logs in automatically and opens a terminal.

1. **Change the default password** (default user `remnux`, password `malware`):
   ```bash
   passwd
   ```
   Nothing appears on screen while you type a password. That's normal.

2. **Check internet works:**
   ```bash
   ping -c 3 google.com
   ```

3. **Update REMnux** (20–60 minutes):
   ```bash
   remnux upgrade
   ```

4. **Check the tools are there:**
   ```bash
   python3 -c "import pefile; print('pefile ok')"
   yara --version
   capa --version
   diec --version
   upx --version
   ```

5. **Shut down:**
   ```bash
   sudo shutdown now
   ```

## 7. Cut the internet and take a snapshot

1. **VM → Settings → Network Adapter** → select **Host-only**.
   The VM can now only reach your own PC. No internet, no home network.
2. **VM → Snapshot → Take Snapshot** → name it `clean-baseline`.

## Rules for working with samples

- **Samples stay inside the VM, always.** Never download or unzip one on Windows.
- Samples are shared as **password-protected zips** (usual password: `infected`).
- To download samples: switch the VM network to **NAT** briefly, download inside the VM, switch back to **Host-only** before opening anything.
- **After every session with samples:** **VM → Snapshot → Revert to Snapshot → `clean-baseline`.**
- Only `.json` reports leave the VM. Never sample files.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ping` fails on first boot | Network adapter isn't on NAT |
| VM very slow | Lower cores/RAM if your PC has fewer resources, or close other apps |
| `command not found` for a tool | Run `remnux upgrade` again (needs NAT) |
