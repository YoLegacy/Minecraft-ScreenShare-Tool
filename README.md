# Minecraft-ScreenShare-Tool[README.md](https://github.com/user-attachments/files/34550580/README.md)
# YoLegacy SS Tool

A PowerShell screenshare (SS) tool for Minecraft. It runs a set of read-only checks on a Windows PC and prints a colour-coded report, so a staff member can quickly see whether a player's system shows signs of cheating or of tampering with evidence.

> **Disclaimer:** This tool reports *indicators*, not proof. A flag means "look closer", not "guilty". Always review findings manually before making a ruling.

---

## Quick start

1. Open **PowerShell as Administrator** (right-click → *Run as administrator*).
2. Run:

```powershell
Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/YoLegacy/YoLegacyLarpSS/refs/heads/main/YoLegacySSTool.ps1)
```

Or download `YoLegacySSTool.ps1` and run it locally:

```powershell
powershell -ExecutionPolicy Bypass -File .\YoLegacySSTool.ps1
```

Administrator rights are required. The script exits immediately if it isn't elevated.

---

## What it checks

### Module 1: System checks
- System boot time and uptime
- Connected drives and free space
- Status of services commonly tied to forensic artifacts (SysMain, PcaSvc, DPS, EventLog, Schedule, BAM, and others)
- Registry settings (CMD availability, PowerShell script block logging, Activity Feed, Prefetch)
- Windows Defender exclusions
- Event logs (cleared logs, device events)
- Prefetch integrity
- Recycle Bin activity
- PowerShell console history

### Module 2: Common directories scan
- Folders left behind by known cheat clients
- Recent `.minecraft` activity
- Non-Microsoft executable paths, saved to `C:\YoLegacy\paths.txt`

### Module 3: JAR parser / Prefetch analysis
- Downloads `PECmd.exe` and `xxstrings64.exe` to `%TEMP%`
- Parses Java/Javaw Prefetch files created since the last boot
- Scans for cheat-related strings

### Module 4: Mod analyzer
- Hashes every mod in `.minecraft\mods` and looks each one up on [Modrinth](https://modrinth.com) and Megabase
- Classifies mods as **Verified**, **Unknown**, **Potentially tampered** (file size differs from the Modrinth release) or **Cheat mod** (cheat strings found inside)
- Reports where each file was downloaded from, using the Zone.Identifier data

### Final conclusion
Every finding is rated `CRITICAL`, `WARNING` or `INFO` and grouped in a summary, followed by an overall verdict from *Clean* to *Highly suspicious*.

---

## Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10 / 11 |
| PowerShell | 5.1 or newer |
| Privileges | Administrator |
| Network | Internet access to GitHub, Modrinth and Megabase |

---

## Files and folders it touches

| Path | Purpose |
|---|---|
| `C:\YoLegacy\` | Output folder, including `paths.txt` |
| `%TEMP%\PECmd.exe`, `%TEMP%\xxstrings64.exe` | Downloaded analysis tools |
| `%TEMP%\yolegacysstool\` | Temporary working folder, deleted after the scan |

The tool does not modify or delete the player's mods or game files. It only reads them.

---

## Troubleshooting

**`Program 'powershell.exe' failed to run: Access is denied`**
Don't wrap the command in a second `powershell -Command "..."`. From an already elevated PowerShell window, run the `Invoke-Expression` line from the Quick start section directly.

**"Administrator privileges required"**
Reopen PowerShell with *Run as administrator*.

**Antivirus blocks the script or the downloaded tools**
The tool downloads unsigned executables and contains cheat-name strings, which security software can flag. Check *Windows Security → Protection history*. If you trust the source, add an exclusion for the specific file or folder rather than disabling protection.

**"Failed to download tools"**
Module 3 is skipped if GitHub can't be reached. Check your connection and any firewall or proxy settings.

---

## Credits

- Mod analyzer concept based on **Habibi Mod Analyzer**
- Prefetch parsing by [PECmd](https://github.com/EricZimmerman/PECmd) (Eric Zimmerman)
- Mod lookups via the [Modrinth API](https://docs.modrinth.com/)

## Contact

DM **yolegacy** for bugs or questions.
