#!/usr/bin/env python3
"""
gtfo_suid.py — Scan les binaires SUID et croise avec GTFOBins
Usage: python3 gtfo_suid.py [--offline]
"""

import subprocess
import json
import urllib.request
import sys
import os

# ─── Couleurs ────────────────────────────────────────────────────────────────
R  = "\033[91m"   # rouge
Y  = "\033[93m"   # jaune
G  = "\033[92m"   # vert
B  = "\033[94m"   # bleu
C  = "\033[96m"   # cyan
W  = "\033[97m"   # blanc
DIM = "\033[2m"
RST = "\033[0m"   # reset

GTFOBINS_JSON = "https://gtfobins.org/api.json"

BANNER = f"""
{R}  ██████╗ ████████╗███████╗ ██████╗     ███████╗██╗   ██╗██╗██████╗
 {R} ██╔════╝╚══██╔══╝██╔════╝██╔═══██╗    ██╔════╝██║   ██║██║██╔══██╗
 {Y} ██║  ███╗   ██║   █████╗  ██║   ██║    ███████╗██║   ██║██║██║  ██║
 {Y} ██║   ██║   ██║   ██╔══╝  ██║   ██║    ╚════██║██║   ██║██║██║  ██║
 {G} ╚██████╔╝   ██║   ██║     ╚██████╔╝    ███████║╚██████╔╝██║██████╔╝
 {G}  ╚═════╝    ╚═╝   ╚═╝      ╚═════╝     ╚══════╝ ╚═════╝ ╚═╝╚═════╝{RST}
        {DIM}SUID PrivEsc — powered by GTFOBins{RST}
"""

# ─── Fetch GTFOBins JSON ──────────────────────────────────────────────────────
def fetch_gtfobins():
    print(f"{B}[*]{RST} Fetching GTFOBins database...", end=" ", flush=True)
    try:
        req = urllib.request.Request(
            GTFOBINS_JSON,
            headers={"User-Agent": "gtfo_suid/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = json.loads(r.read().decode())
        data = raw.get("executables", raw)
        print(f"{G}OK{RST} ({len(data)} binaries)")
        return data
    except Exception as e:
        print(f"{R}FAILED{RST} ({e})")
        return None

# ─── Scan SUID binaries ───────────────────────────────────────────────────────
def find_suid():
    print(f"{B}[*]{RST} Scanning SUID binaries on this system...")
    try:
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=30
        )
        paths = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        # Garde juste le nom du binaire (basename)
        binaries = {}
        for p in paths:
            name = os.path.basename(p)
            binaries[name] = p
        print(f"{G}[+]{RST} Found {len(binaries)} SUID binaries\n")
        return binaries
    except Exception as e:
        print(f"{R}[-]{RST} find failed: {e}")
        return {}

# ─── Croisement & affichage ───────────────────────────────────────────────────
def match_and_display(suid_bins, gtfo_db):
    hits = {}
    for name, path in suid_bins.items():
        if name in gtfo_db:
            entry = gtfo_db[name]
            suid_functions = {}
            functions = entry.get("functions", {})
            for func_name, examples in functions.items():
                for ex in examples:
                    contexts = ex.get("contexts", {})
                    # suid key présente = exploitable (null = code générique, dict = code spécifique)
                    if "suid" not in contexts:
                        continue
                    suid_ctx = contexts["suid"]
                    if suid_ctx and isinstance(suid_ctx, dict) and suid_ctx.get("code"):
                        code = suid_ctx["code"].strip()
                    else:
                        # suid: null → le code générique s'applique tel quel
                        code = ex.get("code", "").strip()
                    if not code:
                        continue
                    if func_name not in suid_functions:
                        suid_functions[func_name] = []
                    if code not in suid_functions[func_name]:
                        suid_functions[func_name].append(code)
            if suid_functions:
                hits[name] = {"path": path, "functions": suid_functions}

    if not hits:
        print(f"{Y}[!]{RST} No GTFOBins matches found for SUID binaries.")
        return

    print(f"{R}{'═'*60}{RST}")
    print(f"{R}  ⚡ {len(hits)} EXPLOITABLE SUID BINARIES FOUND{RST}")
    print(f"{R}{'═'*60}{RST}\n")

    for name, info in hits.items():
        print(f"{R}┌─ {name}{RST}  {DIM}{info['path']}{RST}")
        print(f"{R}│{RST}  {C}GTFOBins:{RST} https://gtfobins.org/gtfobins/{name}/")
        for func, codes in info["functions"].items():
            print(f"{R}│{RST}")
            print(f"{R}│  {Y}[{func.upper()}]{RST}")
            for code in codes:
                for line in code.splitlines():
                    print(f"{R}│{RST}    {G}{line}{RST}")
        print(f"{R}└{'─'*58}{RST}\n")

# ─── Listing de tous les SUID (même sans match) ───────────────────────────────
def list_all_suid(suid_bins, gtfo_db):
    print(f"\n{B}{'─'*60}{RST}")
    print(f"{B}  All SUID binaries on this system:{RST}")
    print(f"{B}{'─'*60}{RST}")
    for name, path in sorted(suid_bins.items()):
        tag = f"{G}[GTFOBins]{RST}" if name in gtfo_db else f"{DIM}[unknown]{RST}"
        print(f"  {tag}  {path}")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    gtfo_db = fetch_gtfobins()
    if gtfo_db is None:
        print(f"{R}[!]{RST} Cannot reach GTFOBins. Check your network.")
        sys.exit(1)

    suid_bins = find_suid()
    if not suid_bins:
        print(f"{Y}[!]{RST} No SUID binaries found (try running as root for full scan)")
        sys.exit(0)

    match_and_display(suid_bins, gtfo_db)
    list_all_suid(suid_bins, gtfo_db)

if __name__ == "__main__":
    main()
