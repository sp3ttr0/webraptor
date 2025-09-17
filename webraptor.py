#!/usr/bin/env python3

# ===============================================================
# WebRaptor - Automated Web App Scanning Script (Single-target)
# ---------------------------------------------------------------
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# Refactor / updates: ChatGPT
# ===============================================================

import subprocess
import sys
import shutil
import re
import argparse
import logging
import signal
import time
from pathlib import Path
from colorama import Fore, Style
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------
# UI / Banner
# -------------------------
def print_banner():
    banner = fr"""
        ⣠⣶⣶⠶⠖⠒⠒⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⢠⠞⠁⠙⠏⢀⣀⣠⣤⣤⢬⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⡰⠃⠀⠐⠒⠉⠉⠉⠉⠉⠉⣩⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
    ⢀⠃⠀⠀⠀⠀⠀⠀⣀⣀⠤⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠒⣉⠥⠄⠀⠩⠽⢶⣤⣀⠀⠀⠀
    ⢸⠀⠀⠀⠀⣼⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢋⡴⠋⠀⠀⠀⠀⠀⠀⠀⠈⠙⠳⢦⡀
    ⠘⠀⠀⠀⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠊⢠⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⡇⠀⠀⠀⠀⠑⢤⣀⣀⣀⣠⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠂⠤⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠤⠒⠁⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠘⣷⠀⠀⠀⠀⠀⠀⠠⣀⠀⠀⠀⠀⠀⠀⠈⠉⠒⠒⠒⠒⠒⠂⠉⠁⠀⠀⠀⢀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠹⣆⠀⠀⣄⠀⠀⠀⠈⠑⢄⠀⠀⠀⡴⠀⠀⠀⢄⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠙⢦⡀⠈⠑⠢⢤⡤⠄⠀⢱⠀⢰⠁⠀⠀⠀⠈⢆⠀⠀⣀⡠⠔⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⢰⠏⢹⣶⠒⣋⡥⣤⡄⠊⠁⠀⢸⡆⠀⠀⠀⠀⣸⠶⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⢿⣿⣿⣿⡀⠘⣿⣶⡷⢤⢄⣀⠀⡇⠀⠀⠀⠀⢼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠙⠻⠿⢧⠱⣤⡼⣧⡞⠀⢾⡉⠻⢦⡀⠀⠀⠈⠓⠲⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠈⠒⠛⢿⡁⠀⠀⠠⡇⠀⠀⠙⣄⠀⠀⠀⠀⠈⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠢⣄⠀⠑⢄⠀⠀⠈⠓⠤⢄⣀⣀⡀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⢀⠼⠀⠀⠀⠀⠀⠀⠀⠀⠹⡀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡤⢋⣍⣴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⢰⣟⢻⠋⢿⠭⠋⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⣿⣰⠀⡎⠣⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠈⣉⡙⠒⢚⣒⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⡧⠻⠤⠿⡷⠀ {Style.BRIGHT} by sp3ttr0⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
        webraptor 🦖 — Hunt Smarter, Not Harder
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")

def check_tool(tool):
    return shutil.which(tool) is not None

def check_required_tools(tools):
    missing = [tool for tool in tools if not check_tool(tool)]
    if missing:
        print(f"{Fore.RED}[-] Missing required tools: {', '.join(missing)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] Install missing tools or remove them from the required list if you don't need them right now.{Style.RESET_ALL}")
        sys.exit(1)

def sanitize_filename(url):
    # remove scheme if present before sanitizing so folder names are tidy
    url = re.sub(r'^https?://', '', url)
    return re.sub(r'[^a-zA-Z0-9.-]', '_', url)

def handle_sigint(signal_received, frame):
    print(f"{Fore.RED}[!] Ctrl+C detected. Exiting...{Style.RESET_ALL}")
    sys.exit(0)

# -------------------------
# Target verification
# -------------------------
def is_target_up(user_target, timeout=8.0):
    """
    Checks whether the target is reachable. Accepts full URLs (with scheme) or bare domains.
    Returns the canonical URL (with scheme) that worked, or None if none responded.
    """
    print(f"{Fore.BLUE}[*] Verifying target is up: {user_target}{Style.RESET_ALL}")

    candidates = []
    if re.match(r'^https?://', user_target, re.I):
        candidates.append(user_target)
    else:
        candidates.append(f"https://{user_target}")
        candidates.append(f"http://{user_target}")

    for candidate in candidates:
        try:
            # use a fresh client per request to avoid any extra debug output
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(candidate)
                if resp.status_code < 400:
                    print(f"{Fore.GREEN}[+] Target responsive: {candidate} (HTTP {resp.status_code}){Style.RESET_ALL}")
                    return candidate
                else:
                    print(f"{Fore.YELLOW}[-] {candidate} returned HTTP {resp.status_code}{Style.RESET_ALL}")
        except Exception:
            # swallow and try next candidate
            continue

    print(f"{Fore.RED}[-] Target {user_target} is not reachable via HTTP/HTTPS.{Style.RESET_ALL}")
    return None

# -------------------------
# Tool runners
# -------------------------
def run_whatweb(target, output_dir):
    print(f"{Fore.MAGENTA}[whatweb] Starting...{Style.RESET_ALL}")
    whatweb_file = output_dir / "whatweb_results.txt"
    try:
        with open(whatweb_file, "w") as out:
            subprocess.run(["whatweb", "-v", target], stdout=out, stderr=subprocess.DEVNULL, check=True)
        print(f"{Fore.GREEN}[whatweb] Completed. Results: {whatweb_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[whatweb] Failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[whatweb] Unexpected error: {e}{Style.RESET_ALL}")

def run_nikto(target, output_dir, use_sudo=True):
    print(f"{Fore.MAGENTA}[nikto] Starting...{Style.RESET_ALL}")
    nikto_file = output_dir / "nikto_results.txt"
    try:
        with open(nikto_file, "w") as out:
            cmd = ["nikto", "-C", "all", "-host", target]
            if use_sudo:
                cmd.insert(0, "sudo")
            subprocess.run(cmd, stdout=out, stderr=subprocess.DEVNULL, check=True)
        print(f"{Fore.GREEN}[nikto] Completed. Results: {nikto_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[nikto] Failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[nikto] Unexpected error: {e}{Style.RESET_ALL}")

def run_waybackurls(target, output_dir):
    print(f"{Fore.MAGENTA}[waybackurls] Starting...{Style.RESET_ALL}")
    wayback_dir = output_dir / "wayback_results"
    wayback_dir.mkdir(parents=True, exist_ok=True)
    out_file = wayback_dir / f"{sanitize_filename(target)}.txt"
    try:
        with open(out_file, 'w') as out:
            subprocess.run(["waybackurls", target], stdout=out, stderr=subprocess.DEVNULL, check=True)
        print(f"{Fore.GREEN}[waybackurls] Completed. Results: {out_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[waybackurls] Failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[waybackurls] Unexpected error: {e}{Style.RESET_ALL}")

def run_dirsearch(target, output_dir, wordlist=None):
    print(f"{Fore.MAGENTA}[dirsearch] Starting...{Style.RESET_ALL}")
    dirsearch_dir = output_dir / "dirsearch_results"
    dirsearch_dir.mkdir(parents=True, exist_ok=True)
    out_file = dirsearch_dir / f"{sanitize_filename(target)}.txt"
    cmd = [
        "dirsearch", "-u", target,
        "-e", "php,asp,aspx,jsp,html,js,json",
        "--random-agent", "-t", "10", "-F",
        "-o", str(out_file)
    ]
    if wordlist:
        cmd.extend(["-w", wordlist])
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"{Fore.GREEN}[dirsearch] Completed. Results: {out_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[dirsearch] Failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[dirsearch] Unexpected error: {e}{Style.RESET_ALL}")

def run_eyewitness(target, output_dir):
    print(f"{Fore.MAGENTA}[eyewitness] Starting...{Style.RESET_ALL}")
    eyewitness_dir = output_dir / "eyewitness"
    eyewitness_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["eyewitness", "--web", "-f", target, "-d", str(eyewitness_dir), "--no-prompt"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"{Fore.GREEN}[eyewitness] Completed. Results: {eyewitness_dir}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[eyewitness] Failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[eyewitness] Unexpected error: {e}{Style.RESET_ALL}")

def run_nuclei(target, output_dir, template=None):
    print(f"{Fore.MAGENTA}[nuclei] Starting...{Style.RESET_ALL}")
    output_file = output_dir / "nuclei_results.txt"
    cmd = ["nuclei", "-u", target, "-es", "info,unknown", "-etags", "ssl,dns,http", "-o", str(output_file)]
    if template:
        cmd.extend(["-t", template])
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"{Fore.GREEN}[nuclei] Completed. Results: {output_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[nuclei] Failed.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[nuclei] Unexpected error: {e}{Style.RESET_ALL}")

# -------------------------
# Main
# -------------------------
def main():
    signal.signal(signal.SIGINT, handle_sigint)

    parser = argparse.ArgumentParser(description="WebRaptor — Single-target web application scanner")
    parser.add_argument("target", help="Target URL or domain (e.g. https://example.com or example.com)")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    parser.add_argument("--nuclei-template", help="Custom Nuclei template path")
    parser.add_argument("--wordlist", help="Custom wordlist path for Dirsearch")
    parser.add_argument("--threads", type=int, default=6, help="Max concurrent scans (default: 6)")
    parser.add_argument("--nikto-no-sudo", action="store_true", help="Run nikto without sudo (useful if sudo not available)")
    args = parser.parse_args()

    user_target = args.target.strip()

    # check target first
    canonical_target = is_target_up(user_target)
    if not canonical_target:
        print(f"{Fore.RED}[-] Aborting scans because target is not reachable: {user_target}{Style.RESET_ALL}")
        sys.exit(1)

    base_output = Path(args.output_dir) / sanitize_filename(canonical_target)
    base_output.mkdir(parents=True, exist_ok=True)

    print_banner()

    check_required_tools(["whatweb", "nikto", "dirsearch", "nuclei", "eyewitness", "waybackurls"])

    print(f"{Fore.CYAN}[~] Target confirmed: {canonical_target}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Starting scans...{Style.RESET_ALL}")

    tasks = [
        ("whatweb", run_whatweb, (canonical_target, base_output), {}),
        ("nikto", run_nikto, (canonical_target, base_output), {"use_sudo": not args.nikto_no_sudo}),
        ("waybackurls", run_waybackurls, (canonical_target, base_output), {}),
        ("dirsearch", run_dirsearch, (canonical_target, base_output), {"wordlist": args.wordlist}),
        ("eyewitness", run_eyewitness, (canonical_target, base_output), {}),
        ("nuclei", run_nuclei, (canonical_target, base_output), {"template": args.nuclei_template}),
    ]

    # Run tasks in parallel — do not duplicate start messages
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        future_to_name = {}
        for name, func, fargs, fkwargs in tasks:
            # submit only, don't print here (functions print their own start)
            future = executor.submit(func, *fargs, **fkwargs)
            future_to_name[future] = name

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                future.result()
                print(f"{Fore.GREEN}[{name}] Completed.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[{name}] Failed: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[+] All scans completed. Results in {base_output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
