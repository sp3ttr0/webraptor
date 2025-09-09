#!/usr/bin/env python3


# ===============================================================
# Raptor - Automated Web App Scanning Script
# ---------------------------------------------------------------
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# ===============================================================


import subprocess
import sys
import shutil
import re
import argparse
import logging
import signal
from pathlib import Path
from colorama import Fore, Style


def print_banner():
    banner = fr"""
    ⠀⠀⠀⠀⣠⣶⣶⠶⠖⠒⠒⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
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
    
    Bug Bounty Raptor 🦖 — Hunt Smarter, Not Harder
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")

def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def handle_sigint(signal_received, frame):
    logging.warning(f"{Fore.RED}[!] Ctrl+C detected. Exiting...{Style.RESET_ALL}")
    sys.exit(0)

def check_tool(tool):
    return shutil.which(tool) is not None 

def check_required_tools(tools):
    missing = [tool for tool in tools if not check_tool(tool)]
    if missing:
        logging.error(f"{Fore.RED}[-] Missing required tools: {', '.join(missing)}{Style.RESET_ALL}")
        sys.exit(1)

def sanitize_filename(url):
    return re.sub(r'[^a-zA-Z0-9.-]', '_', url)

def run_waybackurls(target, output_dir):
    logging.info(f"{Fore.BLUE}[*] Running Wayback Machine URL collection...{Style.RESET_ALL}")
    wayback_dir = output_dir / "wayback_results"
    wayback_dir.mkdir(parents=True, exist_ok=True)
    out_file = wayback_dir / f"{sanitize_filename(target)}.txt"
    with open(out_file, 'w') as out:
        subprocess.run(["waybackurls", target], stdout=out, stderr=subprocess.DEVNULL)
    logging.info(f"{Fore.GREEN}[+] Wayback URLs saved to {out_file}{Style.RESET_ALL}")

def run_dirsearch(target, output_dir, wordlist=None):
    logging.info(f"{Fore.BLUE}[*] Running Dirsearch...{Style.RESET_ALL}")
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
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info(f"{Fore.GREEN}[+] Dirsearch results saved to {out_file}{Style.RESET_ALL}")

def run_eyewitness(target, output_dir):
    logging.info(f"{Fore.BLUE}[*] Running EyeWitness...{Style.RESET_ALL}")
    eyewitness_dir = output_dir / "eyewitness"
    subprocess.run(["eyewitness", "--web", "-f", target, "-d", str(eyewitness_dir), "--no-prompt"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info(f"{Fore.GREEN}[+] EyeWitness report saved in {eyewitness_dir}{Style.RESET_ALL}")

def run_nuclei(target, output_dir, template=None):
    logging.info(f"{Fore.BLUE}[*] Running Nuclei...{Style.RESET_ALL}")
    output_file = output_dir / "nuclei_results.txt"
    cmd = ["nuclei", "-u", target, "-es", "info,unknown", "-etags", "ssl,dns,http", "-o", str(output_file)]
    if template:
        cmd.extend(["-t", template])
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info(f"{Fore.GREEN}[+] Nuclei results saved to {output_file}{Style.RESET_ALL}")

def main():
    signal.signal(signal.SIGINT, handle_sigint)

    parser = argparse.ArgumentParser(description="Raptor")
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    parser.add_argument("--nuclei-template", help="Custom Nuclei template path")
    parser.add_argument("--wordlist", help="Custom wordlist path for Dirsearch")
    args = parser.parse_args()

    target = args.target.strip()
    base_output = Path(args.output_dir) / sanitize_filename(target)
    base_output.mkdir(parents=True, exist_ok=True)

    log_file = base_output / "scan.log"
    setup_logging(log_file)

    print_banner()
    check_required_tools(["dirsearch", "nuclei", "eyewitness", "waybackurls"])

    logging.info(f"{Fore.BLUE}[*] Starting scan on {target}{Style.RESET_ALL}")

    run_waybackurls(target, base_output)
    run_dirsearch(target, base_output, wordlist=args.wordlist)
    run_eyewitness(target, base_output)
    run_nuclei(target, base_output, args.nuclei_template)

    logging.info(f"{Fore.GREEN}[+] Scan completed. Results in {base_output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()


