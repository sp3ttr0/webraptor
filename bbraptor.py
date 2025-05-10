#!/usr/bin/env python3


# ===============================================================
# Bug Bounty Raptor - Automated Bug Bounty Scanning Script
# ---------------------------------------------------------------
# This script automates the bug bounty reconnaissance process,
# performing subdomain enumeration, live subdomain checks
# and comprehensive scanning tools such as Eyewitness, 
# Dirsearch, and Nuclei. It utilizes Python alongside powerful 
# external tools to help network administrators and pentesters 
# identify potential vulnerabilities in target domains.
#
# Author: Howell King Jr. | Github: https://github.com/sp3ttr0
# ===============================================================


import subprocess
import sys
import shutil
import re
import httpx
from urllib.parse import urlparse
from colorama import Fore, Style
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import logging
import signal


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
    logging.warning(f"{Fore.RED}[!] Ctrl+C detected. Exiting gracefully...{Style.RESET_ALL}")
    sys.exit(0)


def is_valid_domain(domain):
    pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,}$"
    return re.match(pattern, domain) is not None


def check_tool(tool):
    return shutil.which(tool) is not None 


def append_unique(filename, new_content):
    existing_content = set()
    path = Path(filename)
    if path.exists():
        existing_content = set(path.read_text().splitlines())

    new_lines = [line for line in new_content.splitlines() if line not in existing_content]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(existing_content.union(new_lines)) + "\n")


def list_subdomains(domain, output_dir):
    logging.info(f"{Fore.BLUE}[*] Finding subdomains...{Style.RESET_ALL}")
    output_dir.mkdir(parents=True, exist_ok=True)
    subdomains_path = output_dir / "subs.txt"

    logging.info(f"{Fore.BLUE}[*] Listing subdomains using sublist3r...{Style.RESET_ALL}")
    subprocess.run(["sublist3r", "-d", domain, "-o", str(subdomains_path)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    logging.info(f"{Fore.BLUE}[*] Listing subdomains using subfinder...{Style.RESET_ALL}")
    subfinder_output = subprocess.run(["subfinder", "-d", domain, "-silent"],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    append_unique(subdomains_path, subfinder_output)

    unique_subs = sorted(set(subdomains_path.read_text().splitlines()))
    subdomains_path.write_text("\n".join(unique_subs) + "\n")
    logging.info(f"{Fore.BLUE}[+] Total unique subdomains found: {len(unique_subs)}{Style.RESET_ALL}")

def check_live_subdomains(subdomains_file):
    logging.info(f"{Fore.BLUE}[*] Checking live subdomains...{Style.RESET_ALL}")

    def check(sub):
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                for scheme in ["https://", "http://"]:
                    try:
                        response = client.get(f"{scheme}{sub}")
                        if response.status_code < 400:
                            logging.info(f"{Fore.GREEN}[+] Live: {scheme}{sub}{Style.RESET_ALL}")
                            return sub
                        else:
                            logging.info(f"{Fore.RED}[+] {sub} returned {status}{Style.RESET_ALL}")
                    except httpx.RequestError:
                        continue
        except Exception:
            pass
        return None

    subdomains = Path(subdomains_file).read_text().splitlines()
    with ThreadPoolExecutor() as executor:
        live = [sub for sub in executor.map(check, subdomains) if sub]

    logging.info(f"{Fore.BLUE}[+] Total live subdomains: {len(live)}{Style.RESET_ALL}")
    return live

def run_dirsearch(live_subdomains, output_dir, threads):
    logging.info(f"{Fore.BLUE}[*] Running Dirsearch...{Style.RESET_ALL}")
    dirsearch_dir = output_dir / "dirsearch_results"
    dirsearch_dir.mkdir(parents=True, exist_ok=True)

    def scan(sub):
        out_file = dirsearch_dir / f"{sub}.txt"
        subprocess.run(["dirsearch", 
                        "-u", f"https://{sub}",
                        "-i", "200,204,403", "-x", "400,404,500,502,429,581,503",
                        "--random-agent", "--exclude-sizes=0B", "-t", "50", "-F", 
                        "-o", str(out_file)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"{Fore.GREEN}[+] Dirsearch completed for {sub}{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan, live_subdomains)

def run_eyewitness(live_subdomains, output_dir):
    logging.info(f"{Fore.BLUE}[*] Running EyeWitness...{Style.RESET_ALL}")
    eyewitness_dir = output_dir / "eyewitness"
    url_list_file = output_dir / "eyewitness_urls.txt"

    with url_list_file.open("w") as f:
        for sub in live_subdomains:
            f.write(f"https://{sub}\n")

    try:
        subprocess.run(["eyewitness", "--web", "-f", str(url_list_file),
                        "-d", str(eyewitness_dir), "--no-prompt"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"{Fore.GREEN}[+] EyeWitness completed. Results in {eyewitness_dir}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        logging.error(f"{Fore.RED}[-] EyeWitness failed.{Style.RESET_ALL}")

def run_nuclei(live_subdomains_file, output_dir, template=None):
    logging.info(f"{Fore.BLUE}[*] Running Nuclei...{Style.RESET_ALL}")
    output_file = output_dir / "nuclei_results.txt"

    cmd = [
        "nuclei", 
        "-l", str(live_subdomains_file), 
        "-etags", "ssl,dns,security-headers", 
        "-severity", "medium,high,critical",
        "-silent", 
        "-o", str(output_file)
    ]

    if template:
        cmd.extend(["-t", template])

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"{Fore.GREEN}[+] Nuclei completed. Results saved to {output_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        logging.error(f"{Fore.RED}[-] Nuclei failed.{Style.RESET_ALL}")

def main():

    signal.signal(signal.SIGINT, handle_sigint)
    
    parser = argparse.ArgumentParser(description="Bug Bounty Raptor")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    parser.add_argument("--nuclei-template", help="Custom Nuclei template path")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent threads")
    args = parser.parse_args()

    domain = args.target.strip().lower()
    
    base_output = Path(args.output_dir) / domain
    base_output.mkdir(parents=True, exist_ok=True)

    # Setup logging AFTER directory exists
    log_file = base_output / "recon.log"
    setup_logging(log_file)


    print_banner()

    if not is_valid_domain(domain):
        logging.error(f"{Fore.RED}[-] Invalid domain format: {domain}{Style.RESET_ALL}")
        sys.exit(1)

    for tool in ["sublist3r", "subfinder", "dirsearch", "nuclei", "eyewitness"]:
        if not check_tool(tool):
            logging.error(f"{Fore.RED}[-] Missing tool: {tool}{Style.RESET_ALL}")
            sys.exit(1)
    
    logging.info(f"{Fore.BLUE}[*] Starting reconnaissance on {domain}{Style.RESET_ALL}")

    list_subdomains(domain, base_output)
    live_subs = check_live_subdomains(base_output / "subs.txt")

    if not live_subs:
        logging.warning(f"{Fore.RED}[!] No live subdomains found. Exiting.{Style.RESET_ALL}")
        sys.exit(0)

    live_file = base_output / "subs_live.txt"
    live_file.write_text("\n".join(live_subs) + "\n")

    run_eyewitness(live_subs, base_output)
    run_dirsearch(live_subs, base_output, args.threads)
    run_nuclei(live_file, base_output, args.nuclei_template)

    logging.info(f"{Fore.GREEN}[+] Scan completed. Results in {base_output}{Style.RESET_ALL}")
    
if __name__ == "__main__":
    main()
