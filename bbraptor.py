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


def check_required_tools(tools):
    missing = [tool for tool in tools if not check_tool(tool)]
    if missing:
        logging.error(f"{Fore.RED}[-] Missing required tools: {', '.join(missing)}{Style.RESET_ALL}")
        logging.info(f"{Fore.YELLOW}[i] Please install them via apt, brew, or go install, as appropriate.{Style.RESET_ALL}")
        sys.exit(1)


def sanitize_filename(url):
    # Remove http:// or https://
    url = re.sub(r'^https?://', '', url)
    # Replace slashes and other problematic characters
    return re.sub(r'[^a-zA-Z0-9.-]', '_', url)


def append_unique(filename, new_content):
    existing_content = set()
    path = Path(filename)
    if path.exists():
        existing_content = set(path.read_text().splitlines())

    new_lines = [line for line in new_content.splitlines() if line not in existing_content]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(existing_content.union(new_lines)) + "\n")


def add_https_scheme(input_file: Path, output_file: Path) -> None:
    """
    Reads subdomains from input_file, prepends 'https://' to each, and writes to output_file.
    """
    try:
        if not input_file.exists():
            logging.warning(f"{Fore.YELLOW}[!] {input_file} not found. Skipping HTTPS endpoint creation.{Style.RESET_ALL}")
            return

        with input_file.open("r") as f:
            subs = [line.strip() for line in f if line.strip()]

        https_endpoints = [f"https://{sub}" for sub in subs]
        output_file.write_text("\n".join(https_endpoints) + "\n")

    except Exception as e:
        logging.error(f"{Fore.RED}[-] Error creating HTTPS endpoints: {e}{Style.RESET_ALL}")


def list_subdomains(domain, output_dir):
    logging.info(f"{Fore.BLUE}[*] Finding subdomains...{Style.RESET_ALL}")
    output_dir.mkdir(parents=True, exist_ok=True)
    subdomains_path = output_dir / "subs.txt"

    # Sublist3r
    logging.info(f"{Fore.BLUE}[*] Using Sublist3r...{Style.RESET_ALL}")
    subprocess.run(["sublist3r", "-d", domain, "-o", str(subdomains_path)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Subfinder
    logging.info(f"{Fore.BLUE}[*] Using Subfinder...{Style.RESET_ALL}")
    subfinder_output = subprocess.run(["subfinder", "-d", domain, "-silent"],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    append_unique(subdomains_path, subfinder_output)

    # Amass
    logging.info(f"{Fore.BLUE}[*] Using Amass (passive)...{Style.RESET_ALL}")
    amass_raw_output = subprocess.run(
        ["amass", "enum", "-passive", "-d", domain],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    ).stdout.decode()
    
    # Extract only lines that are valid subdomains (e.g., end with the domain)
    amass_output = "\n".join(
        line.strip() for line in amass_raw_output.splitlines()
        if line.strip().endswith(f".{domain}") or line.strip() == domain
    )
    append_unique(subdomains_path, amass_output)
    
    # Assetfinder
    logging.info(f"{Fore.BLUE}[*] Using Assetfinder...{Style.RESET_ALL}")
    assetfinder_output = subprocess.run(["assetfinder", "--subs-only", domain],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    append_unique(subdomains_path, assetfinder_output)

    # Final deduplication and save
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
                            logging.info(f"{Fore.RED}[-] {sub} returned {response.status_code}{Style.RESET_ALL}")
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


def run_waybackurls(domains_file, output_dir):
    logging.info(f"{Fore.BLUE}[*] Running Wayback Machine URL collection...{Style.RESET_ALL}")
    wayback_dir = output_dir / "wayback_results"
    wayback_dir.mkdir(parents=True, exist_ok=True)

    try:
        with open(domains_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

        for domain in domains:
            sanitized_name = sanitize_filename(domain)
            out_file = wayback_dir / f"{sanitized_name}.txt"
            with open(out_file, 'w') as out:
                subprocess.run(["waybackurls", domain], stdout=out, stderr=subprocess.DEVNULL)
            logging.info(f"{Fore.GREEN}[+] Wayback URLs collected for {domain}{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"{Fore.RED}[-] Error during Wayback Machine collection: {e}{Style.RESET_ALL}")


def run_dirsearch(endpoint_file, output_dir, wordlist=None, threads=10):
    logging.info(f"{Fore.BLUE}[*] Running Dirsearch...{Style.RESET_ALL}")
    dirsearch_dir = output_dir / "dirsearch_results"
    dirsearch_dir.mkdir(parents=True, exist_ok=True)

    def scan(endpoint):
        sanitized_name = sanitize_filename(endpoint)
        out_file = dirsearch_dir / f"{sanitized_name}.txt"
        try:
            cmd = [
                "dirsearch",
                "-u", endpoint,
                "-e", "php,asp,aspx,jsp,html,js,json",
                "-i", "200,204,403",
                "-x", "400,404,500,502,429,581,503",
                "--random-agent",
                "--exclude-sizes=0B",
                "-t", "10",
                "-F",
                "-o", str(out_file)
            ]
            if wordlist:
                cmd.extend(["-w", wordlist])
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info(f"{Fore.GREEN}[+] Dirsearch completed for {endpoint}{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            logging.error(f"{Fore.RED}[-] Dirsearch failed for {endpoint}: {e}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"{Fore.RED}[-] Unexpected error with Dirsearch for {endpoint}: {e}{Style.RESET_ALL}")

    with open(endpoint_file, 'r') as f:
        endpoints = [line.strip() for line in f if line.strip()]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan, endpoints)


def run_eyewitness(endpoint_file, output_dir):
    logging.info(f"{Fore.BLUE}[*] Running EyeWitness...{Style.RESET_ALL}")
    eyewitness_dir = output_dir / "eyewitness"

    try:
        subprocess.run(["eyewitness", "--web", "-f", str(endpoint_file),
                        "-d", str(eyewitness_dir), "--no-prompt"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"{Fore.GREEN}[+] EyeWitness completed. Results in {eyewitness_dir}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        logging.error(f"{Fore.RED}[-] EyeWitness failed.{Style.RESET_ALL}")


def run_nuclei(endpoint_file, output_dir, template=None):
    logging.info(f"{Fore.BLUE}[*] Running Nuclei...{Style.RESET_ALL}")
    output_file = output_dir / "nuclei_results.txt"
    
    cmd = [
        "nuclei", 
        "-l", str(endpoint_file),
        "-es", "info,unknown",
        "-etags", "ssl,dns,http",
        "-o", str(output_file)
    ]

    if template:
        cmd.extend(["-t", template])

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"{Fore.GREEN}[+] Nuclei completed. Results saved to {output_file}{Style.RESET_ALL}")
    except subprocess.TimeoutExpired:
        logging.error(f"{Fore.RED}[-] Nuclei scan timed out.{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        logging.error(f"{Fore.RED}[-] Nuclei failed.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"{Fore.RED}[-] Unexpected error while running Nuclei: {e}{Style.RESET_ALL}")    


def main():

    signal.signal(signal.SIGINT, handle_sigint)
    
    parser = argparse.ArgumentParser(description="Bug Bounty Raptor")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    parser.add_argument("--nuclei-template", help="Custom Nuclei template path")
    parser.add_argument("--wordlist", help="Custom wordlist path for Dirsearch")
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

    check_required_tools(["sublist3r", "subfinder", "amass", "assetfinder", "dirsearch", "nuclei", "eyewitness", "waybackurls"])

    logging.info(f"{Fore.BLUE}[*] Starting reconnaissance on {domain}{Style.RESET_ALL}")

    list_subdomains(domain, base_output)
    live_subs = check_live_subdomains(base_output / "subs.txt")

    if not live_subs:
        logging.warning(f"{Fore.RED}[!] No live subdomains found. Exiting.{Style.RESET_ALL}")
        sys.exit(0)

    live_file = base_output / "subs_live.txt"
    live_file.write_text("\n".join(live_subs) + "\n")
    
    endpoint_file = base_output / "endpoints.txt"
    add_https_scheme(live_file, endpoint_file)

    run_waybackurls(live_file, base_output)
    run_eyewitness(endpoint_file, base_output)
    run_dirsearch(endpoint_file, base_output, wordlist=args.wordlist, threads=args.threads)
    run_nuclei(endpoint_file, base_output, args.nuclei_template)

    logging.info(f"{Fore.GREEN}[+] Scan completed. Results in {base_output}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
