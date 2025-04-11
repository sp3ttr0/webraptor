#!/usr/bin/env python3


# ===============================================================
# Bug Bounty Raptor - Automated Bug Bounty Scanning Script
# ---------------------------------------------------------------
# This script automates the bug bounty reconnaissance process,
# performing subdomain enumeration, live subdomain checks
# and comprehensive scanning tools such as NMAP, Eyewitness, 
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


def print_banner():
    banner = r"""
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
    ⠀⠀⠀⠀⠀⠀⠈⣉⡙⠒⢚⣒⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⡧⠻⠤⠿⡷⠀ by sp3ttr0⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
        Bug Bounty Raptor 🦖 — Hunt Smarter, Not Harder
    """
    print(f"{Fore.LIGHTYELLOW_EX}{banner}{Style.RESET_ALL}")



def is_valid_domain(domain):
    pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,}$"
    return re.match(pattern, domain) is not None


def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


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
    print(f"{Fore.BLUE}[*] Finding subdomains...{Style.RESET_ALL}")
    output_dir.mkdir(parents=True, exist_ok=True)
    subdomains_path = output_dir / "subs.txt"

    print(f"{Fore.BLUE}[*] Listing subdomains using sublist3r...{Style.RESET_ALL}")
    subprocess.run(["sublist3r", "-d", domain, "-o", str(subdomains_path)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"{Fore.BLUE}[*] Listing subdomains using subfinder...{Style.RESET_ALL}")
    subfinder_output = subprocess.run(["subfinder", "-d", domain, "-silent"],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode()
    append_unique(subdomains_path, subfinder_output)

    unique_subs = sorted(set(subdomains_path.read_text().splitlines()))
    subdomains_path.write_text("\n".join(unique_subs) + "\n")
    print(f"{Fore.GREEN}[+] Total unique subdomains found: {len(unique_subs)}{Style.RESET_ALL}")


def check_live_subdomains(subdomains_file):
    print(f"{Fore.BLUE}[*] Checking live subdomains...{Style.RESET_ALL}")

    def check(sub):
        try:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                for scheme in ["https://", "http://"]:
                    try:
                        response = client.get(f"{scheme}{sub}")
                        if response.status_code < 400:
                            print(f"{Fore.GREEN}[+] Live: {scheme}{sub}{Style.RESET_ALL}")
                            return sub
                    except httpx.RequestError:
                        continue
        except Exception:
            pass
        return None

    subdomains = Path(subdomains_file).read_text().splitlines()
    with ThreadPoolExecutor() as executor:
        live = [sub for sub in executor.map(check, subdomains) if sub]

    print(f"{Fore.GREEN}[+] Total live subdomains: {len(live)}{Style.RESET_ALL}")
    return live

def run_nmap(subdomains, output_dir):
    print(f"{Fore.BLUE}[*] Running Nmap...{Style.RESET_ALL}")
    portscan_dir = output_dir / "nmap_results"
    portscan_dir.mkdir(parents=True, exist_ok=True)

    def scan(sub):
        out_file = portscan_dir / f"{sub}.txt"
        try:
            result = subprocess.run(["nmap", "-sV", "--top-ports", "3000", "-T4", "-Pn", sub],
                                    capture_output=True, text=True, check=True)
            out_file.write_text(result.stdout)
            print(f"{Fore.GREEN}[+] Nmap scan completed for {sub}. Results in {out_file}{Style.RESET_ALL}")
        except subprocess.CalledProcessError:
            out_file.write_text("Nmap scan failed.\n")
            print(f"{Fore.RED}[-] Nmap scan failed for {sub}{Style.RESET_ALL}")

    with ThreadPoolExecutor() as executor:
        executor.map(scan, subdomains)


def run_dirsearch(live_subdomains, output_dir, threads):
    print(f"{Fore.BLUE}[*] Running Dirsearch...{Style.RESET_ALL}")
    dirsearch_dir = output_dir / "dirsearch_results"
    dirsearch_dir.mkdir(parents=True, exist_ok=True)

    def scan(sub):
        out_file = dirsearch_dir / f"{sub}.txt"
        subprocess.run(["dirsearch", 
                        "-u", f"https://{sub}",
                        "-i", "200,204,403,443", "-x", "500,502,429,581,503",
                        "--deep-recursive", "--force-recursive",
                        '-e', "conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old.sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml",
                        "-R", "5", "--random-agent", "--exclude-sizes=0B", "-t", "50", "-F", 
                        "-o", str(out_file)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{Fore.GREEN}[+] Dirsearch completed for {sub}. Results in {out_file}{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan, live_subdomains)


def run_eyewitness(live_subdomains, output_dir):
    print(f"{Fore.BLUE}[*] Running EyeWitness...{Style.RESET_ALL}")
    eyewitness_dir = output_dir / "eyewitness"
    url_list_file = output_dir / "eyewitness_urls.txt"

    # Write https:// URLs to file
    with url_list_file.open("w") as f:
        for sub in live_subdomains:
            f.write(f"https://{sub}\n")

    try:
        subprocess.run(["eyewitness", "--web", "-f", str(url_list_file),
                        "-d", str(eyewitness_dir), "--no-prompt"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{Fore.GREEN}[+] EyeWitness completed. Results in {eyewitness_dir}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] EyeWitness failed.{Style.RESET_ALL}")


def run_nuclei(live_subdomains_file, output_dir, template=None):
    print(f"{Fore.BLUE}[*] Running Nuclei...{Style.RESET_ALL}")
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
        print(f"{Fore.GREEN}[+] Nuclei completed. Results saved to {output_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] Nuclei failed.{Style.RESET_ALL}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Bug Bounty Raptor")
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--output-dir", default="results", help="Output directory")
    parser.add_argument("--nuclei-template", help="Custom Nuclei template path")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent threads")
    args = parser.parse_args()

    domain = extract_domain(args.target)

    if not is_valid_domain(domain):
        print(f"{Fore.RED}[-] Invalid domain: {domain}{Style.RESET_ALL}")
        sys.exit(1)

    for tool in ["sublist3r", "subfinder", "dirsearch", "nuclei", "eyewitness", "nmap"]:
        if not check_tool(tool):
            print(f"{Fore.RED}[-] Missing tool: {tool}{Style.RESET_ALL}")
            sys.exit(1)

    base_output = Path(args.output_dir) / domain

    print(f"{Fore.BLUE}[*] Starting reconnaissance on {domain}{Style.RESET_ALL}")

    list_subdomains(domain, base_output)
    live_subs = check_live_subdomains(base_output / "subs.txt")

    if not live_subs:
        print(f"{Fore.YELLOW}[!] No live subdomains found. Exiting.{Style.RESET_ALL}")
        sys.exit(0)

    live_file = base_output / "subs_live.txt"
    live_file.write_text("\n".join(live_subs) + "\n")

    
    run_nmap(live_subs, base_output)
    run_eyewitness(live_subs, base_output)
    run_dirsearch(live_subs, base_output, args.threads)
    run_nuclei(live_file, base_output, args.nuclei_template)

    
    print(f"{Fore.GREEN}[+] Scan completed. Results in {base_output}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
