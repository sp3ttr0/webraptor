#!/usr/bin/env python3

# ===============================================================
# Bug Bounty Raptor - Automated Bug Bounty Scanning Script
# ---------------------------------------------------------------
# This script automates the bug bounty reconnaissance process, 
# performing subdomain enumeration, live subdomain checks, 
# and comprehensive scanning with tools such as Nmap, Nuclei, 
# and Dirsearch. It utilizes Python alongside powerful external 
# tools to help network administrators and pentesters identify 
# potential vulnerabilities in target domains.
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

# Validate domain name
def is_valid_domain(domain):
    pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$"
    return re.match(pattern, domain) is not None

# Check if a tool is available
def check_tool(tool):
    return shutil.which(tool) is not None and subprocess.run([tool, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0

# Check if a file is empty
def is_file_empty(file_path):
    try:
        with open(file_path, 'r') as file:
            return not any(file.read())
    except FileNotFoundError:
        return True

# Append unique lines to a file
def append_unique(filename, new_content):
    existing_content = set()
    try:
        with open(filename, 'r') as file:
            existing_content = set(file.read().splitlines())
    except FileNotFoundError:
        pass

    new_content_lines = [line for line in new_content.splitlines() if line not in existing_content]

    with open(filename, 'a') as file:
        for line in new_content_lines:
            file.write(line + '\n')

# List subdomains
def list_subdomains(domain, output_dir):
    print(f"{Fore.BLUE}[*] Finding subdomains...{Style.RESET_ALL}")
    subprocess.run(["mkdir", "-p", output_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    subdomains_path = f"{output_dir}/subs.txt"
    
    print(f"{Fore.BLUE}[*] Listing subdomains using sublist3r...{Style.RESET_ALL}")
    subprocess.run(["sublist3r", "-d", domain, "-o", f"{output_dir}/subs.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    print(f"{Fore.BLUE}[*] Listing subdomains using subfinder...{Style.RESET_ALL}")
    subfinder_output = subprocess.run(["subfinder", "-d", domain, "-silent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
    append_unique(subdomains_path, subfinder_output)
    
    with open(subdomains_path, "r") as file:
        unique_subs = sorted(set(line.strip() for line in file if line.strip()))
    with open(subdomains_path, "w") as file:
        file.write("\n".join(unique_subs))

    print(f"{Fore.GREEN}[+] Total unique subdomains found: {len(unique_subs)}{Style.RESET_ALL}")

# Check live subdomains
def check_live_subdomains(subdomains_file):
    print(f"{Fore.BLUE}[*] Checking live subdomains...{Style.RESET_ALL}")
    live_subdomains = []

    def check_subdomain(subdomain):
        try:
            with httpx.Client(timeout=15, follow_redirects=True) as client:
                response = client.get(f"https://{subdomain}")
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Live: {subdomain}{Style.RESET_ALL}")
                    return subdomain
        except httpx.RequestError:
            pass
        return None

    with open(subdomains_file, "r") as file:
        subdomains = [line.strip() for line in file]

    with ThreadPoolExecutor() as executor:
        results = executor.map(check_subdomain, subdomains)

    live_subdomains = [result for result in results if result]
    return live_subdomains

# Run Nmap scans
def run_nmap(domain, live_subdomains, output_dir):
    print(f"{Fore.BLUE}[*] Running Nmap scans...{Style.RESET_ALL}")
    subprocess.run(["mkdir", "-p", f"{output_dir}/nmap_results"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def scan_target(target):
        nmap_output_file = f"{output_dir}/nmap_results/{target}.txt"
        command = ["nmap", "-n", "-sV", "--script", "http*", "--min-rate", "1000", "-T4", "-oN", nmap_output_file, target]
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            print(f"{Fore.GREEN}[+] Nmap completed for {target}. Results saved to {nmap_output_file}{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Nmap error for {target}: {e.stderr}{Style.RESET_ALL}")

    with ThreadPoolExecutor() as executor:
        executor.map(scan_target, live_subdomains)

# Run Nuclei scans
def run_nuclei(domain, live_subdomains, output_dir, nuclei_template):
    print(f"{Fore.BLUE}[*] Running Nuclei scans...{Style.RESET_ALL}")
    nuclei_output = f"{output_dir}/nuclei_results.txt"
    try:
        nuclei_command = [
            "nuclei", "-l", f"{output_dir}/subs_live.txt",
            "-etags", "ssl,dns,security-headers",
            "-silent", "-o", nuclei_output
        ]
        if nuclei_template:
            nuclei_command.extend(["-t", nuclei_template])
        subprocess.run(nuclei_command, check=True)
        print(f"{Fore.GREEN}[+] Nuclei completed. Results saved to {nuclei_output}{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[-] Nuclei error: {e.stderr}{Style.RESET_ALL}")

# Run Dirsearch scans
def run_dirsearch(live_subdomains, output_dir):
    print(f"{Fore.BLUE}[*] Running Dirsearch on live subdomains...{Style.RESET_ALL}")
    
    def dirsearch_scan(subdomain):
        print(f"{Fore.BLUE}[*] Brute-forcing directories for {subdomain}...{Style.RESET_ALL}")
        output_file = f"{output_dir}/dirsearch_results/{subdomain}.txt"
        dirsearch_command = [
            "dirsearch", "-u", f"https://{subdomain}",
            "-i", "200,204,403,443", "-x", "500,502,429,581,503", 
            "-R", "5", "--random-agent", "-t", "50", "-F", "-o", output_file
        ]
        subprocess.run(dirsearch_command)
        print(f"{Fore.GREEN}[+] Dirsearch results for {subdomain} saved to {output_file}{Style.RESET_ALL}")
    
    subprocess.run(["mkdir", "-p", f"{output_dir}/dirsearch_results"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    with ThreadPoolExecutor() as executor:
        executor.map(dirsearch_scan, live_subdomains)

# Extract domain from URL
def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
    return domain

# Validate domain name (supports full URLs)
def is_valid_domain(domain):
    pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$"
    return re.match(pattern, domain) is not None

# Main function
def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Raptor")
    parser.add_argument("target", help="Target domain or URL (http://example.com or example.com)")
    parser.add_argument("--output-dir", default="results", help="Base directory for storing results")
    parser.add_argument("--nuclei-template", default=None, help="Custom Nuclei template to use for scans")
    args = parser.parse_args()
    domain = extract_domain(args.target)

    required_tools = ["sublist3r", "subfinder", "nmap", "nuclei", "dirsearch"]
    for tool in required_tools:
        if not check_tool(tool):
            print(f"{Fore.RED}[-] Error: {tool} is not installed or not available.{Style.RESET_ALL}")
            sys.exit(1)
    
    if not is_valid_domain(domain):
        print(f"{Fore.RED}[-] Invalid domain name.{Style.RESET_ALL}")
        sys.exit(1)

    output_dir = f"{args.output_dir}/{domain}"

    print(f"{Fore.BLUE}[*] Starting scans for {domain}{Style.RESET_ALL}")
    
    list_subdomains(domain, output_dir)
    live_subdomains = check_live_subdomains(f"{output_dir}/subs.txt")

    if not live_subdomains:
        print(f"{Fore.YELLOW}[!] No live subdomains found. Exiting.{Style.RESET_ALL}")
        sys.exit()
    
    with open(f"{output_dir}/subs_live.txt", "w") as file:
        file.write("\n".join(live_subdomains) + "\n")

    run_nmap(domain, live_subdomains, output_dir)
    run_dirsearch(live_subdomains, output_dir)
    run_nuclei(domain, live_subdomains, output_dir, args.nuclei_template)

    print(f"{Fore.GREEN}[+] All tasks completed. Results saved in {output_dir}.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
