#!/usr/bin/env python3

import subprocess
import sys
import shutil
import requests
import re
from colorama import Fore, Style

def is_valid_domain(domain):
    """
    Check if the input string is a valid domain name.

    Args:
    domain (str): The domain name to validate.

    Returns:
    bool: True if the input is a valid domain name, False otherwise.
    """
    pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$"
    return re.match(pattern, domain) is not None

def check_tool(tool):
    """
    Check if the specified tool is available in the system.

    Args:
    tool (str): The name of the tool to check.

    Returns:
    bool: True if the tool is available, False otherwise.
    """
    return shutil.which(tool) is not None

def append_unique(filename, new_content):
    """
    Append unique content to a file, avoiding duplicates.

    Args:
    filename (str): The name of the file to append to.
    new_content (str): The new content to append.

    Returns:
    None
    """
    # Read existing content, if any
    existing_content = set()
    try:
        with open(filename, 'r') as file:
            existing_content = set(file.read().splitlines())
    except FileNotFoundError:
        pass

    # Append new content that doesn't already exist
    new_content_lines = [line for line in new_content.splitlines() if line not in existing_content]

    # Append new content to existing content
    with open(filename, 'a') as file:
        for line in new_content_lines:
            file.write(line + '\n')

def check_live_subdomains(subdomains_file):
    """
    Check live subdomains using requests library.

    Args:
    subdomains_file (str): Path to the file containing subdomains.

    Returns:
    list: List of live subdomains.
    """
    live_subdomains = []
    with open(subdomains_file, "r") as file:
        for line in file:
            subdomain = line.strip()
            print(f"{Fore.BLUE}[*] Checking {subdomain}...{Style.RESET_ALL}", end=" ")
            try:
                response = requests.get(f"https://{subdomain}", timeout=10)
                if response.status_code == 200 or response.status_code == 403:
                    print(f"{Fore.GREEN}Status: Live (HTTP {response.status_code}){Style.RESET_ALL}")
                    live_subdomains.append(subdomain)
                else:
                    print(f"{Fore.RED}Status: Not Live (HTTP {response.status_code}){Style.RESET_ALL}")
            except requests.RequestException as e:
                print(f"{Fore.RED}Error: ({e}){Style.RESET_ALL}")
    return live_subdomains

def run_nuclei(domain):

    print(f"{Fore.BLUE}[*] Running nuclei against live subdomains...{Style.RESET_ALL}")
    # Run nuclei against live subdomains
    nuclei_process = subprocess.Popen(["nuclei", "-l", f"{domain}/alive.txt", "-es", "info", "-silent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Display progress
    for stdout_line in iter(nuclei_process.stdout.readline, b''):
        sys.stdout.write(stdout_line.decode())
        sys.stdout.flush()

    nuclei_output, nuclei_error = nuclei_process.communicate()
    
    # Check if there was an error
    if nuclei_error:
        print(f"{Fore.RED}[-] Error while running Nuclei: {nuclei_error.decode()}{Style.RESET_ALL}")
    else:
        with open(f"{domain}/nuclei.txt", "w") as nuclei_file:
            nuclei_file.write(nuclei_output.decode())
            print(f"{Fore.GREEN}[+] Nuclei tests completed.{Style.RESET_ALL}")


def main(domain):
    """
    Main function to perform reconnaissance on the specified domain.

    Args:
    domain (str): The domain to perform reconnaissance on.

    Returns:
    None
    """
    if not is_valid_domain(domain):
        print(f"{Fore.RED}[-] Error: Invalid domain name.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.BLUE}[*] Start checking for domain: {domain}{Style.RESET_ALL}")

    # Check if required tools are available
    required_tools = ['sublist3r', 'subfinder', 'assetfinder', 'amass', 'nuclei']
    for tool in required_tools:
        if not check_tool(tool):
            print(f"{Fore.RED}[-] Error: {tool} is not installed or not available in the system.{Style.RESET_ALL}")
            sys.exit(1)

    # Create directory for the domain
    subprocess.run(["mkdir", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(f"{Fore.BLUE}[*] Finding subdomains...{Style.RESET_ALL}")
    # Find subdomains using various tools
    print(f"{Fore.BLUE}[*] Listing subdomains using sublist3r...{Style.RESET_ALL}")
    subprocess.run(["sublist3r", "-d", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"{Fore.GREEN}[+] sublist3r completed.{Style.RESET_ALL}")

    print(f"{Fore.BLUE}[*] Listing subdomains using subfinder...{Style.RESET_ALL}")
    subfinder_output = subprocess.run(["subfinder", "-d", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
    append_unique(f"{domain}/subs.txt", subfinder_output)
    print(f"{Fore.GREEN}[+] subfinder completed.{Style.RESET_ALL}")

    print(f"{Fore.BLUE}[*] Listing subdomains using  assetfinder...{Style.RESET_ALL}")
    assetfinder_output = subprocess.run(["assetfinder", "-subs-only", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
    append_unique(f"{domain}/subs.txt", assetfinder_output)
    print(f"{Fore.GREEN}[+] assetfinder completed.{Style.RESET_ALL}")

    print(f"{Fore.BLUE}[*] Listing subdomains using amass...{Style.RESET_ALL}")
    amass_output = subprocess.run(["amass", "enum", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
    append_unique(f"{domain}/subs.txt", amass_output)
    print(f"{Fore.GREEN}[+] amass completed.{Style.RESET_ALL}")

    # Read subs.txt, sort, and remove duplicates
    with open(f"{domain}/subs.txt", "r") as file:
        subs_content = sorted(set(file.read().splitlines()))
    # Write sorted and unique subdomains back to subs.txt
    with open(f"{domain}/subs.txt", "w") as file:
        file.write("\n".join(subs_content))

    print(f"{Fore.BLUE}[*] Checking live subdomains...{Style.RESET_ALL}")
    # Check live subdomains using requests library
    live_subdomains = check_live_subdomains(f"{domain}/subs.txt")
    with open(f"{domain}/alive.txt", "w") as file:
        for subdomain in live_subdomains:
            file.write(subdomain + "\n")

    run_nuclei(domain)

    print(f"{Fore.GREEN}Done!{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.RED}[*] Usage: python3 bb.py <domain>{Style.RESET_ALL}")
        sys.exit(1)
    main(sys.argv[1])
