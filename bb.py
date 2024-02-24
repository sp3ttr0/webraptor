#!/usr/bin/env python3
import subprocess
import sys
import shutil
import requests
import re
from colorama import Fore, Style

domain = sys.argv[1]
nmap_output_folder = f"{domain}/nmap_results"

def is_valid_domain():
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

def list_subdomains():

    print(f"{Fore.BLUE}[*] Finding subdomains...{Style.RESET_ALL}")

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

    # Read subs.txt, sort, and remove duplicates
    with open(f"{domain}/subs.txt", "r") as file:
        subs_content = sorted(set(file.read().splitlines()))
    # Write sorted and unique subdomains back to subs.txt
    with open(f"{domain}/subs.txt", "w") as file:
        file.write("\n".join(subs_content))


def check_live_subdomains(subdomains_file):
    """
    Check live subdomains using requests library.

    Args:
    subdomains_file (str): Path to the file containing subdomains.

    Returns:
    list: List of live subdomains.
    """
    print(f"{Fore.BLUE}[*] Checking live subdomains...{Style.RESET_ALL}")
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
                print(f"{Fore.RED}Error: Connection Timeout.{Style.RESET_ALL}")
    return live_subdomains

def run_nmap():

    print(f"{Fore.BLUE}[*] Running nmap against live subdomains...{Style.RESET_ALL}")
    try:
        subprocess.run(["mkdir", nmap_output_folder], check=True)
    except subprocess.CalledProcessError:
        pass
    
    with open(f"{domain}/subs_live.txt", "r") as file:
        targets = file.readlines()
        targets = [target.strip() for target in targets if target.strip()]

    for target in targets:
        nmap_output_file = f"{nmap_output_folder}/{target}.txt"
        command = ["nmap", "-n", "-Pn", "-sV", "--script", "http-*,vuln*,auth,brute,exploit", "--min-rate", "1000", "-T4", "-oA", nmap_output_file, target]

        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
            print(result.stdout)
            print(f"{Fore.GREEN}[+] Nmap scan for {target} completed. Results saved to {nmap_output_file}{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[-] Error while running Nmap for {target}: {e.stderr}{Style.RESET_ALL}")

def run_nuclei():

    print(f"{Fore.BLUE}[*] Running nuclei against live subdomains...{Style.RESET_ALL}")
    # Define the subprocess command
    nuclei_command = ["nuclei", "-l", f"{domain}/subs_live.txt", "-etags", "ssl,dns,header,security", "-silent", "-o", "{domain}/nuclei.txt"]
    
    # Run the Nuclei process
    nuclei_process = subprocess.Popen(nuclei_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Process the output while running
    for stdout_line in nuclei_process.stdout:
        sys.stdout.write(stdout_line)
        sys.stdout.flush()
    
    # Wait for the process to finish
    nuclei_process.communicate()
    
    # Check if the process has finished successfully
    if nuclei_process.returncode == 0:
        print(f"{Fore.GREEN}[+] Nuclei tests completed.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Error while running Nuclei.{Style.RESET_ALL}")
        
def main():

    if not is_valid_domain():
        print(f"{Fore.RED}[-] Error: Invalid domain name.{Style.RESET_ALL}")
        sys.exit(1)

    # Check if required tools are available
    required_tools = ['sublist3r', 'subfinder', 'assetfinder', 'nmap', 'nuclei']
    for tool in required_tools:
        if not check_tool(tool):
            print(f"{Fore.RED}[-] Error: {tool} is not installed or not available in the system.{Style.RESET_ALL}")
            sys.exit(1)
    
    print(f"{Fore.BLUE}[*] Start checking for domain: {domain}{Style.RESET_ALL}")

    # Create directory for the domain
    subprocess.run(["mkdir", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # List subdomains
    list_subdomains()

    # Check live subdomains 
    live_subdomains = check_live_subdomains(f"{domain}/subs.txt")
    with open(f"{domain}/subs_live.txt", "w") as file:
        for subdomain in live_subdomains:
            file.write(subdomain + "\n")

    # Run vulnerability scanner
    run_nmap()
    run_nuclei()


    print(f"{Fore.GREEN}Done!{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.RED}[*] Usage: python3 bb.py <domain>{Style.RESET_ALL}")
        sys.exit(1)
    main()
