# Bug Bounty Raptor

Bug Bounty Raptor is an automated tool to streamline the bug bounty process by performing subdomain enumeration, checking for live subdomains, and running various scans, including Eyewitness, Dirsearch, and Nuclei. The results are saved in organized directories for further analysis.

## Features
- Subdomain Enumeration
  - Using `sublist3r`, `subfinder`, `assetfinder`, `amass`.
- Live Subdomain Check
  - Identifies active subdomains using HTTP requests.
- Wayback URL
  - Extracts historical URLs for each live subdomain from the Wayback Machine using     waybackurls. Useful for discovering hidden endpoints, parameters, deprecated        paths, and potential attack surfaces.
- Eyewitness
  - Captures website screenshots, provides server header information, and attempts      to identify default credentials if available.
- Dirsearch
  - Performs directory brute-forcing on live subdomains.
- Nuclei
  - Performs vulnerability scans using Nuclei templates.
- Organized Output
  - Results are saved in structured directories for each scan type.

## Requirements
Ensure the following tools are installed and available in your `PATH`:
- [sublist3r](https://github.com/aboul3la/Sublist3r)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [amass](https://github.com/owasp-amass/amass)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [eyewitness](https://github.com/RedSiege/EyeWitness)
- [dirsearch](https://github.com/maurosoria/dirsearch)
- [nuclei](https://github.com/projectdiscovery/nuclei)


### Python Libraries
Install the required Python libraries:
```bash
pip3 install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python3 bbraptor.py <domain>
```

### Options
- `--output-dir`: Specify the base directory for storing results (default: `results`).
- `--nuclei-template`: Specify a custom scan Nuclei template.
- `--threads`: Specify the max concurrent threads.

### Example
```bash
python3 bbraptor.py example.com --output-dir my_results --nuclei-template /path/to/custom-template --threads 20
```

## Output Structure
The script saves results in the following structure under the specified output directory:
```
<output-dir>/
  └── <domain>/
      ├── subs.txt             # All discovered subdomains
      ├── subs_live.txt        # Live subdomains
      ├── eyewitness_results/  # Eyewitness for each live subdomain
      ├── dirsearch_results/   # Dirsearch results for each live subdomain
      └── nuclei_results.txt   # Nuclei scan results
```

## Notes
- Ensure all required tools are installed and accessible via the command line.
- Please customize the script to include additional flags or features according to your requirements.

## Disclaimer
This script is provided for educational and ethical testing purposes only. You can use it strictly on systems you own or have explicit permission to test. The developers are not responsible for any misuse or damage caused by this tool.

## Work in Progress
This tool is still under active development. Features and functionality may change, and additional updates are planned to improve its efficiency and expand its capabilities.

## License
This script is open-source and distributed under the MIT License.
