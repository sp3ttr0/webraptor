# webraptor

WebRaptor is an automated tool to streamline web application security testing by combining reconnaissance and scanning modules into a single workflow.

It performs historical URL extraction, directory brute-forcing, screenshot capture, and vulnerability scanning with Nuclei. Results are saved in structured directories for easier analysis and reporting.

## Features
- Target Scanning
  - Scan domains or URLs directly.
  - (Planned) Support for multiple targets via list file input.
- Wayback URL
  - Extracts archived URLs from the Wayback Machine using waybackurls.
- Eyewitness
  - Captures website screenshots, provides server header information, and attempts      to identify default credentials if available.
- Dirsearch
  - Performs directory brute-forcing.
- Nuclei
  - Runs vulnerability scans using community or custom templates.
- Organized Output
  - Results are automatically grouped in structured directories.
 
## Requirements
Ensure the following tools are installed and available in your `PATH`:
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
python3 webraptor.py <domain>
```

### Options
- `--output-dir`: Specify the base directory for storing results (default: `results`).
- `--nuclei-template`: Specify a custom scan Nuclei template.
- `--wordlist`: Specify a custom wordlist for Dirsearch

### Example
```bash
python3 webraptor.py https://example.com --output-dir my_results --nuclei-template /path/to/templates --wordlist /path/to/wordlist.txt
```

## Output Structure
The script saves results in the following structure under the specified output directory:
```
<output-dir>/
  └── <target>/
      ├── wayback_results/       # Historical URLs from Wayback Machine
      ├── eyewitness/            # Screenshots and analysis
      ├── dirsearch_results/     # Directory brute-force results
      ├── nuclei_results.txt     # Vulnerability scan results
      └── scan.log               # Logging output
```

## Notes
- Ensure all required tools are installed and accessible via the command line.
- Support for multiple targets via the input file is planned.

## Disclaimer
This tool is provided for educational and authorized security testing purposes only.
Use it responsibly and only on systems you own or have explicit permission to test.
The developers are not responsible for misuse or damage caused by this tool.

## Work in Progress
This tool is still under active development. Features and functionality may change, and additional updates are planned to improve its efficiency and expand its capabilities.

## License
This project is open-source and distributed under the MIT License.
