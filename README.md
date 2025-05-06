# Sploitec Recon Tool

A modular reconnaissance tool designed for red team engagements. This tool automates common reconnaissance tasks and provides a foundation that can be extended with additional modules.

## Features

- Comprehensive subdomain discovery:
  - Passive enumeration using subfinder
  - Active enumeration using dnsx with wordlists
- IP resolution and mapping
- HTTP/HTTPS service detection and analysis
- Port scanning
- Vulnerability scanning (Currently disabled)
- Results export to JSON and HTML
- Multi-threaded scanning with optimized performance
- Interactive mode: Choose which scan phases to run

## TODO / Roadmap

The following improvements are planned for future development:

- [ ] Implement Nuclei-based vulnerability scanning with proper error handling and parallel scanning
- [ ] Add advanced reconnaissance capabilities including Google dorking and subdomain takeover detection
- [ ] Integrate additional discovery tools like Amass, Assetfinder, and cloud enumeration tools
- [ ] Enhance reporting with interactive dashboards and additional export formats
- [ ] Improve architecture with caching, database storage, and API interfaces
- [ ] Add screenshots and content discovery features for more comprehensive reconnaissance

## Requirements

The tool requires several external utilities that should be installed on your system:

- `subfinder` - for passive subdomain enumeration
- `dnsx` - for active subdomain enumeration and DNS resolution
- `httpx` - for HTTP/HTTPS service detection and analysis
- `nmap` - for port scanning
- `nuclei` - for vulnerability scanning (optional, currently not used)

## Installation

1. Clone this repository to your local machine:
```bash
git clone https://github.com/sploitec/srecon.git
cd srecon
```

2. Create and activate a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows
venv\Scripts\activate
# On Linux/macOS
source venv/bin/activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Install external tools:
```bash
# For Ubuntu/Debian
sudo apt install nmap dnsutils

# Install subfinder
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

# Install dnsx
GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx

# Install httpx
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx

# Install nuclei (optional)
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

5. Set up configuration files:
```bash
# Copy template config files and customize them with your API keys
cp config.yaml.template config.yaml
cp config/subfinder.yaml.template config/subfinder.yaml
# Edit config/subfinder.yaml and add your API keys
```

## Configuration

The tool uses configuration files to customize its behavior. The main configuration file is `config.yaml` in the root directory.

### Main Configuration (config.yaml)

This file contains settings for the tool's operation:

```yaml
# General settings
general:
  threads: 5                 # Default number of threads to use
  verbose: false             # Enable verbose output by default
  interactive: false         # Interactive mode: prompt before each scan phase

# Subdomain enumeration settings
subdomain_enumeration:
  wordlist: "wordlists/subdomains_top5000.txt"   # Path to active enumeration wordlist

# Port scanning settings
port_scan:
  scan_type: "top-1000"      # Port scan type: full, top-1000, top-100
  additional_args: "-T4"     # Additional nmap arguments
```

### API Configuration (config/subfinder.yaml)

This file contains API keys for various services used in passive subdomain enumeration.

## Usage

### Basic usage:

```bash
# Scan a single domain
python srecon.py -d example.com

# Scan multiple domains from a file
python srecon.py -f domains.txt

# Run in interactive mode
python srecon.py -d example.com -i
```

### Options:

```
usage: srecon.py [-h] (-d DOMAIN | -f FILE) [-o OUTPUT] [-t THREADS] [-v] [-i] [--config CONFIG]

Automated Reconnaissance Tool for Red Teaming

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain or IP address
  -f FILE, --file FILE  File containing list of targets (one per line)
  -o OUTPUT, --output OUTPUT
                        Custom output directory (default: results/target_timestamp)
  -t THREADS, --threads THREADS
                        Number of threads to use (default: from config or 5)
  -v, --verbose         Enable verbose output
  -i, --interactive     Interactive mode - prompt before each phase
  --config CONFIG       Path to custom config file
```

### Examples:

```bash
# Scan a single domain with 10 threads
python srecon.py -d example.com -t 10

# Specify custom output directory
python srecon.py -d example.com -o custom_output_dir

# Enable verbose output
python srecon.py -d example.com -v

# Run in interactive mode
python srecon.py -d example.com -i

# Scan multiple domains from a file
python srecon.py -f domains.txt -t 8
```

## Output

All scan results are stored in the `results` directory by default. For each scan, a new directory is created with the format `target_timestamp` that contains:

- `subdomains.txt` - List of discovered subdomains from passive techniques
- `active_enumerated_subdomains.txt` - List of subdomains discovered through active enumeration
- `ip_addresses.txt` - List of resolved IP addresses
- `ip_addresses.json` - Raw DNS resolution results from dnsx
- `http_services.txt` - Human-readable list of HTTP/HTTPS services with titles and technologies
- `http_services.json` - Detailed HTTP/HTTPS service information in JSON format
- `nmap_*.xml` - Raw nmap scan results for each IP
- `results.json` - Complete results in JSON format
- `report.html` - Comprehensive HTML report
- `summary.txt` - Summary of findings
- `recon.log` - Tool execution log

## Project Structure

```
srecon/
├── srecon.py         # Main script
├── requirements.txt  # Python dependencies
├── config.yaml       # Main configuration file
├── config/           # Tool configuration directory
│   └── *.template    # Configuration templates
├── wordlists/        # Directory containing wordlists for active enumeration
│   └── subdomains_top5000.txt  # Default subdomain wordlist
├── results/          # Directory containing all scan results (not tracked in git)
│   └── example.com_20230101_120000/  # Example scan result directory
├── venv/             # Virtual environment (not tracked in git)
├── README.md         # This file
└── .gitignore        # Git ignore configuration
```

## Interactive Mode

When running in interactive mode (`-i` flag), the tool will:

1. Always run passive subdomain enumeration first without prompting
2. Then prompt you before each subsequent scan phase:
   - Active subdomain enumeration
   - IP resolution
   - HTTP/HTTPS service probing
   - Port scanning
   - Vulnerability scanning

This allows you to selectively run only the phases you're interested in, which can be useful for:
- Focusing on specific aspects of reconnaissance
- Reducing noise and scan time
- Avoiding more aggressive scans in sensitive environments

## Extending the Tool

The code is designed to be modular. To add new functionality:

1. Create a new method in the ReconTool class
2. Update the run_recon method to include your new functionality
3. Add any new results to the results dictionary

## Security Considerations

- This tool is meant for authorized security testing only
- Always ensure you have permission to scan your targets
- Some scanning activities may be considered intrusive

## License

MIT License