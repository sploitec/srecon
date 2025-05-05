# Sploitec Recon Tool

A modular reconnaissance tool designed for red team engagements. This tool automates common reconnaissance tasks and provides a foundation that can be extended with additional modules.

## Features

- Subdomain enumeration
- IP resolution
- Port scanning
- Basic vulnerability scanning
- Results export to JSON and HTML
- Summary generation
- Multi-threaded scanning

## Requirements

The tool requires several external utilities that should be installed on your system:

- `subfinder` - for subdomain enumeration
- `host` - for DNS resolution
- `nmap` - for port scanning
- `nuclei` - for vulnerability scanning (optional)

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

# Install nuclei (optional)
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

5. Set up configuration files:
```bash
# Copy template config files and customize them with your API keys
cp config/subfinder.yaml.template config/subfinder.yaml
# Edit config/subfinder.yaml and add your API keys
```

## Usage

### Basic usage:

```bash
python srecon.py example.com
```

### Options:

```
usage: srecon.py [-h] [-o OUTPUT] [-t THREADS] [-v] target

Automated Reconnaissance Tool for Red Teaming

positional arguments:
  target                Target domain or IP address

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Custom output directory (default: results/target_timestamp)
  -t THREADS, --threads THREADS
                        Number of threads to use (default: 5)
  -v, --verbose         Enable verbose output
```

### Examples:

```bash
# Perform a complete scan with 10 threads
python srecon.py example.com -t 10

# Specify custom output directory
python srecon.py example.com -o custom_output_dir

# Enable verbose output
python srecon.py example.com -v
```

## Output

All scan results are stored in the `results` directory by default. For each scan, a new directory is created with the format `target_timestamp` that contains:

- `subdomains.txt` - List of discovered subdomains
- `ip_addresses.txt` - List of resolved IP addresses
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
├── config/           # Tool configuration directory
│   └── *.template    # Configuration templates
├── results/          # Directory containing all scan results (not tracked in git)
│   └── example.com_20230101_120000/  # Example scan result directory
├── venv/             # Virtual environment (not tracked in git)
├── README.md         # This file
└── .gitignore        # Git ignore configuration
```

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

