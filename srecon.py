#!/usr/bin/env python3
# Automated Recon Tool for Red Teaming

import os
import sys
import argparse
import json
import subprocess
import time
import logging
import shutil
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Suppress SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconTool:
    def __init__(self, target, output_dir=None, threads=5, verbose=False):
        """Initialize the recon tool with target and parameters."""
        self.target = target
        self.threads = threads
        self.verbose = verbose
        
        # Create results directory if it doesn't exist
        if not os.path.exists("results"):
            os.makedirs("results")
        
        # Set up output directory
        if output_dir:
            # For custom output directory, create a subdirectory for each target
            if os.path.exists(output_dir) and os.path.isdir(output_dir):
                # If output_dir exists and it's a directory, create a subdirectory for the target
                target_dir = target.replace(':', '_').replace('/', '_').replace('\\', '_')
                self.output_dir = os.path.join(output_dir, target_dir)
            else:
                # If output_dir doesn't exist or isn't a directory, use it directly
                self.output_dir = output_dir
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join("results", f"{self.target}_{timestamp}")
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Set up logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(self.output_dir, "recon.log")),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("ReconTool")
        self.logger.info(f"Initializing recon for target: {target}")
        self.logger.info(f"Results will be saved to: {self.output_dir}")
        
        # Results storage
        self.results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "ip_addresses": [],
            "open_ports": {},
            "services": {},
            "vulnerabilities": []
        }
        
        # Check dependencies
        self.check_dependencies()

    def check_dependencies(self):
        """Check if required external tools are installed."""
        self.logger.info("Checking dependencies...")
        dependencies = {
            "subfinder": "Subdomain enumeration",
            "dnsx": "DNS resolution and subdomain enumeration",
            "nmap": "Port scanning",
            "nuclei": "Vulnerability scanning"
        }
        
        missing_deps = []
        for tool, purpose in dependencies.items():
            if not shutil.which(tool):
                self.logger.warning(f"Missing dependency: {tool} (needed for {purpose})")
                missing_deps.append(tool)
            else:
                self.logger.debug(f"Found dependency: {tool}")
        
        if missing_deps:
            self.logger.warning(f"Missing dependencies: {', '.join(missing_deps)}")
            self.logger.warning("Some functionality may be limited. See README for installation instructions.")
        else:
            self.logger.info("All dependencies are installed.")

    def run_command(self, command, description):
        """Run a shell command and return its output."""
        self.logger.debug(f"Running command: {command}")
        start_time = time.time()
        try:
            result = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True
            )
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                self.logger.debug(f"{description} completed in {execution_time:.2f}s")
                return result.stdout
            else:
                self.logger.error(f"{description} failed: {result.stderr}")
                return None
        except Exception as e:
            self.logger.error(f"Error executing {description}: {str(e)}")
            return None

    def save_results(self):
        """Save all results to a JSON file."""
        output_file = os.path.join(self.output_dir, "results.json")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        self.logger.info(f"Results saved to {output_file}")
        return output_file

    def subdomain_enumeration(self):
        """Enumerate subdomains of the target."""
        self.logger.info("Starting subdomain enumeration")
        
        # Example using subfinder (you can replace this with your preferred tool)
        output_file = os.path.join(self.output_dir, "subdomains.txt")
        
        # Check if config file exists
        config_file = os.path.join("config", "subfinder.yaml")
        config_param = ""
        if os.path.exists(config_file):
            self.logger.info(f"Using subfinder config file: {config_file}")
            config_param = f"-config {config_file}"
        
        command = f"subfinder -d {self.target} {config_param} -o {output_file}"
        self.run_command(command, "Subdomain enumeration")
        
        # Read and store results
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                self.results["subdomains"] = subdomains
                self.logger.info(f"Found {len(subdomains)} subdomains")
        
        return self.results["subdomains"]

    def active_subdomain_enumeration(self):
        """Perform active subdomain enumeration using a wordlist and dnsx."""
        self.logger.info("Starting active subdomain enumeration with wordlist")
        
        # Check if dnsx is available
        if not shutil.which("dnsx"):
            self.logger.warning("dnsx not found. Skipping active subdomain enumeration.")
            return self.results["subdomains"]
        
        # Output file for active enumeration
        output_file = os.path.join(self.output_dir, "active_enumerated_subdomains.txt")
        
        # Path to wordlist
        wordlist_path = os.path.join("wordlists", "subdomains_top20000.txt")
        
        # Run dnsx for active enumeration
        command = (
            f"dnsx -d {self.target} -w {wordlist_path} -o {output_file} "
            f"-r 8.8.8.8,1.1.1.1 -t {self.threads} -silent"
        )
        self.run_command(command, "Active subdomain enumeration")
        
        # Read new subdomains and merge with existing ones
        new_subdomains = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                new_subdomains = [line.strip() for line in f if line.strip()]
        
        # Merge and deduplicate
        combined_subdomains = list(set(self.results["subdomains"] + new_subdomains))
        self.results["subdomains"] = combined_subdomains
        
        self.logger.info(f"Active enumeration found {len(new_subdomains)} new subdomains")
        self.logger.info(f"Total unique subdomains: {len(combined_subdomains)}")
        
        return self.results["subdomains"]

    def ip_resolution(self, domains=None):
        """Resolve IP addresses for domains using dnsx."""
        self.logger.info("Starting IP resolution with dnsx")
        domains = domains or self.results["subdomains"]
        if not domains:
            domains = [self.target]
        
        # Track which domains resolve to which IPs
        ip_to_domains = {}
        output_file = os.path.join(self.output_dir, "ip_addresses.txt")
        
        # Create a temporary file with all domains to resolve
        temp_domains_file = os.path.join(self.output_dir, "temp_domains_to_resolve.txt")
        with open(temp_domains_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        # Output file for dnsx
        json_output_file = os.path.join(self.output_dir, "ip_addresses.json")
        
        # Run dnsx for IP resolution
        command = (
            f"dnsx -l {temp_domains_file} -json -o {json_output_file} "
            f"-a -r 8.8.8.8,1.1.1.1 -t {self.threads} -silent"
        )
        self.run_command(command, "IP resolution")
        
        # Process results
        ip_addresses = []
        
        if os.path.exists(json_output_file):
            with open(json_output_file, 'r') as f, open(output_file, 'w') as out_f:
                for line in f:
                    try:
                        result = json.loads(line)
                        domain = result.get("host")
                        ips = result.get("a", [])
                        
                        if domain and ips:
                            # Write to the output file
                            out_f.write(f"{domain}: {', '.join(ips)}\n")
                            
                            # Update results
                            ip_addresses.extend(ips)
                            
                            # Map IP to domains
                            for ip in ips:
                                if ip not in ip_to_domains:
                                    ip_to_domains[ip] = []
                                ip_to_domains[ip].append(domain)
                    except json.JSONDecodeError:
                        self.logger.warning(f"Could not parse JSON line: {line}")
                
                # Write IP to domains mapping
                out_f.write("\n\n# IP Addresses with associated subdomains:\n")
                for ip, domains in ip_to_domains.items():
                    out_f.write(f"{ip}: {', '.join(domains)}\n")
        
        # Remove duplicates
        self.results["ip_addresses"] = list(set(ip_addresses))
        
        # Store the IP to domains mapping in results
        self.results["ip_to_domains"] = ip_to_domains
        
        # Clean up
        if os.path.exists(temp_domains_file):
            os.remove(temp_domains_file)
        
        self.logger.info(f"Resolved {len(self.results['ip_addresses'])} unique IP addresses")
        return self.results["ip_addresses"]

    def port_scanning(self, targets=None):
        """Scan for open ports on targets."""
        self.logger.info("Starting port scanning")
        targets = targets or self.results["ip_addresses"]
        if not targets:
            targets = [self.target]
        
        # Initialize results dictionaries
        for ip in targets:
            self.results["open_ports"][ip] = []
            self.results["services"][ip] = {}
        
        # Use multithreading for parallel scanning of different targets
        def scan_target(ip):
            """Scan a single target for open ports"""
            self.logger.debug(f"Scanning ports for: {ip}")
            output_file = os.path.join(self.output_dir, f"nmap_{ip.replace('.', '_')}.xml")
            
            # Run nmap scan 
            command = f"nmap -sV --top-ports 1000 -T4 {ip} -oX {output_file}"
            self.run_command(command, f"Port scanning for {ip}")
            
            result = {"ip": ip, "ports": [], "services": {}}
            
            # Parse results using proper XML handling
            if os.path.exists(output_file):
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(output_file)
                    root = tree.getroot()
                    
                    # Find all ports with state "open"
                    for port in root.findall(".//port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_id = port.get("portid")
                            result["ports"].append(port_id)
                            
                            # Get service information
                            service = port.find("service")
                            if service is not None:
                                service_name = service.get("name", "unknown")
                                product = service.get("product", "")
                                version = service.get("version", "")
                                
                                service_info = service_name
                                if product:
                                    service_info += f" ({product}"
                                    if version:
                                        service_info += f" {version}"
                                    service_info += ")"
                                
                                result["services"][port_id] = service_info
                except Exception as e:
                    self.logger.error(f"Error parsing nmap results for {ip}: {str(e)}")
            
            return result
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=min(self.threads, len(targets))) as executor:
            scan_results = list(executor.map(scan_target, targets))
        
        # Consolidate results
        for result in scan_results:
            ip = result["ip"]
            self.results["open_ports"][ip] = result["ports"]
            self.results["services"][ip] = result["services"]
            
            port_count = len(result["ports"])
            self.logger.info(f"Found {port_count} open ports on {ip}")
        
        total_ports = sum(len(ports) for ports in self.results["open_ports"].values())
        self.logger.info(f"Port scanning completed. Found {total_ports} open ports across {len(targets)} targets.")
        return self.results["open_ports"]

    def vulnerability_scanning(self):
        """Basic vulnerability scanning."""
        self.logger.info("Starting vulnerability scanning")
        
        # This is a placeholder - in a real tool, you'd integrate with tools like Nuclei, Nessus, etc.
        # For now, we'll just create a sample vulnerability report
        
        # Example of what this might look like with Nuclei
        for domain in self.results["subdomains"] or [self.target]:
            output_file = os.path.join(self.output_dir, f"nuclei_{domain.replace('.', '_')}.json")
            command = f"nuclei -u {domain} -o {output_file} -json"
            self.run_command(command, f"Vulnerability scanning for {domain}")
            
            # Parse results (simplified)
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                vuln = json.loads(line)
                                self.results["vulnerabilities"].append({
                                    "target": domain,
                                    "name": vuln.get("info", {}).get("name", "Unknown"),
                                    "severity": vuln.get("info", {}).get("severity", "Unknown"),
                                    "description": vuln.get("info", {}).get("description", "No description")
                                })
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    self.logger.error(f"Error parsing vulnerability results: {str(e)}")
        
        self.logger.info(f"Found {len(self.results['vulnerabilities'])} potential vulnerabilities")
        return self.results["vulnerabilities"]

    def run_recon(self):
        """Run the complete recon pipeline."""
        self.logger.info("Starting full reconnaissance")
        
        # Execute the recon pipeline
        self.subdomain_enumeration()
        self.active_subdomain_enumeration()
        self.ip_resolution()
        self.port_scanning()
        self.vulnerability_scanning()
        
        # Save final results
        output_file = self.save_results()
        self.logger.info(f"Reconnaissance completed. Results saved to {output_file}")
        
        # Generate summary
        self.generate_summary()
        
        return self.results
    
    def generate_summary(self):
        """Generate a summary of findings."""
        summary_file = os.path.join(self.output_dir, "summary.txt")
        with open(summary_file, 'w') as f:
            f.write(f"Recon Summary for {self.target}\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"Subdomains found: {len(self.results['subdomains'])}\n")
            f.write(f"IP addresses discovered: {len(self.results['ip_addresses'])}\n")
            
            total_ports = sum(len(ports) for ports in self.results["open_ports"].values())
            f.write(f"Open ports discovered: {total_ports}\n")
            f.write(f"Potential vulnerabilities: {len(self.results['vulnerabilities'])}\n\n")
            
            # Add high-severity vulnerabilities to summary
            high_vulns = [v for v in self.results["vulnerabilities"] if v.get("severity", "").lower() in ["high", "critical"]]
            if high_vulns:
                f.write(f"High-severity vulnerabilities ({len(high_vulns)}):\n")
                for vuln in high_vulns:
                    f.write(f"- {vuln.get('name')} on {vuln.get('target')}\n")
        
        self.logger.info(f"Summary generated at {summary_file}")
        
        # Generate HTML report too
        self.generate_html_report()

    def generate_html_report(self):
        """Generate a comprehensive HTML report of all findings."""
        self.logger.info("Generating HTML report")
        
        html_file = os.path.join(self.output_dir, "report.html")
        
        # Create basic HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report: {self.target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .container {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            background-color: #f9f9f9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .vulnerability {{
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
        }}
        .critical {{
            background-color: #ffdddd;
            border-left: 5px solid #f44336;
        }}
        .high {{
            background-color: #ffeecc;
            border-left: 5px solid #ff9800;
        }}
        .medium {{
            background-color: #ffffcc;
            border-left: 5px solid #ffeb3b;
        }}
        .low {{
            background-color: #e7f5fe;
            border-left: 5px solid #03a9f4;
        }}
        .info {{
            background-color: #f0f0f0;
            border-left: 5px solid #9e9e9e;
        }}
    </style>
</head>
<body>
    <h1>Reconnaissance Report for {self.target}</h1>
    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="container">
        <h2>Overview</h2>
        <table>
            <tr>
                <td>Target</td>
                <td>{self.target}</td>
            </tr>
            <tr>
                <td>Subdomains Discovered</td>
                <td>{len(self.results['subdomains'])}</td>
            </tr>
            <tr>
                <td>IP Addresses Identified</td>
                <td>{len(self.results['ip_addresses'])}</td>
            </tr>
            <tr>
                <td>Open Ports Found</td>
                <td>{sum(len(ports) for ports in self.results["open_ports"].values())}</td>
            </tr>
            <tr>
                <td>Vulnerabilities Detected</td>
                <td>{len(self.results['vulnerabilities'])}</td>
            </tr>
        </table>
    </div>
    
    <div class="container">
        <h2>Subdomains</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Subdomain</th>
            </tr>
            {''.join(f'<tr><td>{i+1}</td><td>{subdomain}</td></tr>' for i, subdomain in enumerate(self.results['subdomains'][:100]))}
        </table>
        {f'<p>Showing 100 of {len(self.results["subdomains"])} subdomains. See full list in the JSON results.</p>' if len(self.results['subdomains']) > 100 else ''}
    </div>
    
    <div class="container">
        <h2>IP Addresses</h2>
        <table>
            <tr>
                <th>#</th>
                <th>IP Address</th>
                <th>Associated Subdomains</th>
            </tr>
            {''.join(
                f'<tr><td>{i+1}</td><td>{ip}</td><td>{", ".join(self.results.get("ip_to_domains", {}).get(ip, []))}</td></tr>' 
                for i, ip in enumerate(self.results['ip_addresses'][:100])
            )}
        </table>
        {f'<p>Showing 100 of {len(self.results["ip_addresses"])} IP addresses. See full list in the JSON results.</p>' if len(self.results['ip_addresses']) > 100 else ''}
    </div>
    
    <div class="container">
        <h2>Open Ports & Services</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Port</th>
                <th>Service</th>
            </tr>
            {''.join(
                f'<tr><td>{ip}</td><td>{port}</td><td>{self.results["services"].get(ip, {}).get(port, "Unknown")}</td></tr>' 
                for ip in self.results["open_ports"] 
                for port in self.results["open_ports"].get(ip, [])[:20]
            )}
        </table>
    </div>
    
    <div class="container">
        <h2>Vulnerabilities</h2>
        {''.join(
            f'<div class="vulnerability {v.get("severity", "").lower()}">'
            f'<h3>{v.get("name", "Unknown Vulnerability")}</h3>'
            f'<p><strong>Target:</strong> {v.get("target", "Unknown")}</p>'
            f'<p><strong>Severity:</strong> {v.get("severity", "Unknown")}</p>'
            f'<p><strong>Description:</strong> {v.get("description", "No description available")}</p>'
            f'</div>'
            for v in self.results["vulnerabilities"]
        ) if self.results["vulnerabilities"] else '<p>No vulnerabilities detected.</p>'}
    </div>
    
    <footer>
        <p>Generated by Sploitec Recon Tool</p>
    </footer>
</body>
</html>
"""
        
        # Write HTML to file
        with open(html_file, 'w') as f:
            f.write(html_template)
        
        self.logger.info(f"HTML report generated at {html_file}")
        return html_file

def main():
    """Main entry point for the recon tool."""
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Tool for Red Teaming")
    
    # Define target input group (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-d", "--domain", help="Target domain or IP address")
    target_group.add_argument("-f", "--file", help="File containing list of targets (one per line)")
    
    # Other arguments
    parser.add_argument("-o", "--output", help="Custom output directory (default: results/target_timestamp)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Get targets
    targets = []
    if args.domain:
        targets = [args.domain]
    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: Target file {args.file} not found.")
            sys.exit(1)
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    
    if not targets:
        print("Error: No valid targets specified.")
        sys.exit(1)
    
    # Print banner
    try:
        from pyfiglet import Figlet
        print(Figlet(font='slant').renderText('Sploitec Recon'))
        if len(targets) == 1:
            print(f"Target: {targets[0]}\n")
        else:
            print(f"Targets: {len(targets)} domains from {args.file}\n")
    except ImportError:
        print("=" * 50)
        print("Sploitec Recon Tool")
        print("=" * 50)
        if len(targets) == 1:
            print(f"Target: {targets[0]}\n")
        else:
            print(f"Targets: {len(targets)} domains from {args.file}\n")
            
    # Run the recon for each target
    for target in targets:
        print(f"\n{'=' * 30}\nProcessing target: {target}\n{'=' * 30}\n")
        
        # Initialize the recon tool for this target
        recon = ReconTool(
            target=target,
            output_dir=args.output,
            threads=args.threads,
            verbose=args.verbose
        )
        
        # Run the recon pipeline
        try:
            recon.run_recon()
            
            output_file = os.path.join(recon.output_dir, "results.json")
            print(f"\nReconnaissance completed for {target}!")
            print(f"Results saved to: {output_file}")
            print(f"HTML report: {os.path.join(recon.output_dir, 'report.html')}")
                
        except KeyboardInterrupt:
            recon.logger.warning("Reconnaissance interrupted by user")
            recon.save_results()
            print("\nRecon interrupted. Partial results saved.")
            break  # Exit the loop if user interrupts
        except Exception as e:
            recon.logger.error(f"Error during reconnaissance: {str(e)}")
            print(f"\nAn error occurred: {str(e)}")
            recon.save_results()
            
    if len(targets) > 1:
        print(f"\nAll {len(targets)} targets processed. Results saved in individual directories.")
        
if __name__ == "__main__":
    main()