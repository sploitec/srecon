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
            "host": "IP resolution",
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
        command = f"subfinder -d {self.target} -o {output_file}"
        self.run_command(command, "Subdomain enumeration")
        
        # Read and store results
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                self.results["subdomains"] = subdomains
                self.logger.info(f"Found {len(subdomains)} subdomains")
        
        return self.results["subdomains"]

    def ip_resolution(self, domains=None):
        """Resolve IP addresses for domains."""
        self.logger.info("Starting IP resolution")
        domains = domains or self.results["subdomains"]
        if not domains:
            domains = [self.target]
        
        ip_dict = {}
        output_file = os.path.join(self.output_dir, "ip_addresses.txt")
        
        def resolve_domain(domain):
            """Helper function to resolve a single domain."""
            self.logger.debug(f"Resolving IP for: {domain}")
            command = f"host {domain} | grep 'has address' | cut -d ' ' -f 4"
            output = self.run_command(command, f"IP resolution for {domain}")
            
            result = {}
            if output:
                ips = [ip.strip() for ip in output.split('\n') if ip.strip()]
                if ips:
                    result = {domain: ips}
            return result
        
        # Use ThreadPoolExecutor for parallel resolution
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(resolve_domain, domains))
        
        # Consolidate results
        for result in results:
            ip_dict.update(result)
            for ips in result.values():
                    self.results["ip_addresses"].extend(ips)
        
        # Remove duplicates
        self.results["ip_addresses"] = list(set(self.results["ip_addresses"]))
        
        # Save to file
        with open(output_file, 'w') as f:
            for domain, ips in ip_dict.items():
                f.write(f"{domain}: {', '.join(ips)}\n")
        
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
            command = f"nmap -sV -p 1-1000 -T4 {ip} -oX {output_file}"
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
            </tr>
            {''.join(f'<tr><td>{i+1}</td><td>{ip}</td></tr>' for i, ip in enumerate(self.results['ip_addresses'][:100]))}
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
    
    <div class="container">
        <h2>Recommendations</h2>
        <ul>
            <li>Review all open ports and services, disable unnecessary services</li>
            <li>Implement proper access controls for all exposed services</li>
            <li>Address identified vulnerabilities based on severity</li>
            <li>Consider implementing a web application firewall (WAF)</li>
            <li>Regularly scan for new vulnerabilities and misconfigurations</li>
        </ul>
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
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-o", "--output", help="Custom output directory (default: results/target_timestamp)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Initialize the recon tool
    recon = ReconTool(
        target=args.target,
        output_dir=args.output,
        threads=args.threads,
        verbose=args.verbose
    )
    
    # Print banner
    try:
        from pyfiglet import Figlet
        print(Figlet(font='slant').renderText('Sploitec Recon'))
        print(f"Target: {args.target}\n")
    except ImportError:
        print("=" * 50)
        print("Sploitec Recon Tool")
        print("=" * 50)
        print(f"Target: {args.target}\n")
    
    # Run the recon pipeline
    try:
        recon.run_recon()
        
        output_file = os.path.join(recon.output_dir, "results.json")
        print(f"\nReconnaissance completed!")
        print(f"Results saved to: {output_file}")
        print(f"HTML report: {os.path.join(recon.output_dir, 'report.html')}")
            
    except KeyboardInterrupt:
        recon.logger.warning("Reconnaissance interrupted by user")
        recon.save_results()
        print("\nRecon interrupted. Partial results saved.")
    except Exception as e:
        recon.logger.error(f"Error during reconnaissance: {str(e)}")
        print(f"\nAn error occurred: {str(e)}")
        recon.save_results()
        
if __name__ == "__main__":
    main()