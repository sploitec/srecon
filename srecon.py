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
import yaml
import concurrent.futures
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Suppress SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconTool:
    def __init__(self, target, output_dir=None, threads=5, verbose=False, interactive=False, debug=False):
        """Initialize the recon tool with target and parameters."""
        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.interactive = interactive
        self.debug = debug
        
        # Load configuration
        self.config = self.load_config()
        
        # Override config with command line arguments if provided
        if threads:
            self.threads = threads
        elif self.config.get('general', {}).get('threads'):
            self.threads = self.config['general']['threads']
            
        if verbose:
            self.verbose = verbose
        elif self.config.get('general', {}).get('verbose') is not None:
            self.verbose = self.config['general']['verbose']
            
        if interactive:
            self.interactive = interactive
        elif self.config.get('general', {}).get('interactive') is not None:
            self.interactive = self.config['general']['interactive']
            
        if debug:
            self.debug = debug
        elif self.config.get('general', {}).get('debug') is not None:
            self.debug = self.config['general']['debug']
        
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
        log_level = logging.DEBUG if self.verbose else logging.INFO
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
            "vulnerabilities": [],
            "http_services": []
        }
        
        # Check dependencies
        self.check_dependencies()

    def load_config(self):
        """Load configuration from YAML file."""
        config_path = "config.yaml"
        default_config = {
            "general": {
                "threads": 5,
                "verbose": False,
                "interactive": False,
                "debug": False
            },
            "subdomain_enumeration": {
                "wordlist": "wordlists/subdomains_top5000.txt"
            },
            "port_scan": {
                "scan_type": "top-1000",
                "additional_args": "-T4"
            }
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    if config:
                        return config
            except Exception as e:
                print(f"Error loading config file: {str(e)}")
        
        return default_config

    def check_dependencies(self):
        """Check if required external tools are installed."""
        self.logger.info("Checking dependencies...")
        dependencies = {
            "subfinder": "Subdomain enumeration",
            "dnsx": "DNS resolution and subdomain enumeration",
            "nmap": "Port scanning",
            "nuclei": "Vulnerability scanning",
            "httpx": "HTTP/HTTPS probing"
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
        if self.debug:
            self.logger.debug(f"[DEBUG] Running command: {command}")
            
        start_time = time.time()
        
        try:
            if self.debug:
                process_start_time = time.time()
                self.logger.debug(f"[DEBUG] Process creation started at: {process_start_time - start_time:.6f}s")
            
            result = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True
            )
            
            execution_time = time.time() - start_time
            
            if self.debug:
                self.logger.debug(f"[DEBUG] Process execution time: {execution_time:.6f}s")
                self.logger.debug(f"[DEBUG] Command return code: {result.returncode}")
                self.logger.debug(f"[DEBUG] Command stderr: {result.stderr}")
                
                # Log first few lines of stdout for debugging
                if result.stdout:
                    lines = result.stdout.split('\n')
                    preview = '\n'.join(lines[:5])
                    self.logger.debug(f"[DEBUG] Command stdout preview (first 5 lines):\n{preview}")
                    self.logger.debug(f"[DEBUG] Total output lines: {len(lines)}")
            
            if result.returncode == 0:
                self.logger.debug(f"{description} completed in {execution_time:.2f}s")
                return result.stdout
            else:
                self.logger.error(f"{description} failed: {result.stderr}")
                return None
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Error executing {description} after {execution_time:.2f}s: {str(e)}")
            if self.debug:
                import traceback
                self.logger.debug(f"[DEBUG] Exception traceback:\n{traceback.format_exc()}")
            return None

    def save_results(self):
        """Save all results to a JSON file."""
        output_file = os.path.join(self.output_dir, "results.json")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        self.logger.info(f"Results saved to {output_file}")
        return output_file

    def check_user_confirmation(self, phase_name):
        """Ask for user confirmation in interactive mode."""
        if not self.interactive:
            return True
        
        response = input(f"\n[?] Proceed with {phase_name}? [Y/n]: ").strip().lower()
        if response == '' or response == 'y' or response == 'yes':
            return True
        return False

    def subdomain_enumeration(self):
        """Enumerate subdomains of the target."""
        # Always run passive subdomain enumeration
        self.logger.info("Starting passive subdomain enumeration")
        
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
        if not self.check_user_confirmation("active subdomain enumeration"):
            self.logger.info("Skipping active subdomain enumeration")
            return self.results["subdomains"]
            
        self.logger.info("Starting active subdomain enumeration with wordlist")
        
        # Check if dnsx is available
        if not shutil.which("dnsx"):
            self.logger.warning("dnsx not found. Skipping active subdomain enumeration.")
            return self.results["subdomains"]
        
        # Output file for active enumeration
        output_file = os.path.join(self.output_dir, "active_enumerated_subdomains.txt")
        
        # Path to wordlist from config
        wordlist_path = self.config.get('subdomain_enumeration', {}).get('wordlist', "wordlists/subdomains_top5000.txt")
        
        if self.debug:
            self.logger.debug(f"[DEBUG] Using wordlist: {wordlist_path}")
            if os.path.exists(wordlist_path):
                wordlist_size = os.path.getsize(wordlist_path)
                self.logger.debug(f"[DEBUG] Wordlist size: {wordlist_size} bytes")
                
                # Count lines in wordlist
                with open(wordlist_path, 'r') as f:
                    line_count = sum(1 for _ in f)
                self.logger.debug(f"[DEBUG] Wordlist contains {line_count} entries")
            else:
                self.logger.debug(f"[DEBUG] Wordlist not found at path: {wordlist_path}")
                
            self.logger.debug(f"[DEBUG] Thread count: {self.threads}")
        
        # Check if wordlist exists
        if not os.path.exists(wordlist_path):
            self.logger.error(f"Wordlist not found: {wordlist_path}")
            return self.results["subdomains"]
            
        # Clear output file if it exists
        if os.path.exists(output_file):
            os.remove(output_file)

        # Use ThreadPoolExecutor for faster processing
        self.logger.info("Using ThreadPoolExecutor for parallel subdomain enumeration")
        
        # Read the wordlist
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
        
        # Determine optimal chunk size and number of workers
        num_words = len(words)
        # Use CPU count as a baseline for number of workers
        num_workers = min(os.cpu_count() or 4, 8)  # Limit to 8 workers max to avoid overwhelming the system
        chunk_size = max(1, num_words // num_workers)
        
        # Use 20 threads for dnsx (or config value if higher)
        dnsx_threads = max(20, self.threads)
        
        chunks = [words[i:i + chunk_size] for i in range(0, num_words, chunk_size)]
        self.logger.info(f"Split wordlist into {len(chunks)} chunks of ~{chunk_size} words each")
        
        # Function to process a chunk of the wordlist
        def process_chunk(chunk_words):
            # Create a temporary wordlist chunk file with thread ID to avoid conflicts
            import threading
            chunk_file = os.path.join(self.output_dir, f"temp_chunk_{threading.get_ident()}.txt")
            with open(chunk_file, 'w') as f:
                for word in chunk_words:
                    f.write(f"{word}\n")
            
            # Run dnsx on this chunk
            chunk_output = os.path.join(self.output_dir, f"temp_output_{threading.get_ident()}.txt")
            cmd = f"dnsx -d {self.target} -w {chunk_file} -o {chunk_output} -t {dnsx_threads} -retry 2 -rate-limit 500 -silent"
            
            try:
                # Run the command
                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                
                # Read results if any
                found_subdomains = []
                if os.path.exists(chunk_output):
                    with open(chunk_output, 'r') as f:
                        found_subdomains = [line.strip() for line in f if line.strip()]
                    
                    # Append to main output file
                    with open(output_file, 'a') as f:
                        for subdomain in found_subdomains:
                            f.write(f"{subdomain}\n")
                    
                    # Clean up
                    os.remove(chunk_output)
                
                os.remove(chunk_file)
                return len(found_subdomains)
            except Exception as e:
                self.logger.error(f"Error processing chunk: {str(e)}")
                # Clean up any temp files
                if os.path.exists(chunk_file):
                    os.remove(chunk_file)
                if os.path.exists(chunk_output):
                    os.remove(chunk_output)
                return 0
        
        # Process chunks in parallel using ThreadPoolExecutor
        import concurrent.futures
        total_found = 0
        
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    count = future.result()
                    total_found += count
                    self.logger.debug(f"Chunk processed, found {count} subdomains")
                except Exception as e:
                    self.logger.error(f"Error in subdomain enumeration: {str(e)}")
        
        execution_time = time.time() - start_time
        self.logger.info(f"Active enumeration completed in {execution_time:.2f}s")
        
        # Read new subdomains from the output file
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
        if not self.check_user_confirmation("IP resolution"):
            self.logger.info("Skipping IP resolution")
            return []
            
        self.logger.info("Starting IP resolution with dnsx")
        domains = domains or self.results["subdomains"]
        if not domains:
            domains = [self.target]
        
        # Track which domains resolve to which IPs
        ip_to_domains = {}
        output_file = os.path.join(self.output_dir, "ip_addresses.txt")
        json_output_file = os.path.join(self.output_dir, "ip_addresses.json")
        
        # Clear output files if they exist
        for file_path in [output_file, json_output_file]:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Use ThreadPoolExecutor for faster processing
        self.logger.info("Using ThreadPoolExecutor for parallel IP resolution")
        
        # Use 20 threads for dnsx (or config value if higher)
        dnsx_threads = max(20, self.threads)
        
        # Determine optimal chunk size and number of workers
        num_domains = len(domains)
        # Use CPU count as a baseline for number of workers
        num_workers = min(os.cpu_count() or 4, 8)  # Limit to 8 workers max
        chunk_size = max(1, num_domains // num_workers)
        
        # Split domains into chunks
        chunks = [domains[i:i + chunk_size] for i in range(0, num_domains, chunk_size)]
        self.logger.info(f"Split {num_domains} domains into {len(chunks)} chunks of ~{chunk_size} domains each")
        
        # Function to process a chunk of domains
        def process_chunk(chunk_domains):
            # Create a temporary domains file
            import threading
            chunk_file = os.path.join(self.output_dir, f"temp_domains_{threading.get_ident()}.txt")
            with open(chunk_file, 'w') as f:
                for domain in chunk_domains:
                    f.write(f"{domain}\n")
            
            # Run dnsx on this chunk
            chunk_output = os.path.join(self.output_dir, f"temp_ip_{threading.get_ident()}.json")
            cmd = f"dnsx -l {chunk_file} -json -o {chunk_output} -a -t {dnsx_threads} -retry 2 -rate-limit 500 -silent"
            
            try:
                # Run the command
                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                
                # Process results if any
                chunk_results = []
                if os.path.exists(chunk_output):
                    with open(chunk_output, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line)
                                chunk_results.append(result)
                                
                                # Append to main JSON output file
                                with open(json_output_file, 'a') as out_f:
                                    out_f.write(f"{line.strip()}\n")
                            except json.JSONDecodeError:
                                self.logger.warning(f"Could not parse JSON line: {line}")
                    
                    # Clean up
                    os.remove(chunk_output)
                
                os.remove(chunk_file)
                return chunk_results
            except Exception as e:
                self.logger.error(f"Error processing domain chunk: {str(e)}")
                # Clean up any temp files
                if os.path.exists(chunk_file):
                    os.remove(chunk_file)
                if os.path.exists(chunk_output):
                    os.remove(chunk_output)
                return []
        
        # Process chunks in parallel using ThreadPoolExecutor
        import concurrent.futures
        all_ip_results = []
        
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    chunk_results = future.result()
                    all_ip_results.extend(chunk_results)
                    self.logger.debug(f"Domain chunk processed, found {len(chunk_results)} IP results")
                except Exception as e:
                    self.logger.error(f"Error in IP resolution: {str(e)}")
        
        execution_time = time.time() - start_time
        self.logger.info(f"IP resolution completed in {execution_time:.2f}s")
        
        # Process all results
        ip_addresses = []
        
        # Open output file for writing the human-readable results
        with open(output_file, 'w') as out_f:
            for result in all_ip_results:
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
            
            # Write IP to domains mapping
            out_f.write("\n\n# IP Addresses with associated subdomains:\n")
            for ip, domains in ip_to_domains.items():
                out_f.write(f"{ip}: {', '.join(domains)}\n")
        
        # Remove duplicates
        self.results["ip_addresses"] = list(set(ip_addresses))
        
        # Store the IP to domains mapping in results
        self.results["ip_to_domains"] = ip_to_domains
        
        self.logger.info(f"Resolved {len(self.results['ip_addresses'])} unique IP addresses")
        return self.results["ip_addresses"]

    def http_probe(self, domains=None):
        """Probe domains to identify HTTP/HTTPS services using httpx."""
        if not self.check_user_confirmation("HTTP/HTTPS probing"):
            self.logger.info("Skipping HTTP/HTTPS probing")
            return []
            
        self.logger.info("Starting HTTP/HTTPS probing with httpx")
        
        # Check if httpx is available
        if not shutil.which("httpx"):
            self.logger.warning("httpx not found. Skipping HTTP probing.")
            return []
            
        # Use domains that have resolved IPs if no specific domains provided
        if domains is None:
            domains = []
            for ip, domains_for_ip in self.results.get("ip_to_domains", {}).items():
                domains.extend(domains_for_ip)
            # Remove duplicates
            domains = list(set(domains))
            
        if not domains:
            self.logger.warning("No domains with resolved IPs found. Skipping HTTP probing.")
            return []
            
        self.logger.info(f"Probing {len(domains)} domains for HTTP/HTTPS services")
        
        # Create output files
        output_file = os.path.join(self.output_dir, "http_services.txt")
        json_output_file = os.path.join(self.output_dir, "http_services.json")
        
        # Clear output files if they exist
        for file_path in [output_file, json_output_file]:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Create a temporary file with all domains to probe
        temp_domains_file = os.path.join(self.output_dir, "temp_domains_for_http.txt")
        with open(temp_domains_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        # Use ThreadPoolExecutor for faster processing
        self.logger.info("Using ThreadPoolExecutor for parallel HTTP probing")
        
        # Determine optimal chunk size and number of workers
        num_domains = len(domains)
        num_workers = min(os.cpu_count() or 4, 8)  # Limit to 8 workers max
        chunk_size = max(1, num_domains // num_workers)
        
        # Split domains into chunks
        chunks = [domains[i:i + chunk_size] for i in range(0, num_domains, chunk_size)]
        self.logger.info(f"Split {num_domains} domains into {len(chunks)} chunks of ~{chunk_size} domains each")
        
        if self.debug:
            # Print detailed information in debug mode
            self.logger.debug(f"[DEBUG] Using httpx with {num_workers} worker threads")
            self.logger.debug(f"[DEBUG] Chunk size: {chunk_size} domains per worker")
            # Show sample domains for verification
            sample_domains = domains[:5] if len(domains) > 5 else domains
            self.logger.debug(f"[DEBUG] Sample domains to probe: {', '.join(sample_domains)}")
            self.logger.debug("[DEBUG] httpx command parameters:")
            self.logger.debug("[DEBUG] - title: Extract page title")
            self.logger.debug("[DEBUG] - tech-detect: Identify technologies")
            self.logger.debug("[DEBUG] - status-code: Get HTTP status code")
            self.logger.debug("[DEBUG] - content-length: Get content length")
            self.logger.debug("[DEBUG] - web-server: Identify web server")
            self.logger.debug("[DEBUG] - timeout 10: 10 second timeout")
            self.logger.debug("[DEBUG] - retries 2: Retry failed requests")
        
        # Function to process a chunk of domains
        def process_chunk(chunk_domains):
            # Create a temporary domains file
            import threading
            chunk_file = os.path.join(self.output_dir, f"temp_http_{threading.get_ident()}.txt")
            with open(chunk_file, 'w') as f:
                for domain in chunk_domains:
                    f.write(f"{domain}\n")
            
            # Run httpx on this chunk
            chunk_output = os.path.join(self.output_dir, f"temp_http_result_{threading.get_ident()}.json")
            
            # Build httpx command with useful options
            cmd = (
                f"httpx -l {chunk_file} -json -o {chunk_output} "
                f"-title -tech-detect -status-code -content-length -web-server "
                f"-timeout 10 -retries 2 -max-host-error 15 -silent"
            )
            
            try:
                # Run the command
                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                
                # Process results if any
                chunk_results = []
                if os.path.exists(chunk_output):
                    with open(chunk_output, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line)
                                chunk_results.append(result)
                                
                                # Append to main JSON output file
                                with open(json_output_file, 'a') as out_f:
                                    out_f.write(f"{line.strip()}\n")
                                
                                # Also write to text file for human reading
                                with open(output_file, 'a') as out_f:
                                    url = result.get('url', 'N/A')
                                    status_code = result.get('status-code', 'N/A')
                                    title = result.get('title', 'N/A')
                                    server = result.get('webserver', 'N/A')
                                    technologies = ', '.join(result.get('technologies', []))
                                    content_length = result.get('content-length', 'N/A')
                                    
                                    out_f.write(f"URL: {url}\n")
                                    out_f.write(f"Status: {status_code}\n")
                                    out_f.write(f"Title: {title}\n")
                                    out_f.write(f"Server: {server}\n")
                                    out_f.write(f"Technologies: {technologies}\n")
                                    out_f.write(f"Content Length: {content_length}\n")
                                    out_f.write("=" * 50 + "\n")
                            except json.JSONDecodeError:
                                self.logger.warning(f"Could not parse JSON line: {line}")
                    
                    # Clean up
                    os.remove(chunk_output)
                
                os.remove(chunk_file)
                return chunk_results
            except Exception as e:
                self.logger.error(f"Error processing HTTP chunk: {str(e)}")
                # Clean up any temp files
                if os.path.exists(chunk_file):
                    os.remove(chunk_file)
                if os.path.exists(chunk_output):
                    os.remove(chunk_output)
                return []
        
        # Process chunks in parallel using ThreadPoolExecutor
        import concurrent.futures
        all_http_results = []
        
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(process_chunk, chunk) for chunk in chunks]
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    chunk_results = future.result()
                    all_http_results.extend(chunk_results)
                    self.logger.debug(f"HTTP chunk processed, found {len(chunk_results)} live services")
                except Exception as e:
                    self.logger.error(f"Error in HTTP probing: {str(e)}")
        
        # Clean up the temporary domains file
        if os.path.exists(temp_domains_file):
            os.remove(temp_domains_file)
            
        execution_time = time.time() - start_time
        self.logger.info(f"HTTP probing completed in {execution_time:.2f}s")
        
        # Process and store results in a structured format
        http_services = []
        
        for result in all_http_results:
            http_service = {
                'url': result.get('url'),
                'status_code': result.get('status-code'),
                'title': result.get('title'),
                'server': result.get('webserver'),
                'technologies': result.get('technologies', []),
                'content_length': result.get('content-length'),
                'host': result.get('host')
            }
            http_services.append(http_service)
        
        # Store in results
        self.results["http_services"] = http_services
        
        self.logger.info(f"Found {len(http_services)} active HTTP/HTTPS services")
        return http_services

    def port_scanning(self, targets=None):
        """Scan for open ports on targets."""
        if not self.check_user_confirmation("port scanning"):
            self.logger.info("Skipping port scanning")
            return {}
            
        self.logger.info("Starting port scanning")
        targets = targets or self.results["ip_addresses"]
        if not targets:
            targets = [self.target]
        
        # Initialize results dictionaries
        for ip in targets:
            self.results["open_ports"][ip] = []
            self.results["services"][ip] = {}
        
        # Determine optimal number of workers based on system resources
        num_workers = min(os.cpu_count() or 4, 8)  # Limit to 8 workers max
        
        # Get scan type and args from config
        scan_type = self.config.get('port_scan', {}).get('scan_type', "top-1000")
        additional_args = self.config.get('port_scan', {}).get('additional_args', "-T4")
        
        # Determine port range based on scan type
        if scan_type == "full":
            port_arg = "-p-"
        elif scan_type == "top-100":
            port_arg = "--top-ports 100"
        else:  # Default to top-1000
            port_arg = "--top-ports 1000"
            
        if self.debug:
            self.logger.debug(f"[DEBUG] Port scanning with {num_workers} worker threads")
            self.logger.debug(f"[DEBUG] Scan type: {scan_type} ({port_arg})")
            self.logger.debug(f"[DEBUG] Additional args: {additional_args}")
            self.logger.debug(f"[DEBUG] Targets: {', '.join(targets[:5])}{' and more' if len(targets) > 5 else ''}")
            
        # Use ThreadPoolExecutor for parallel scanning of different targets
        start_time = time.time()
        port_scan_results = []
        
        self.logger.info(f"Scanning {len(targets)} targets with {num_workers} workers")
        
        # Function to scan a single target
        def scan_target(ip):
            """Scan a single target for open ports"""
            self.logger.debug(f"Scanning ports for: {ip}")
            output_file = os.path.join(self.output_dir, f"nmap_{ip.replace('.', '_')}.xml")
            
            # Run nmap scan 
            cmd = f"nmap -sV {port_arg} {additional_args} {ip} -oX {output_file}"
            
            try:
                # Run the command
                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                
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
                        
                        # Count the open ports found
                        port_count = len(result["ports"])
                        self.logger.info(f"Found {port_count} open ports on {ip}")
                        
                        return result
                    except Exception as e:
                        self.logger.error(f"Error parsing nmap results for {ip}: {str(e)}")
                        return {"ip": ip, "ports": [], "services": {}, "error": str(e)}
                else:
                    self.logger.warning(f"No output file found for {ip}")
                    return {"ip": ip, "ports": [], "services": {}, "error": "No output file found"}
            except Exception as e:
                self.logger.error(f"Error scanning {ip}: {str(e)}")
                return {"ip": ip, "ports": [], "services": {}, "error": str(e)}
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            # Submit all tasks and get futures
            futures = {executor.submit(scan_target, ip): ip for ip in targets}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if "error" not in result:
                        # Update results
                        self.results["open_ports"][ip] = result["ports"]
                        self.results["services"][ip] = result["services"]
                        port_scan_results.append(result)
                except Exception as e:
                    self.logger.error(f"Error in port scanning for {ip}: {str(e)}")
        
        execution_time = time.time() - start_time
        self.logger.info(f"Port scanning completed in {execution_time:.2f}s")
        
        total_ports = sum(len(ports) for ports in self.results["open_ports"].values())
        self.logger.info(f"Found {total_ports} open ports across {len(targets)} targets.")
        
        return self.results["open_ports"]

    def vulnerability_scanning(self):
        """Basic vulnerability scanning."""
        if not self.check_user_confirmation("vulnerability scanning"):
            self.logger.info("Skipping vulnerability scanning")
            return []
            
        self.logger.info("Starting vulnerability scanning")
        
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
        self.logger.info("Starting reconnaissance")
        
        if self.interactive:
            self.logger.info("Running in interactive mode")
            print("\n=== Sploitec Recon Interactive Mode ===")
            print(f"Target: {self.target}")
            print("Passive subdomain enumeration will run first, then you will be prompted before each additional phase.\n")
        
        # Always execute passive subdomain enumeration without prompting
        self.subdomain_enumeration()
        
        # Execute the rest of the recon pipeline with interactive prompts if enabled
        self.active_subdomain_enumeration()
        self.ip_resolution()
        self.http_probe()
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
            
            # HTTP services summary
            http_services_count = len(self.results.get('http_services', []))
            f.write(f"HTTP services found: {http_services_count}\n")
            
            if http_services_count > 0:
                # Count status codes
                status_counts = {}
                for service in self.results.get('http_services', []):
                    status = service.get('status_code')
                    if status:
                        status_key = f"{str(status)[0]}xx"  # Group by first digit
                        status_counts[status_key] = status_counts.get(status_key, 0) + 1
                
                f.write("  Status code breakdown:\n")
                for status, count in status_counts.items():
                    f.write(f"    {status}: {count}\n")
                
                # Count detected technologies
                tech_counts = {}
                for service in self.results.get('http_services', []):
                    for tech in service.get('technologies', []):
                        tech_counts[tech] = tech_counts.get(tech, 0) + 1
                
                if tech_counts:
                    f.write("  Top technologies detected:\n")
                    for tech, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                        f.write(f"    {tech}: {count}\n")
            
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
        
        # Create a lookup for domains to IPs
        domain_to_ips = {}
        for ip, domains in self.results.get("ip_to_domains", {}).items():
            for domain in domains:
                if domain not in domain_to_ips:
                    domain_to_ips[domain] = []
                domain_to_ips[domain].append(ip)
        
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
        .status-200 {{ color: green; font-weight: bold; }}
        .status-30x {{ color: blue; font-weight: bold; }}
        .status-40x {{ color: orange; font-weight: bold; }}
        .status-50x {{ color: red; font-weight: bold; }}
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
                <td>HTTP Services Found</td>
                <td>{len(self.results.get('http_services', []))}</td>
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
                <th>IP Address</th>
            </tr>
            {''.join(
                f'<tr><td>{i+1}</td><td>{subdomain}</td><td>{", ".join(domain_to_ips.get(subdomain, []))}</td></tr>' 
                for i, subdomain in enumerate(self.results['subdomains'][:100])
            )}
        </table>
        {f'<p>Showing 100 of {len(self.results["subdomains"])} subdomains. See full list in the JSON results.</p>' if len(self.results['subdomains']) > 100 else ''}
    </div>
    
    <div class="container">
        <h2>HTTP Services</h2>
        <table>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>Status</th>
                <th>Title</th>
                <th>Server</th>
                <th>Technologies</th>
            </tr>
            {''.join(
                f'<tr><td>{i+1}</td>'
                f'<td><a href="{service.get("url", "#")}" target="_blank">{service.get("url", "N/A")}</a></td>'
                f'<td class="status-{str(service.get("status_code", "0"))[0]}0x">{service.get("status_code", "N/A")}</td>'
                f'<td>{service.get("title", "N/A")}</td>'
                f'<td>{service.get("server", "N/A")}</td>'
                f'<td>{", ".join(service.get("technologies", []))}</td>'
                f'</tr>' 
                for i, service in enumerate(self.results.get("http_services", [])[:100])
            ) if self.results.get("http_services") else '<tr><td colspan="6">No HTTP services found</td></tr>'}
        </table>
        {f'<p>Showing 100 of {len(self.results.get("http_services", []))} HTTP services. See full list in the JSON results.</p>' if len(self.results.get("http_services", [])) > 100 else ''}
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
    parser.add_argument("-t", "--threads", type=int, help="Number of threads to use (default: from config or 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode - prompt before each phase")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with detailed timing and execution info")
    parser.add_argument("--config", help="Path to custom config file")
    
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
            verbose=args.verbose,
            interactive=args.interactive,
            debug=args.debug
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