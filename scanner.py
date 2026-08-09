import requests  # External library for sending HTTP requests (GET, POST)
import socket    # Built-in module for DNS resolution and socket network connections
import json      # Built-in module for exporting scan reports in JSON format
import sys       # Built-in module for system-level operations and exits
import argparse  # Built-in module for parsing command-line interface arguments
from colorama import Fore, Style, init  # Library for colored terminal text formatting

# Initialize Colorama to ensure cross-platform terminal color compatibility
init(autoreset=True)

def show_banner():
    """Displays the ASCII banner and tool title in the terminal."""
    print(Fore.CYAN + "=" * 55)
    print(Fore.GREEN + "   AUTOMATED WEB RECON & VULNERABILITY SCANNER")
    print(Fore.YELLOW + "         Built for Security & Educational Testing")
    print(Fore.CYAN + "=" * 55 + "\n")

# Module 1: HTTP Security Headers Checker
def check_headers(target_url):
    """
    Inspects HTTP response headers of the target URL to identify missing
    critical security headers.
    """
    print(Fore.BLUE + f"[*] Checking Security Headers for: {target_url}\n")
    
    # List of critical security headers expected on a secure web application
    security_headers = [
        "X-Frame-Options",            # Prevents Clickjacking attacks
        "Strict-Transport-Security",  # Enforces HTTPS connections (HSTS)
        "Content-Security-Policy",    # Prevents XSS and data injection attacks (CSP)
        "X-Content-Type-Options",     # Prevents MIME-sniffing vulnerabilities
        "X-XSS-Protection"            # Legacy browser XSS filtering
    ]

    missing_headers = []  # List to track missing headers

    try:
        # Send HTTP GET request with a 15-second timeout
        response = requests.get(target_url, timeout=15)
        fetched_headers = response.headers

        # Iterate over expected headers and verify their presence
        for header in security_headers:
            if header not in fetched_headers:
                print(Fore.RED + f"[-] MISSING: {header}")
                missing_headers.append(header)
            else:
                print(Fore.GREEN + f"[+] PRESENT: {header}")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error fetching headers: {e}")
        return None

    return missing_headers

# Module 2: Port Scanner using Low-Level Sockets
def scan_ports(target_domain, ports_to_scan=[80, 443, 22, 8080, 21, 25]):
    """
    Resolves target domain to an IP address and performs a TCP connect scan
    on specified network ports.
    """
    print(Fore.BLUE + f"\n[*] Starting Port Scan for: {target_domain}\n")
    
    # Perform DNS Resolution (Domain to IP)
    try:
        target_ip = socket.gethostbyname(target_domain)
        print(Fore.YELLOW + f"[i] Resolved IP: {target_ip}\n")
    except socket.gaierror:
        print(Fore.RED + f"[!] Could not resolve hostname: {target_domain}")
        return []

    open_ports = []  # List to track open ports

    # Iterate over target ports and attempt TCP handshake
    for port in ports_to_scan:
        # Create an IPv4 (AF_INET) TCP (SOCK_STREAM) socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)  # 1-second connection timeout
        
        # connect_ex returns 0 on successful TCP connection
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            print(Fore.GREEN + f"[+] Port {port}: OPEN")
            open_ports.append(port)
        else:
            print(Fore.RED + f"[-] Port {port}: CLOSED / FILTERED")
            
        sock.close()  # Clean up the socket resource
        
    return open_ports

# Module 3: Basic SQLi & Reflected XSS Vulnerability Tester
def check_vulnerabilities(target_url):
    """
    Tests URL query parameters against basic SQL Injection and Reflected XSS payloads.
    """
    print(Fore.BLUE + f"\n[*] Testing Basic Vulnerabilities for: {target_url}\n")
    
    vulnerabilities_found = []

    # 1. SQL Injection (SQLi) test payload and database error signatures
    sqli_payload = "'"
    sqli_errors = [
        "you have an error in your sql syntax",
        "warning: mysql_",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "microsoft ole db provider",
        "syntax error in string expression"
    ]

    # 2. Reflected Cross-Site Scripting (XSS) test payload
    xss_payload = "<script>alert('XSS_TEST')</script>"

    # Construct test URLs based on query parameter availability
    if "?" not in target_url:
        test_url_sqli = f"{target_url}?id=1{sqli_payload}"
        test_url_xss = f"{target_url}?search={xss_payload}"
    else:
        test_url_sqli = f"{target_url}&id=1{sqli_payload}"
        test_url_xss = f"{target_url}&search={xss_payload}"

    # --- SQL INJECTION TEST EXECUTION ---
    try:
        response_sqli = requests.get(test_url_sqli, timeout=5)
        response_text_lower = response_sqli.text.lower()

        # Check for database error messages in response HTML
        for error in sqli_errors:
            if error in response_text_lower:
                print(Fore.RED + f"[!] POTENTIAL SQLi DETECTED: {test_url_sqli}")
                print(Fore.YELLOW + f"    [→] Found Error Signature: '{error}'")
                vulnerabilities_found.append({"type": "SQL Injection", "url": test_url_sqli})
                break

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] SQLi Test Request Failed: {e}")

    # --- CROSS-SITE SCRIPTING (XSS) TEST EXECUTION ---
    try:
        response_xss = requests.get(test_url_xss, timeout=5)

        # Check if injected payload is reflected back un-sanitized
        if xss_payload in response_xss.text:
            print(Fore.RED + f"[!] POTENTIAL REFLECTED XSS DETECTED: {test_url_xss}")
            print(Fore.YELLOW + f"    [→] Payload Reflected in Response Body without escaping.")
            vulnerabilities_found.append({"type": "Reflected XSS", "url": test_url_xss})
        else:
            print(Fore.GREEN + f"[+] No Basic Reflected XSS detected on default parameter.")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] XSS Test Request Failed: {e}")

    return vulnerabilities_found

# Module 4: JSON Report Exporter
def export_json(data, filename):
    """
    Exports gathered scan details to a formatted JSON file.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(Fore.GREEN + f"\n[+] Scan report successfully saved to: {filename}")
    except Exception as e:
        print(Fore.RED + f"\n[!] Failed to save JSON report: {e}")

# Main execution controller
def main():
    show_banner()

    # Configure command-line options
    parser = argparse.ArgumentParser(description="Automated Web Recon & Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/page.php?id=1)")
    parser.add_argument("-o", "--output", help="Output JSON report filename (e.g., report.json)")

    args = parser.parse_args()
    target_url = args.url

    # Sanitize and extract host domain for socket port scanning
    domain = target_url.split("//")[-1].split("/")[0].split(":")[0]

    # Container structure for final output report
    scan_report = {
        "target_url": target_url,
        "domain": domain,
        "missing_headers": [],
        "open_ports": [],
        "vulnerabilities": []
    }

    # Execute security scanning modules
    scan_report["missing_headers"] = check_headers(target_url) or []
    scan_report["open_ports"] = scan_ports(domain) or []
    scan_report["vulnerabilities"] = check_vulnerabilities(target_url) or []

    # Export report if -o / --output argument is supplied
    if args.output:
        export_json(scan_report, args.output)

# Program Entry Point
if __name__ == "__main__":
    main()