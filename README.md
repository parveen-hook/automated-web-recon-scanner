# automated-web-recon-scanner
Modular Python CLI tool for HTTP security headers check, TCP port scanning, and basic web vulnerability testing.
# Automated Web Recon & Vulnerability Scanner 

A modular Python-based Command Line Interface (CLI) security tool engineered to automate initial web reconnaissance, inspect HTTP security headers, perform TCP port scanning, and detect basic web application vulnerabilities (SQL Injection & Reflected XSS).

---

## Features

- **HTTP Security Headers Inspection:** Analyzes response headers to detect missing security controls such as `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Frame-Options`, and `X-Content-Type-Options`.
- **Network Port Scanner:** Implements low-level TCP socket connections to scan common web and administration ports (`80`, `443`, `22`, `8080`, `21`, `25`).
- **Vulnerability Assessment Engine:** Automated query parameter testing for database error signatures (SQL Injection) and un-sanitized reflection vectors (Reflected XSS).
- **Structured JSON Reporting:** Generates clean, machine-readable `.json` scan reports for security analysis and integration.

---

## Technology Stack

- **Language:** Python 3.8+
- **Networking & Transport:** `socket`, `requests`
- **CLI & Output Parsing:** `argparse`, `json`, `colorama`

---

## Installation & Usage

1. **Clone the Repository:**
```bash
git clone https://github.com/parveen-hook/automated-web-recon-scanner.git
cd automated-web-recon-scanner
