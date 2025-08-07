# PWSHRECON

POWERRECON is a modular, multi-threaded network reconnaissance framework written in PowerShell and intended to run on Kali Linux (or other Linux distributions with PowerShell Core). It is designed for automated service enumeration and result parsing.

The framework performs initial port and service scans using tools like Nmap, then dynamically launches protocol-specific enumeration modules (e.g., SSLyze for TLS, CME for SMB/SSH, Nikto for HTTP) based on detected services. Parsed outputs from scanners are exported to structured formats (CSV), enabling fast analysis and review. Built with scalability and auditability in mind, POWERRECON is ideal for internal assessments, or learning-driven recon projects.

## TOOLS

- Dig
- DNSrecon
- Whois
- Nmap
- Masscan
- Curl
- SSLScan
- WhatWeb
- enum4linux
- Swaks
- Nikto
- SSLyze
- CrackMapExec


---

## Usage

Run POWERRECON via the main launcher script `main.ps1` with optional flags for inputs and directories:

```powershell
.\main.ps1 [-InputFile <path>] [-InputType ip|domain] [-OutputDir <path>] [-ParsedDir <path>] [-Help]
```

### Defaults

InputType = ip
InputFile = ../targets/ips.list
OutputDir = ../output
ParsedDir = ../parsedOutput

### Example

.\main.ps1 -InputFile 'C:\targets\custom_domains.txt' -InputType domain -OutputDir 'C:\scan_results' -ParsedDir 'C:\parsed_results'

- To print instructions

.\main.ps1 -Help

## Directory Structure

POWERRECON/
├── output/          # Raw tool outputs
├── parsedOutput/          # Structured CSVs
├── modules/         # Parser functions and automation modules
├── main/       # Orchestrating script
└── README.md        # Documentation

## Output Overview

POWERRECON organizes results into two key folders:

- `output/` — This is where all **raw scan results** go. Outputs from tools like Nmap, Nikto, CrackMapExec, Impacket, etc. are saved here exactly as they're generated.

- `parsedOutput/` — This folder contains the **structured CSV files** created by the parser modules. These files make it easy to review findings, filter data, and create reports.

## Sample Workflow

1. Run `main.ps1` with your input list
2. Framework performs service scans using Nmap and Masscan
3. Based on discovered ports, it launches protocol-specific scans:
   - HTTP → Nikto, WhatWeb
   - SSL → SSLyze, SSLScan
   - SMB → CrackMapExec
   - DNS → Dig, DNSrecon
4. Raw outputs go to `output/`, then are parsed into `.csv` files in `parsedOutput/`