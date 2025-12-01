# Claude Cybersecurity Skills

<div align="center">

**Professional cybersecurity capabilities for Claude AI - with built-in authorization and ethics**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status: Prototype](https://img.shields.io/badge/status-prototype-orange.svg)](https://github.com/pageman/claude-cybersecurity-skills)

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Roadmap](#roadmap) • [Contributing](#contributing)

</div>

---

## Overview

Claude Cybersecurity Skills is a **prototype framework** that brings professional security testing capabilities to Claude AI, inspired by [claude-scientific-skills](https://github.com/K-Dense-AI/claude-scientific-skills). Unlike generic security tools, this framework includes **mandatory authorization checks** and **comprehensive audit logging** to ensure ethical use.

### What Makes This Different?

- **🔒 Authorization First**: All offensive operations require explicit authorization before execution
- **📝 Audit Everything**: Comprehensive logging creates accountability for all security operations
- **⚖️ Ethical by Design**: Built-in scope validation prevents out-of-scope testing
- **🔵 Red + Blue**: Equal focus on offensive (red team) and defensive (blue team) operations
- **🎯 MITRE ATT&CK**: All skills mapped to adversary tactics and techniques

## Current Status

This is a **working prototype** with **5 production-ready skills** demonstrating the framework's capabilities:

| Skill | Category | Type | Authorization Required |
|-------|----------|------|----------------------|
| **Subdomain Enumeration** | Reconnaissance | Offensive | ✅ Yes |
| **Nmap Scanning** | Network Security | Offensive | ✅ Yes |
| **Port Scanner** | Network Security | Offensive | ✅ Yes |
| **Web Security Scanner** | Web Application | Offensive | ✅ Yes |
| **Hash Cracker** | Cryptography | Offensive | ✅ Yes |
| **CVE Lookup** | Vuln Management | Defensive | ❌ No |
| **Sigma Rule Creation** | Detection | Defensive | ❌ No |

## Features

### 🔐 Authorization Framework

```python
from cybersec_skills import auth

# Penetration testing mode (requires authorization file)
auth.set_context(
    mode="pentest",
    authorization_file="./pentest-auth.json",
    scope=["*.example.com", "192.168.1.0/24"]
)

# CTF/Educational mode
auth.set_context(
    mode="ctf",
    competition="HackTheBox",
    target="10.10.10.150"
)

# Defensive operations (no authorization needed)
auth.set_context(mode="defensive")
```

### 🎯 Reconnaissance - Subdomain Enumeration

```python
from cybersec_skills import recon, auth

# Set authorization context
auth.set_context(mode="pentest", authorization_file="./auth.json")

# Enumerate subdomains
results = recon.enumerate_subdomains(
    domain="example.com",
    methods=["crt.sh", "dns_bruteforce"]
)

print(f"Found {len(results.subdomains)} subdomains:")
for sub in results.subdomains:
    print(f"  {sub['domain']:30s} → {sub['ip']}")

# Export results
results.export("subdomains.json", format="json")
```

**Features:**
- Certificate Transparency log queries (crt.sh)
- DNS brute forcing with customizable wordlists
- Automatic IP resolution and deduplication
- Export to JSON/TXT/CSV

### 🔍 Network Security - Nmap Scanning

```python
from cybersec_skills import network, auth

# Authorization required
auth.set_context(mode="pentest", authorization_file="./auth.json")

# Run comprehensive scan
scan = network.nmap_scan(
    target="192.168.1.100",
    scan_type="full",  # quick, full, stealth, connect
    service_detection=True,
    os_detection=True,
    timing=3  # T3 - normal speed
)

# Analyze results
for host in scan.hosts:
    print(f"\nHost: {host.ip} ({host.hostname})")
    if host.os:
        print(f"OS: {host.os}")
    for port in host.open_ports:
        print(f"  {port.port}/tcp - {port.service} {port.version}")
```

**Features:**
- Multiple scan types (quick, full, stealth, connect)
- Service and version detection
- OS fingerprinting
- NSE script execution
- Full XML output parsing

### 🛡️ Vulnerability Management - CVE Lookup

```python
from cybersec_skills import vuln_mgmt

# No authorization required for defensive research
cves = vuln_mgmt.search_cves(
    product="nginx",
    version="1.18.0",
    severity=["HIGH", "CRITICAL"]
)

for cve in cves:
    print(f"\n{cve.id} - {cve.severity}")
    print(f"CVSS: {cve.cvss_score}/10.0")
    print(f"Description: {cve.description[:200]}...")
    print(f"References: {', '.join(cve.references[:3])}")
```

**Features:**
- NVD API integration
- Search by product, vendor, version
- CVSS scoring and severity filtering
- CWE mapping
- Reference link extraction

### 🔎 Threat Detection - Sigma Rules

```python
from cybersec_skills import detection

# Create Sigma rule for suspicious process execution
rule = detection.create_process_execution_rule(
    title="Detect Mimikatz Execution",
    description="Identifies potential credential dumping tool execution",
    process_name="mimikatz.exe",
    technique="T1003.001",  # MITRE ATT&CK: Credential Dumping
    level="critical"
)

# Export for SIEM deployment
rule.export("mimikatz-detection.yml")
print(rule.to_yaml())
```

**Features:**
- Programmatic Sigma rule generation
- Pre-built templates (process, network, auth)
- MITRE ATT&CK technique mapping
- Rule validation
- YAML export for SIEM deployment

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/pageman/claude-cybersecurity-skills.git
cd claude-cybersecurity-skills

# Install dependencies
pip install -r requirements.txt
```

### Your First Scan

```python
from cybersec_skills import auth, network

# Set up authorization for CTF environment
auth.set_context(
    mode="ctf",
    competition="TryHackMe",
    target="10.10.50.100"
)

# Run quick port scan
scan = network.nmap_scan(
    target="10.10.50.100",
    scan_type="quick"
)

# View results
print(f"Found {len(scan.hosts[0].open_ports)} open ports")
for port in scan.hosts[0].open_ports:
    print(f"  {port.port}/tcp - {port.service}")
```

### Authorization Setup

Create an authorization file for penetration testing:

```json
{
  "authorization_id": "pentest-2024-001",
  "client": "Example Corp",
  "scope": [
    "*.example.com",
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "valid_from": "2024-01-01",
  "valid_until": "2024-12-31",
  "authorized_by": "John Doe (CISO)",
  "restrictions": [
    "No DoS attacks",
    "Business hours only (9 AM - 5 PM EST)",
    "Notify SOC before testing"
  ]
}
```

## Authorization Modes

| Mode | Use Case | Authorization Required | Audit Level |
|------|----------|----------------------|-------------|
| `pentest` | Professional penetration testing | ✅ Authorization file + scope | High |
| `ctf` | CTF competitions, HackTheBox, TryHackMe | ✅ Proof of participation | Medium |
| `research` | Security research, bug bounty | ✅ Program documentation | High |
| `defensive` | Blue team, detection engineering | ❌ None | Low |

## Project Structure

```
claude-cybersecurity-skills/
├── README.md                      # This file
├── PROJECT_SUMMARY.md            # Detailed technical overview
├── GITHUB_SETUP.md               # Repository setup guide
├── requirements.txt              # Python dependencies
├── cybersec_skills/              # Main package
│   ├── auth/                     # Authorization framework
│   │   ├── authorization.py     # Scope validation, mode checking
│   │   └── audit.py             # Comprehensive audit logging
│   ├── recon/                    # Reconnaissance skills
│   │   └── subdomain_enum.py    # Subdomain enumeration
│   ├── network/                  # Network security
│   │   └── nmap_scan.py         # Nmap integration
│   ├── vuln_mgmt/                # Vulnerability management
│   │   └── cve_lookup.py        # CVE/NVD research
│   └── detection/                # Threat detection
│       └── sigma_rules.py       # Sigma rule framework
├── skills/                       # YAML skill definitions
│   └── subdomain-enumeration.yaml
└── examples/                     # Usage examples
    ├── offensive_recon_example.py
    └── defensive_detection_example.py
```

## Examples

### Red Team: Full Reconnaissance Workflow

See [`examples/offensive_recon_example.py`](examples/offensive_recon_example.py) for a complete workflow:

1. Load authorization file
2. Enumerate subdomains
3. Port scan discovered hosts
4. Export results and audit logs

### Blue Team: Detection Engineering

See [`examples/defensive_detection_example.py`](examples/defensive_detection_example.py) for:

1. CVE research for infrastructure
2. Sigma rule creation for threats
3. Rule validation
4. SIEM deployment export

## Documentation

- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Complete technical overview, architecture, roadmap
- **[GITHUB_SETUP.md](GITHUB_SETUP.md)** - Repository setup and configuration guide
- **[skills/](skills/)** - Individual skill definitions with examples and best practices

## Roadmap

This prototype demonstrates the framework's potential. To make this production-ready:

### 🎯 Near Term (High Priority)

- [ ] Add 10+ critical skills:
  - WHOIS lookup, DNS enumeration
  - Web fuzzing (FFUF), directory enumeration
  - SSL/TLS testing, packet analysis
  - Memory forensics, log analysis
  - YARA rule creation, IOC extraction
- [ ] MCP (Model Context Protocol) server implementation
- [ ] Comprehensive test suite (unit + integration)
- [ ] CI/CD pipeline with security scanning
- [ ] Contributing guidelines and code of conduct

### 🚀 Medium Term

- [ ] 25+ additional skills across all domains
- [ ] Claude Code marketplace integration
- [ ] Web-based skill browser/documentation
- [ ] Docker containerization
- [ ] Video tutorials and walkthroughs

### 🌟 Long Term

- [ ] 50+ total skills covering full security lifecycle
- [ ] API integrations (Shodan, VirusTotal, AlienVault)
- [ ] Workflow orchestration engine
- [ ] Real-time collaboration features
- [ ] Community skill marketplace

## Contributing

Contributions are welcome! This project needs:

- **Skill Developers**: Implement new security skills
- **Security Researchers**: Validate techniques and best practices
- **Documentation Writers**: Improve guides and examples
- **Testers**: Test skills in various environments

**Before Contributing:**
- All offensive skills MUST include authorization checks
- All skills MUST include comprehensive documentation
- All skills MUST follow ethical guidelines
- All code MUST include audit logging

## Security & Ethics

### ⚠️ Legal Disclaimer

These tools are for **authorized security testing only**. Unauthorized use against systems you don't own or have explicit permission to test is **illegal** and may violate:

- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in your jurisdiction

**Users are solely responsible** for obtaining proper authorization and complying with all applicable laws.

### 🛡️ Built-in Safeguards

1. **Mandatory Authorization**: Offensive skills won't execute without valid authorization
2. **Scope Validation**: All targets checked against authorized scope (IP/CIDR/domain)
3. **Audit Logging**: Every operation logged with timestamp, user, action
4. **Rate Limiting**: Recommended in all skill documentation
5. **Ethical Guidelines**: Every skill includes responsible use guidance

### 📋 Best Practices

- **Always** obtain written authorization before testing
- **Never** test production systems without proper change control
- **Always** respect scope limitations and testing windows
- **Always** protect sensitive data discovered during testing
- **Always** follow responsible disclosure for vulnerabilities

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by [claude-scientific-skills](https://github.com/K-Dense-AI/claude-scientific-skills)
- Built for the security community
- Special thanks to all contributors

## Support & Community

- **Issues**: [GitHub Issues](https://github.com/pageman/claude-cybersecurity-skills/issues)
- **Discussions**: [GitHub Discussions](https://github.com/pageman/claude-cybersecurity-skills/discussions)
- **Security**: Report vulnerabilities via GitHub Security Advisories

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Built with ❤️ for ethical hackers, security researchers, and defenders

</div>
