# Claude Cybersecurity Skills

A comprehensive collection of ready-to-use cybersecurity skills for Claude Code, enabling AI-assisted security testing, threat hunting, and defensive operations.

## Overview

This repository provides **50+ cybersecurity skills** across offensive security, defensive operations, threat intelligence, and compliance domains. Each skill includes documentation, code examples, ethical guidelines, and best practices.

## Key Features

- **Multi-Domain Coverage**: Reconnaissance, web security, network testing, forensics, threat intelligence, and more
- **Ethical Framework**: Built-in authorization checks and scope validation
- **Workflow Orchestration**: Multi-stage attack chains and automated playbooks
- **Defensive + Offensive**: Equal focus on red team and blue team operations
- **Compliance Ready**: Automated reporting and framework mapping

## Installation

### Claude Code (Recommended)
```bash
# Install via Claude Code marketplace
1. Open Claude Code
2. Navigate to Skills/Plugins
3. Search for "cybersecurity-skills"
4. Click Install
```

### Manual Installation
```bash
git clone https://github.com/your-org/claude-cybersecurity-skills.git
cd claude-cybersecurity-skills
pip install -r requirements.txt
```

## Skill Categories

### 🔍 Reconnaissance & OSINT (5 skills)
- Subdomain enumeration
- DNS reconnaissance
- WHOIS lookup and analysis
- Certificate transparency monitoring
- Shodan/Censys integration

### 🌐 Web Application Security (8 skills)
- OWASP ZAP automation
- FFUF web fuzzing
- SQLMap integration
- Nuclei vulnerability scanning
- JWT analysis
- API security testing
- XSS detection
- Directory enumeration

### 🔌 Network Security (5 skills)
- Nmap scanning and enumeration
- Service version detection
- Network vulnerability scanning
- Packet analysis with tcpdump
- SSL/TLS testing

### 🛡️ Threat Intelligence (6 skills)
- CVE database lookup
- MITRE ATT&CK mapping
- IOC enrichment
- VirusTotal integration
- Threat feed aggregation
- YARA rule creation

### 🔎 Digital Forensics (5 skills)
- File metadata extraction
- Memory dump analysis
- Log parsing and correlation
- Timeline analysis
- Evidence collection

### 📊 Security Monitoring (6 skills)
- Sigma rule creation
- SIEM query generation
- Log analysis automation
- Anomaly detection
- Alert triage
- Hunt query development

### ☁️ Cloud Security (5 skills)
- AWS security audit (Prowler)
- Azure security assessment
- K8s security scanning
- Cloud misconfiguration detection
- IAM policy analysis

### 🔐 Vulnerability Management (5 skills)
- Dependency scanning
- Container security (Trivy)
- SBOM generation
- CVSS scoring
- Patch prioritization

## Quick Start

### Example 1: Subdomain Enumeration
```python
from cybersec_skills import recon

# Enumerate subdomains for a target (with authorization)
results = recon.enumerate_subdomains(
    domain="example.com",
    authorization_token="pentest-2024-001"
)

print(f"Found {len(results.subdomains)} subdomains")
for subdomain in results.subdomains:
    print(f"  - {subdomain.name} [{subdomain.ip}]")
```

### Example 2: Vulnerability Scanning
```python
from cybersec_skills import vuln_mgmt

# Check for CVEs affecting a specific service
cves = vuln_mgmt.lookup_cve(
    product="nginx",
    version="1.18.0"
)

for cve in cves:
    print(f"{cve.id}: {cve.description}")
    print(f"  CVSS: {cve.cvss_score} ({cve.severity})")
```

### Example 3: Sigma Rule Creation
```python
from cybersec_skills import detection

# Generate Sigma rule from attack pattern
rule = detection.create_sigma_rule(
    technique="T1078",  # Valid Accounts
    description="Detect suspicious service account login",
    logsource="windows-security"
)

print(rule.to_yaml())
```

## Authorization & Ethics

**CRITICAL**: All offensive security tools require explicit authorization:

1. **Authorization Tokens**: Required for reconnaissance and exploitation tools
2. **Scope Validation**: All operations validate target is in authorized scope
3. **Audit Logging**: All tool usage is logged for accountability
4. **Ethical Guidelines**: Each skill includes responsible use guidance

### Setting Up Authorization

```python
from cybersec_skills import auth

# Initialize for penetration test
auth.set_context(
    mode="pentest",
    authorization_file="./pentest-authorization.json",
    scope=["*.example.com", "192.168.1.0/24"]
)

# Or for CTF/educational use
auth.set_context(
    mode="ctf",
    competition="HackTheBox",
    target="10.10.10.150"
)

# Or for defensive/blue team only
auth.set_context(mode="defensive")
```

## Modes of Operation

- **`defensive`**: Blue team only (monitoring, detection, forensics)
- **`pentest`**: Requires authorization file with scope
- **`ctf`**: Educational/competition (requires proof of participation)
- **`research`**: Security research (requires institutional approval)

## Architecture

```
claude-cybersecurity-skills/
├── README.md
├── requirements.txt
├── setup.py
├── cybersec_skills/
│   ├── __init__.py
│   ├── auth/              # Authorization framework
│   ├── recon/             # Reconnaissance skills
│   ├── web_security/      # Web application testing
│   ├── network/           # Network security
│   ├── vuln_mgmt/         # Vulnerability management
│   ├── detection/         # Threat detection
│   ├── forensics/         # Digital forensics
│   ├── threat_intel/      # Threat intelligence
│   └── cloud_security/    # Cloud security
├── skills/                # Individual skill definitions
│   ├── subdomain-enumeration.yaml
│   ├── nmap-scanning.yaml
│   ├── cve-lookup.yaml
│   └── ...
├── examples/              # Usage examples
└── docs/                  # Documentation
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - See [LICENSE](LICENSE) for details

## Disclaimer

These tools are for authorized security testing only. Unauthorized use against systems you don't own or have explicit permission to test is illegal. Users are responsible for compliance with all applicable laws and regulations.

## Support

- Documentation: [https://docs.cybersec-skills.io](https://docs.cybersec-skills.io)
- Issues: [GitHub Issues](https://github.com/your-org/claude-cybersecurity-skills/issues)
- Discord: [Join our community](https://discord.gg/cybersec-skills)

---

Built with ❤️ for the security community
