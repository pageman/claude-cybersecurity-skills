# Claude Cybersecurity Skills - Project Summary

## Overview

This is a **prototype** of a comprehensive cybersecurity skills collection for Claude Code, modeled after the [claude-scientific-skills](https://github.com/K-Dense-AI/claude-scientific-skills) repository but designed specifically for cybersecurity professionals.

## What Was Built

### 1. Core Authorization Framework (`cybersec_skills/auth/`)

A robust authorization and ethics system that ensures all offensive operations require proper authorization:

**Key Features:**
- **Multiple authorization modes**: pentest, ctf, research, defensive
- **Scope validation**: Ensures targets are within authorized ranges (IP/CIDR/domains)
- **Authorization file support**: JSON-based authorization documents with expiration
- **Audit logging**: All operations are logged for accountability
- **Decorator-based enforcement**: `@require_authorization` decorator for skills

**Files:**
- `authorization.py` - Core authorization logic, scope checking, validation
- `audit.py` - Comprehensive audit trail logging and export
- `__init__.py` - Public API exports

### 2. Reconnaissance Skills (`cybersec_skills/recon/`)

Offensive reconnaissance capabilities with authorization enforcement:

**Subdomain Enumeration:**
- Certificate Transparency log queries (crt.sh)
- DNS brute forcing with customizable wordlists
- Automatic IP resolution
- Deduplication and result aggregation
- Export to JSON/TXT/CSV formats

**Files:**
- `subdomain_enum.py` - Complete subdomain enumeration implementation
- Skill definition: `skills/subdomain-enumeration.yaml`

### 3. Network Security Skills (`cybersec_skills/network/`)

Network scanning and service enumeration:

**Nmap Integration:**
- Multiple scan types: quick, full, stealth, connect
- Service and version detection
- OS fingerprinting support
- NSE script execution
- Timing templates (T0-T5)
- XML output parsing
- Export to JSON/TXT/CSV

**Files:**
- `nmap_scan.py` - Full Nmap wrapper with parsing
- Skill definition: `skills/nmap-scanning.yaml`

### 4. Vulnerability Management (`cybersec_skills/vuln_mgmt/`)

Defensive vulnerability research (no authorization required):

**CVE Database Lookup:**
- Query NVD API for CVE details
- Search by product, vendor, version, keyword
- CVSS scoring and severity ratings
- CWE mapping
- Affected product enumeration
- Reference links extraction

**Files:**
- `cve_lookup.py` - NVD API integration

### 5. Threat Detection (`cybersec_skills/detection/`)

Blue team detection engineering:

**Sigma Rule Creation:**
- Programmatic Sigma rule generation
- Pre-built templates for common detection scenarios:
  - Process execution monitoring
  - Network connection detection
  - Authentication anomalies
- MITRE ATT&CK technique mapping
- Rule validation
- YAML export for SIEM deployment

**Files:**
- `sigma_rules.py` - Complete Sigma rule framework

## Example Workflows

### Offensive Recon Example (`examples/offensive_recon_example.py`)

Demonstrates a complete red team workflow:
1. Set authorization context with pentest authorization file
2. Enumerate subdomains for target domain
3. Port scan discovered hosts
4. Export all results and audit logs

### Defensive Detection Example (`examples/defensive_detection_example.py`)

Demonstrates blue team operations:
1. Research CVEs for infrastructure components
2. Create Sigma detection rules for common threats
3. Validate rules
4. Export rules for SIEM deployment

## Key Differentiators from Scientific Skills

### 1. **Authorization & Ethics Layer**
Unlike scientific research, cybersecurity operations require strict authorization:
- Built-in authorization validation before offensive operations
- Scope checking (IP/domain validation against authorized targets)
- Audit logging for all operations
- Multiple authorization modes (pentest, CTF, research, defensive)

### 2. **Offensive + Defensive Balance**
Equal focus on red team (offensive) and blue team (defensive):
- Offensive skills require authorization
- Defensive skills work without authorization
- Purple team scenarios supported

### 3. **MITRE ATT&CK Integration**
All skills map to MITRE ATT&CK framework:
- Detection rules include technique IDs
- Skills document corresponding adversary TTPs

### 4. **YAML Skill Definitions**
Comprehensive skill documentation in YAML format:
- Use cases and examples
- Best practices
- Ethical guidelines
- Tool integration guides
- False positive documentation

## Architecture

```
claude-cybersecurity-skills/
├── cybersec_skills/           # Python package
│   ├── auth/                  # Authorization framework
│   ├── recon/                 # Reconnaissance skills
│   ├── network/               # Network security skills
│   ├── vuln_mgmt/             # Vulnerability management
│   └── detection/             # Threat detection
├── skills/                    # YAML skill definitions
├── examples/                  # Usage examples
├── docs/                      # Documentation
└── requirements.txt           # Dependencies
```

## What's Working

All implemented features are functional:

1. ✅ Authorization context management
2. ✅ Scope validation (IP, CIDR, domain with wildcards)
3. ✅ Audit logging and export
4. ✅ Subdomain enumeration (CT logs, DNS)
5. ✅ Nmap scanning with full XML parsing
6. ✅ CVE lookup via NVD API
7. ✅ Sigma rule creation and validation
8. ✅ Example workflows
9. ✅ Comprehensive documentation

## What's Demonstrated (Prototype Scope)

This prototype includes **4 representative skills** from different domains:

| Domain | Skill | Type | Status |
|--------|-------|------|--------|
| Reconnaissance | Subdomain Enumeration | Offensive | ✅ Complete |
| Network Security | Nmap Scanning | Offensive | ✅ Complete |
| Vulnerability Mgmt | CVE Lookup | Defensive | ✅ Complete |
| Detection | Sigma Rules | Defensive | ✅ Complete |

## Production Roadmap

To make this production-ready, add:

### Additional Skills (46+ more):

**Reconnaissance & OSINT:**
- WHOIS lookup
- DNS zone transfer attempts
- Shodan/Censys integration
- Certificate monitoring
- GitHub reconnaissance

**Web Application Security:**
- OWASP ZAP automation
- FFUF fuzzing
- SQLMap integration
- Nuclei vulnerability scanning
- JWT token analysis
- GraphQL testing

**Network Security:**
- SSL/TLS testing
- Packet capture analysis
- Wireless security testing

**Exploitation:**
- Metasploit integration
- Exploit-DB queries
- Payload generation

**Post-Exploitation:**
- Privilege escalation enumeration
- Credential harvesting
- Lateral movement tools

**Forensics:**
- Memory dump analysis
- File carving
- Timeline analysis
- Log correlation

**Malware Analysis:**
- Static analysis (YARA, strings)
- Dynamic analysis (sandbox)
- IOC extraction

**Cloud Security:**
- AWS security audit (Prowler/ScoutSuite)
- Azure security scanning
- Kubernetes security (kube-bench)

**Threat Intelligence:**
- MISP integration
- IOC enrichment
- Threat feed aggregation

### Infrastructure:

- [ ] MCP server implementation
- [ ] Claude Code marketplace integration
- [ ] Web-based skill browser
- [ ] Skill versioning
- [ ] Auto-update mechanism
- [ ] Docker containerization
- [ ] CI/CD pipelines
- [ ] Unit test coverage
- [ ] Integration tests

### Documentation:

- [ ] API reference (Sphinx/MkDocs)
- [ ] Video tutorials
- [ ] CTF walkthroughs
- [ ] Contribution guidelines
- [ ] Security policy
- [ ] License selection

## Usage Example

```python
from cybersec_skills import auth, recon, network, vuln_mgmt, detection

# Red team: Reconnaissance
auth.set_context(mode='pentest', authorization_file='./auth.json')
subdomains = recon.enumerate_subdomains('example.com')
scan = network.scan_target(subdomains.subdomains[0]['ip'])

# Blue team: Detection engineering
auth.set_context(mode='defensive')
cves = vuln_mgmt.search_cves(product='nginx', severity='HIGH')
rule = detection.create_process_execution_rule(
    title='Detect Mimikatz',
    process_name='mimikatz.exe',
    level='critical'
)
```

## Security Considerations

### Built-in Safeguards:

1. **Authorization required** for offensive operations
2. **Scope validation** prevents out-of-scope testing
3. **Audit logging** creates accountability trail
4. **Rate limiting** recommended in documentation
5. **Ethical guidelines** in every skill definition

### User Responsibility:

- Users must obtain proper authorization
- Users must comply with applicable laws
- Users must protect sensitive data
- Users must follow responsible disclosure

## Comparison to claude-scientific-skills

| Feature | Scientific Skills | Cybersecurity Skills |
|---------|------------------|---------------------|
| Domain | Scientific research | Cybersecurity ops |
| Authorization | Not required | **Required for offensive** |
| Scope checking | N/A | **Built-in validation** |
| Audit logging | N/A | **Comprehensive logging** |
| Ethics layer | Minimal | **Extensive** |
| Multiple modes | Single mode | **4 modes (pentest/ctf/research/defensive)** |
| Offensive tools | N/A | **With authorization** |
| Defensive tools | N/A | **No authorization needed** |

## Getting Started

See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for:
- Installation instructions
- Authorization setup
- First scan tutorial
- Example workflows
- Best practices

## License

This is a prototype. Production version would need:
- License selection (MIT recommended for maximum adoption)
- Contributor agreement
- Security policy
- Responsible disclosure guidelines

## Community

For a production release:
- GitHub repository with issue tracker
- Discord/Slack community
- Documentation website
- Regular skill releases
- Community contributions

---

**Built as a proof-of-concept for Claude Code cybersecurity capabilities.**
