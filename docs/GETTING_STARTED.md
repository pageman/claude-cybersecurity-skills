# Getting Started with Claude Cybersecurity Skills

This guide will help you get started with the Claude Cybersecurity Skills collection.

## Table of Contents

- [Installation](#installation)
- [Authorization Setup](#authorization-setup)
- [Your First Recon Scan](#your-first-recon-scan)
- [Defensive Operations](#defensive-operations)
- [Best Practices](#best-practices)

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/your-org/claude-cybersecurity-skills.git
cd claude-cybersecurity-skills

# Install dependencies
pip install -r requirements.txt

# Install system tools (optional, for full functionality)
# On Ubuntu/Debian:
sudo apt-get install nmap

# On macOS:
brew install nmap
```

### Verify Installation

```python
from cybersec_skills import auth, recon, network, vuln_mgmt, detection

print("✓ All modules imported successfully")
```

## Authorization Setup

### Understanding Authorization Modes

The framework supports four authorization modes:

1. **defensive** - Blue team operations only (no authorization needed)
2. **pentest** - Penetration testing with authorization document
3. **ctf** - CTF competitions and educational use
4. **research** - Security research projects

### Setting Up for Penetration Testing

Create an authorization file (see `examples/pentest-authorization.json.example`):

```json
{
  "authorization_type": "penetration_test",
  "authorized_by": "CISO Name",
  "organization": "Target Org",
  "valid_until": "2024-12-31T23:59:59",
  "scope": [
    "*.target.com",
    "192.168.1.0/24"
  ]
}
```

Set the authorization context in your code:

```python
from cybersec_skills import auth

auth.set_context(
    mode='pentest',
    authorization_file='./pentest-auth.json',
    scope=['*.example.com']
)
```

### Setting Up for CTF

For CTF competitions and educational platforms:

```python
auth.set_context(
    mode='ctf',
    competition='HackTheBox',
    target='10.10.10.100'
)
```

### Setting Up for Defensive Operations

No authorization needed for blue team work:

```python
auth.set_context(mode='defensive')
```

## Your First Recon Scan

### Step 1: Enumerate Subdomains

```python
from cybersec_skills import auth, recon

# Set authorization
auth.set_context(
    mode='ctf',
    target='*.example.htb',
    competition='Practice'
)

# Enumerate subdomains
results = recon.enumerate_subdomains(
    domain='example.htb',
    methods=['crt', 'dns']
)

print(f"Found {results.total_found} subdomains:")
for sub in results.subdomains:
    print(f"  {sub['name']} -> {sub['ip']}")
```

### Step 2: Scan Discovered Hosts

```python
from cybersec_skills import network

# Pick a target from subdomain results
target_ip = results.subdomains[0]['ip']

# Scan with Nmap
scan = network.scan_target(
    target=target_ip,
    scan_type='quick',
    version_detection=True
)

print(f"\nOpen ports on {target_ip}:")
for port in scan.ports:
    print(f"  {port.port}/{port.protocol}: {port.service}")
```

### Step 3: Export Results

```python
# Export subdomain results
recon.export_subdomains(results, 'subdomains.json')

# Export scan results
network.export_results(scan, 'scan.json')

# Export audit log
auth.export_audit_log('audit.json')
```

## Defensive Operations

### Research Vulnerabilities

```python
from cybersec_skills import vuln_mgmt

# Look up specific CVE
cve = vuln_mgmt.lookup_cve('CVE-2021-44228')
print(f"{cve.cve_id}: {cve.description}")
print(f"Severity: {cve.cvss_severity} (CVSS: {cve.cvss_score})")

# Search for product vulnerabilities
cves = vuln_mgmt.search_cves(
    product='apache',
    version='2.4.49',
    severity='HIGH'
)

for cve in cves:
    print(f"{cve.cve_id}: CVSS {cve.cvss_score}")
```

### Create Detection Rules

```python
from cybersec_skills import detection

# Create Sigma rule for suspicious PowerShell
rule = detection.create_process_execution_rule(
    title='Suspicious PowerShell with Encoded Commands',
    description='Detects PowerShell with base64 encoding',
    process_name='powershell.exe',
    command_line='-encodedcommand',
    level='high',
    mitre_technique='T1059.001'
)

# Add false positives
rule.falsepositives = [
    'Legitimate admin scripts',
    'Software deployment'
]

# Validate and save
is_valid, errors = detection.validate_sigma_rule(rule)
if is_valid:
    rule.save('detection_rule.yml')
```

## Best Practices

### 1. Always Set Authorization Context

```python
# DO THIS - Set context first
auth.set_context(mode='ctf', target='10.10.10.100')
results = recon.enumerate_subdomains('target.com')

# DON'T DO THIS - Attempting operations without authorization
results = recon.enumerate_subdomains('target.com')  # Will fail!
```

### 2. Validate Targets Before Scanning

```python
# Check if target is in scope
try:
    auth.validate_target('example.com')
    # Proceed with scanning
except auth.ScopeError as e:
    print(f"Target out of scope: {e}")
```

### 3. Use Appropriate Timing

```python
# Production environments - use polite timing
scan = network.scan_target(
    target='prod.example.com',
    timing=2  # T2 - Polite
)

# Lab environments - can be more aggressive
scan = network.scan_target(
    target='lab.example.com',
    timing=4  # T4 - Aggressive
)
```

### 4. Export and Review Audit Logs

```python
# Always export audit logs for accountability
auth.export_audit_log('engagement_audit.json')

# Review what operations were performed
trail = auth.get_audit_trail(limit=10)
for entry in trail:
    print(f"{entry['timestamp']}: {entry['operation']}")
```

### 5. Handle Errors Gracefully

```python
try:
    results = recon.enumerate_subdomains('target.com')
except auth.AuthorizationError as e:
    print(f"Authorization error: {e}")
except auth.ScopeError as e:
    print(f"Scope error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Example Workflows

See the `examples/` directory for complete workflow examples:

- **offensive_recon_example.py** - Full red team reconnaissance workflow
- **defensive_detection_example.py** - Blue team detection engineering

Run them with:

```bash
python examples/offensive_recon_example.py
python examples/defensive_detection_example.py
```

## Next Steps

1. Read the skill documentation in `skills/` directory
2. Review YAML skill definitions for detailed usage
3. Explore advanced NSE scripts for Nmap
4. Learn about MITRE ATT&CK mapping for detections
5. Integrate with your SIEM for Sigma rule deployment

## Getting Help

- Documentation: [https://docs.cybersec-skills.io](https://docs.cybersec-skills.io)
- Issues: [GitHub Issues](https://github.com/your-org/claude-cybersecurity-skills/issues)
- Discord: [Community Server](https://discord.gg/cybersec-skills)

## Legal Notice

Always obtain proper authorization before conducting security testing. Unauthorized security testing is illegal. This framework is designed to enforce authorization checks, but ultimately you are responsible for ensuring you have proper permission.
