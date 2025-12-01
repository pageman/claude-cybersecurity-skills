"""
Example: Defensive Detection Engineering Workflow

This example demonstrates defensive security operations:
1. Research CVEs for infrastructure
2. Create Sigma detection rules
3. Export rules for SIEM deployment

No authorization required for defensive operations!
"""

from cybersec_skills import auth, vuln_mgmt, detection


def main():
    print("=" * 80)
    print("Defensive Detection Engineering Workflow Example")
    print("=" * 80)
    print()

    # Step 1: Set to defensive mode (no authorization needed)
    print("[1] Setting defensive mode...")
    print()

    auth.set_context(mode='defensive')

    print()

    # Step 2: CVE Research
    print("[2] Researching vulnerabilities...")
    print()

    # Example: Check for Log4Shell vulnerability
    log4shell = vuln_mgmt.lookup_cve('CVE-2021-44228')

    if log4shell:
        print(f"CVE ID: {log4shell.cve_id}")
        print(f"Severity: {log4shell.cvss_severity} (CVSS: {log4shell.cvss_score})")
        print(f"Description: {log4shell.description[:200]}...")
        print(f"Published: {log4shell.published_date}")
        print()

    # Search for vulnerabilities in your stack
    print("Searching for nginx vulnerabilities...")
    nginx_cves = vuln_mgmt.search_cves(
        product='nginx',
        severity='HIGH',
        limit=5
    )

    print(f"Found {len(nginx_cves)} high-severity nginx CVEs:")
    for cve in nginx_cves:
        print(f"  - {cve.cve_id}: CVSS {cve.cvss_score} - {cve.description[:80]}...")

    print()

    # Step 3: Create Detection Rules
    print("[3] Creating Sigma detection rules...")
    print()

    # Rule 1: Detect suspicious PowerShell execution
    powershell_rule = detection.create_process_execution_rule(
        title='Suspicious PowerShell Execution with Encoded Command',
        description='Detects PowerShell execution with base64 encoded commands, '
                    'often used by malware and attackers',
        process_name='powershell.exe',
        command_line='-enc',
        level='high',
        mitre_technique='T1059.001'
    )

    powershell_rule.falsepositives = [
        'Legitimate administrative scripts using encoded commands',
        'Software deployment tools'
    ]

    print(f"Created rule: {powershell_rule.title}")
    print(f"  Level: {powershell_rule.level}")
    print(f"  MITRE ATT&CK: {powershell_rule.tags}")
    print()

    # Rule 2: Detect credential dumping
    mimikatz_rule = detection.create_process_execution_rule(
        title='Credential Dumping Tool Execution',
        description='Detects execution of known credential dumping tools like Mimikatz',
        process_name='mimikatz.exe',
        level='critical',
        mitre_technique='T1003'
    )

    mimikatz_rule.falsepositives = [
        'Security testing by authorized personnel',
        'Red team exercises'
    ]

    print(f"Created rule: {mimikatz_rule.title}")
    print(f"  Level: {mimikatz_rule.level}")
    print()

    # Rule 3: Detect suspicious network connections
    c2_rule = detection.create_network_connection_rule(
        title='Suspicious Outbound Connection to Known C2 Port',
        description='Detects outbound connections to common C2 ports from non-browser processes',
        destination_port=4444,
        level='high',
        mitre_technique='T1071'
    )

    c2_rule.falsepositives = [
        'Legitimate applications using port 4444',
        'Development/testing environments'
    ]

    print(f"Created rule: {c2_rule.title}")
    print(f"  Level: {c2_rule.level}")
    print()

    # Rule 4: Detect suspicious authentication
    service_account_rule = detection.create_authentication_rule(
        title='Service Account Interactive Logon',
        description='Detects interactive logon by service accounts, which should only use network logons',
        logon_type=2,  # Interactive logon
        level='medium',
        mitre_technique='T1078'
    )

    service_account_rule.detection['selection']['TargetUserName|startswith'] = 'svc-'
    service_account_rule.falsepositives = [
        'Legitimate administrative access to service accounts',
        'Service account maintenance'
    ]

    print(f"Created rule: {service_account_rule.title}")
    print(f"  Level: {service_account_rule.level}")
    print()

    # Step 4: Validate Rules
    print("[4] Validating detection rules...")
    print()

    rules = [powershell_rule, mimikatz_rule, c2_rule, service_account_rule]

    for rule in rules:
        is_valid, errors = detection.validate_sigma_rule(rule)
        if not is_valid:
            print(f"Validation errors for {rule.title}:")
            for error in errors:
                print(f"  - {error}")

    print()

    # Step 5: Export Rules
    print("[5] Exporting rules for SIEM deployment...")
    print()

    for i, rule in enumerate(rules, 1):
        filename = f"sigma_rule_{i}_{rule.title.lower().replace(' ', '_')[:30]}.yml"
        rule.save(filename)

    print()

    # Show example rule content
    print("Example Sigma rule (YAML):")
    print("-" * 80)
    print(powershell_rule.to_yaml())
    print("-" * 80)

    print()
    print("=" * 80)
    print("[+] Detection engineering workflow complete!")
    print(f"    - Researched CVEs for infrastructure components")
    print(f"    - Created {len(rules)} Sigma detection rules")
    print(f"    - Exported rules for SIEM deployment")
    print("    - Rules cover: Process execution, Network, Authentication")
    print("=" * 80)


if __name__ == '__main__':
    main()
