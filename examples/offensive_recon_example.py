"""
Example: Offensive Reconnaissance Workflow

This example demonstrates a complete reconnaissance workflow:
1. Set authorization context
2. Enumerate subdomains
3. Scan discovered hosts
4. Export results

IMPORTANT: Requires valid authorization before running!
"""

from cybersec_skills import auth, recon, network
import json


def main():
    print("=" * 80)
    print("Offensive Reconnaissance Workflow Example")
    print("=" * 80)
    print()

    # Step 1: Set Authorization Context
    print("[1] Setting up authorization context...")
    print()

    try:
        # For penetration testing engagements
        auth.set_context(
            mode='pentest',
            authorization_file='./pentest-authorization.json',
            scope=['*.example.com', '192.168.1.0/24']
        )
    except auth.AuthorizationError as e:
        print(f"Authorization Error: {e}")
        print("\nFor CTF/educational use, you can use:")
        print("  auth.set_context(mode='ctf', target='10.10.10.100', competition='HackTheBox')")
        return

    print()

    # Step 2: Subdomain Enumeration
    print("[2] Enumerating subdomains...")
    print()

    target_domain = "example.com"

    try:
        subdomain_results = recon.enumerate_subdomains(
            domain=target_domain,
            methods=['crt', 'dns']
        )

        print(f"\n[+] Found {subdomain_results.total_found} subdomains:")
        for subdomain in subdomain_results.subdomains[:10]:  # Show first 10
            print(f"    - {subdomain['name']} -> {subdomain['ip']}")

        if subdomain_results.total_found > 10:
            print(f"    ... and {subdomain_results.total_found - 10} more")

    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
        return

    print()

    # Step 3: Port Scanning
    print("[3] Scanning discovered hosts...")
    print()

    # Scan the first subdomain with an IP
    targets_to_scan = [
        sub for sub in subdomain_results.subdomains
        if sub['ip']
    ][:3]  # Limit to first 3 hosts

    scan_results = []

    for target in targets_to_scan:
        print(f"[*] Scanning {target['name']} ({target['ip']})...")

        try:
            scan_result = network.scan_target(
                target=target['ip'],
                scan_type='quick',
                version_detection=True,
                timing=2  # Polite timing
            )

            scan_results.append(scan_result)

            print(f"    Found {len(scan_result.ports)} open ports:")
            for port in scan_result.ports[:5]:  # Show first 5 ports
                service_info = port.service or 'unknown'
                if port.product:
                    service_info += f" ({port.product}"
                    if port.version:
                        service_info += f" {port.version}"
                    service_info += ")"
                print(f"      - {port.port}/{port.protocol}: {service_info}")

        except Exception as e:
            print(f"    [!] Scan failed: {e}")

        print()

    # Step 4: Export Results
    print("[4] Exporting results...")
    print()

    # Export subdomain results
    recon.export_subdomains(
        subdomain_results,
        'recon_subdomains.json',
        format='json'
    )

    # Export scan results
    for i, scan_result in enumerate(scan_results):
        filename = f"scan_result_{i+1}.json"
        network.export_results(scan_result, filename, format='json')

    # Export audit log
    auth.export_audit_log('audit_log.json', format='json')

    print()
    print("=" * 80)
    print("[+] Reconnaissance workflow complete!")
    print(f"    - Discovered {subdomain_results.total_found} subdomains")
    print(f"    - Scanned {len(scan_results)} hosts")
    print(f"    - Results exported to current directory")
    print("=" * 80)


if __name__ == '__main__':
    main()
