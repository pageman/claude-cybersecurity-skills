"""
Subdomain Enumeration Skill

Discovers subdomains using multiple techniques:
- DNS brute forcing
- Certificate transparency logs
- Search engine queries
- DNS zone transfers (if misconfigured)
"""

import subprocess
import json
import socket
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

from ..auth import require_authorization, validate_target


@dataclass
class SubdomainResult:
    """Result from subdomain enumeration."""
    domain: str
    subdomains: List[Dict[str, str]]
    sources: List[str]
    timestamp: str
    total_found: int

    def to_dict(self) -> dict:
        return {
            'domain': self.domain,
            'subdomains': self.subdomains,
            'sources': self.sources,
            'timestamp': self.timestamp,
            'total_found': self.total_found
        }


@require_authorization(offensive=True)
def enumerate_subdomains(
    domain: str,
    methods: Optional[List[str]] = None,
    wordlist: Optional[str] = None,
    timeout: int = 300
) -> SubdomainResult:
    """
    Enumerate subdomains for a target domain.

    Args:
        domain: Target domain (e.g., 'example.com')
        methods: Enumeration methods to use:
            - 'dns': DNS brute forcing
            - 'crt': Certificate transparency logs
            - 'search': Search engine queries
        wordlist: Path to subdomain wordlist (for DNS brute forcing)
        timeout: Maximum execution time in seconds

    Returns:
        SubdomainResult with discovered subdomains

    Raises:
        AuthorizationError: If not authorized
        ScopeError: If domain is outside scope
    """
    # Validate target is authorized
    validate_target(domain)

    methods = methods or ['dns', 'crt']
    subdomains = []
    sources_used = []

    print(f"[*] Enumerating subdomains for {domain}")
    print(f"[*] Methods: {', '.join(methods)}")

    # Certificate Transparency Logs
    if 'crt' in methods:
        print("[*] Checking certificate transparency logs...")
        crt_results = _enumerate_via_crt(domain)
        subdomains.extend(crt_results)
        sources_used.append('crt.sh')
        print(f"    Found {len(crt_results)} subdomains from CT logs")

    # DNS Brute Forcing
    if 'dns' in methods:
        print("[*] Performing DNS brute force...")
        dns_results = _enumerate_via_dns(domain, wordlist)
        subdomains.extend(dns_results)
        sources_used.append('dns_brute')
        print(f"    Found {len(dns_results)} subdomains via DNS brute force")

    # Deduplicate subdomains
    unique_subdomains = _deduplicate_subdomains(subdomains)

    print(f"[+] Total unique subdomains found: {len(unique_subdomains)}")

    return SubdomainResult(
        domain=domain,
        subdomains=unique_subdomains,
        sources=sources_used,
        timestamp=datetime.now().isoformat(),
        total_found=len(unique_subdomains)
    )


def _enumerate_via_crt(domain: str) -> List[Dict[str, str]]:
    """Enumerate subdomains via certificate transparency logs."""
    try:
        # Query crt.sh
        import urllib.request
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())

        subdomains = []
        seen = set()

        for entry in data:
            name = entry.get('name_value', '')
            # Handle wildcard and multiple names
            for subdomain in name.split('\n'):
                subdomain = subdomain.strip().replace('*.', '')
                if subdomain and subdomain.endswith(domain) and subdomain not in seen:
                    seen.add(subdomain)
                    # Resolve IP
                    ip = _resolve_hostname(subdomain)
                    subdomains.append({
                        'name': subdomain,
                        'ip': ip,
                        'source': 'crt.sh'
                    })

        return subdomains

    except Exception as e:
        print(f"    Warning: CT log enumeration failed: {e}")
        return []


def _enumerate_via_dns(domain: str, wordlist: Optional[str] = None) -> List[Dict[str, str]]:
    """Enumerate subdomains via DNS brute forcing."""
    # Use default wordlist if not provided
    if wordlist is None:
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'localhost', 'test', 'dev', 'staging', 'api', 'app', 'portal', 'vpn',
            'remote', 'blog', 'shop', 'store', 'support', 'help', 'cdn', 'static'
        ]
    else:
        try:
            with open(wordlist, 'r') as f:
                common_subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"    Warning: Wordlist not found: {wordlist}")
            return []

    subdomains = []

    for subdomain_name in common_subdomains:
        full_domain = f"{subdomain_name}.{domain}"
        ip = _resolve_hostname(full_domain)

        if ip:
            subdomains.append({
                'name': full_domain,
                'ip': ip,
                'source': 'dns_brute'
            })

    return subdomains


def _resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _deduplicate_subdomains(subdomains: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove duplicate subdomains, keeping the one with most information."""
    seen = {}

    for subdomain in subdomains:
        name = subdomain['name']
        if name not in seen or subdomain['ip']:
            seen[name] = subdomain

    return list(seen.values())


def export_subdomains(result: SubdomainResult, output_file: str, format: str = 'json'):
    """
    Export subdomain enumeration results to file.

    Args:
        result: SubdomainResult to export
        output_file: Output file path
        format: Output format ('json', 'txt', 'csv')
    """
    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)

    elif format == 'txt':
        with open(output_file, 'w') as f:
            for sub in result.subdomains:
                f.write(f"{sub['name']}\n")

    elif format == 'csv':
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['name', 'ip', 'source'])
            writer.writeheader()
            writer.writerows(result.subdomains)

    print(f"✓ Results exported to {output_file}")
