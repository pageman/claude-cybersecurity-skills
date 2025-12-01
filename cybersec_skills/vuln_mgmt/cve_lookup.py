"""
CVE Database Lookup Skill

Query CVE databases (NVD, MITRE) for vulnerability information.
This is a defensive skill - no authorization required.
"""

import json
import urllib.request
import urllib.parse
from typing import List, Optional, Dict
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CVEResult:
    """CVE vulnerability result."""
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    references: List[str] = None
    cwe: Optional[str] = None
    affected_products: List[Dict[str, str]] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.affected_products is None:
            self.affected_products = []

    def to_dict(self) -> dict:
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'cvss_score': self.cvss_score,
            'cvss_severity': self.cvss_severity,
            'published_date': self.published_date,
            'last_modified': self.last_modified,
            'references': self.references,
            'cwe': self.cwe,
            'affected_products': self.affected_products
        }


def lookup_cve(cve_id: str) -> Optional[CVEResult]:
    """
    Look up specific CVE by ID.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2021-44228')

    Returns:
        CVEResult with vulnerability details, or None if not found
    """
    print(f"[*] Looking up {cve_id}...")

    # Normalize CVE ID
    cve_id = cve_id.upper().strip()

    # Query NVD API
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())

        if 'vulnerabilities' not in data or len(data['vulnerabilities']) == 0:
            print(f"[!] CVE {cve_id} not found")
            return None

        vuln_data = data['vulnerabilities'][0]['cve']
        result = _parse_cve_data(vuln_data)

        print(f"[+] Found {cve_id}: CVSS {result.cvss_score or 'N/A'} ({result.cvss_severity or 'N/A'})")

        return result

    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"[!] CVE {cve_id} not found")
            return None
        raise Exception(f"NVD API error: {e}")
    except Exception as e:
        raise Exception(f"Failed to lookup CVE: {e}")


def search_cves(
    product: Optional[str] = None,
    vendor: Optional[str] = None,
    version: Optional[str] = None,
    keyword: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 20
) -> List[CVEResult]:
    """
    Search for CVEs matching criteria.

    Args:
        product: Product name (e.g., 'nginx', 'windows')
        vendor: Vendor name (e.g., 'microsoft', 'apache')
        version: Product version (e.g., '1.18.0')
        keyword: Keyword to search in descriptions
        severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
        limit: Maximum number of results

    Returns:
        List of CVEResult objects
    """
    print(f"[*] Searching CVEs...")

    # Build query parameters
    params = {}

    if keyword:
        params['keywordSearch'] = keyword

    if product or vendor:
        # CPE name format: cpe:2.3:a:vendor:product:version
        cpe_parts = ['cpe:2.3:a']
        cpe_parts.append(vendor or '*')
        cpe_parts.append(product or '*')
        if version:
            cpe_parts.append(version)
        else:
            cpe_parts.append('*')

        params['cpeName'] = ':'.join(cpe_parts)

    if severity:
        params['cvssV3Severity'] = severity.upper()

    params['resultsPerPage'] = str(min(limit, 100))

    # Query NVD API
    query_string = urllib.parse.urlencode(params)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query_string}"

    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read().decode())

        if 'vulnerabilities' not in data:
            print("[!] No vulnerabilities found")
            return []

        results = []
        for vuln in data['vulnerabilities'][:limit]:
            cve_data = vuln['cve']
            result = _parse_cve_data(cve_data)
            results.append(result)

        print(f"[+] Found {len(results)} CVEs")

        return results

    except Exception as e:
        raise Exception(f"Failed to search CVEs: {e}")


def _parse_cve_data(cve_data: dict) -> CVEResult:
    """Parse CVE data from NVD API response."""
    cve_id = cve_data['id']

    # Get description
    descriptions = cve_data.get('descriptions', [])
    description = next(
        (d['value'] for d in descriptions if d['lang'] == 'en'),
        'No description available'
    )

    # Get CVSS score
    cvss_score = None
    cvss_severity = None

    metrics = cve_data.get('metrics', {})
    if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore')
        cvss_severity = cvss_data.get('baseSeverity')
    elif 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore')
        cvss_severity = cvss_data.get('baseSeverity')
    elif 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
        cvss_score = cvss_data.get('baseScore')

    # Get dates
    published_date = cve_data.get('published')
    last_modified = cve_data.get('lastModified')

    # Get references
    references = [
        ref['url'] for ref in cve_data.get('references', [])
    ]

    # Get CWE
    cwe = None
    weaknesses = cve_data.get('weaknesses', [])
    if weaknesses:
        cwe_data = weaknesses[0].get('description', [])
        if cwe_data:
            cwe = cwe_data[0].get('value')

    # Get affected products (CPEs)
    affected_products = []
    configurations = cve_data.get('configurations', [])
    for config in configurations:
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable', False):
                    cpe = cpe_match.get('criteria', '')
                    # Parse CPE
                    parts = cpe.split(':')
                    if len(parts) >= 5:
                        affected_products.append({
                            'vendor': parts[3],
                            'product': parts[4],
                            'version': parts[5] if len(parts) > 5 else '*'
                        })

    return CVEResult(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        published_date=published_date,
        last_modified=last_modified,
        references=references[:5],  # Limit to 5 references
        cwe=cwe,
        affected_products=affected_products[:10]  # Limit to 10 products
    )


def get_severity_rating(cvss_score: float) -> str:
    """
    Get severity rating from CVSS score.

    Args:
        cvss_score: CVSS base score (0.0 - 10.0)

    Returns:
        Severity rating string
    """
    if cvss_score >= 9.0:
        return 'CRITICAL'
    elif cvss_score >= 7.0:
        return 'HIGH'
    elif cvss_score >= 4.0:
        return 'MEDIUM'
    elif cvss_score > 0:
        return 'LOW'
    else:
        return 'NONE'


def export_cves(cves: List[CVEResult], output_file: str, format: str = 'json'):
    """
    Export CVE results to file.

    Args:
        cves: List of CVEResult objects
        output_file: Output file path
        format: Output format ('json', 'txt', 'csv')
    """
    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump([cve.to_dict() for cve in cves], f, indent=2)

    elif format == 'txt':
        with open(output_file, 'w') as f:
            for cve in cves:
                f.write(f"\n{'=' * 80}\n")
                f.write(f"{cve.cve_id}\n")
                f.write(f"{'=' * 80}\n")
                f.write(f"Severity: {cve.cvss_severity or 'N/A'} (CVSS: {cve.cvss_score or 'N/A'})\n")
                f.write(f"Published: {cve.published_date or 'N/A'}\n")
                f.write(f"CWE: {cve.cwe or 'N/A'}\n\n")
                f.write(f"Description:\n{cve.description}\n\n")
                if cve.references:
                    f.write("References:\n")
                    for ref in cve.references:
                        f.write(f"  - {ref}\n")

    elif format == 'csv':
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['CVE ID', 'CVSS Score', 'Severity', 'Published', 'Description'])
            for cve in cves:
                writer.writerow([
                    cve.cve_id,
                    cve.cvss_score or '',
                    cve.cvss_severity or '',
                    cve.published_date or '',
                    cve.description[:200]  # Truncate description
                ])

    print(f"✓ CVE results exported to {output_file}")
