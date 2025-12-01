"""
Nmap Network Scanning Skill

Performs network reconnaissance and service enumeration using Nmap.
Supports various scan types: TCP SYN, version detection, OS detection, NSE scripts.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import tempfile
import os

from ..auth import require_authorization, validate_target


@dataclass
class Port:
    """Represents a discovered port."""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None


@dataclass
class NmapResult:
    """Result from Nmap scan."""
    target: str
    scan_type: str
    ports: List[Port]
    os_detection: Optional[Dict[str, str]] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'ports': [p.__dict__ for p in self.ports],
            'os_detection': self.os_detection,
            'timestamp': self.timestamp
        }


@require_authorization(offensive=True)
def scan_target(
    target: str,
    scan_type: str = 'quick',
    ports: Optional[str] = None,
    version_detection: bool = True,
    os_detection: bool = False,
    scripts: Optional[List[str]] = None,
    timing: int = 3
) -> NmapResult:
    """
    Perform Nmap scan on target.

    Args:
        target: Target IP address, hostname, or CIDR range
        scan_type: Scan type:
            - 'quick': Top 1000 ports (default)
            - 'full': All 65535 ports
            - 'stealth': SYN stealth scan
            - 'connect': TCP connect scan
        ports: Specific ports to scan (e.g., '80,443,8080' or '1-1000')
        version_detection: Enable service/version detection
        os_detection: Enable OS detection (requires root)
        scripts: NSE scripts to run (e.g., ['vuln', 'exploit'])
        timing: Timing template (0-5, default 3)

    Returns:
        NmapResult with scan findings

    Raises:
        AuthorizationError: If not authorized
        ScopeError: If target is outside scope
    """
    # Validate target is authorized
    validate_target(target)

    print(f"[*] Scanning {target} with Nmap ({scan_type} scan)")

    # Build Nmap command
    nmap_cmd = _build_nmap_command(
        target=target,
        scan_type=scan_type,
        ports=ports,
        version_detection=version_detection,
        os_detection=os_detection,
        scripts=scripts,
        timing=timing
    )

    # Execute scan
    print(f"[*] Executing: {' '.join(nmap_cmd[:5])}...")
    result = _execute_nmap(nmap_cmd)

    # Parse results
    parsed = _parse_nmap_xml(result['xml'])

    print(f"[+] Scan complete: {len(parsed.ports)} open ports found")

    return parsed


def _build_nmap_command(
    target: str,
    scan_type: str,
    ports: Optional[str],
    version_detection: bool,
    os_detection: bool,
    scripts: Optional[List[str]],
    timing: int
) -> List[str]:
    """Build Nmap command line arguments."""
    cmd = ['nmap']

    # Scan type
    if scan_type == 'stealth':
        cmd.append('-sS')  # SYN stealth scan
    elif scan_type == 'connect':
        cmd.append('-sT')  # TCP connect scan
    elif scan_type == 'full':
        cmd.append('-p-')  # All ports
    # 'quick' is default (top 1000 ports)

    # Port specification
    if ports:
        cmd.extend(['-p', ports])

    # Version detection
    if version_detection:
        cmd.append('-sV')

    # OS detection
    if os_detection:
        cmd.append('-O')

    # NSE scripts
    if scripts:
        cmd.extend(['--script', ','.join(scripts)])

    # Timing
    cmd.append(f'-T{timing}')

    # Output format (XML for parsing)
    cmd.extend(['-oX', '-'])  # Output XML to stdout

    # Target
    cmd.append(target)

    return cmd


def _execute_nmap(cmd: List[str]) -> Dict[str, str]:
    """Execute Nmap command and capture output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        if result.returncode != 0:
            raise Exception(f"Nmap failed: {result.stderr}")

        return {
            'xml': result.stdout,
            'stderr': result.stderr
        }

    except subprocess.TimeoutExpired:
        raise Exception("Nmap scan timed out after 10 minutes")
    except FileNotFoundError:
        raise Exception(
            "Nmap not found. Please install nmap: "
            "apt-get install nmap (Linux) or brew install nmap (macOS)"
        )


def _parse_nmap_xml(xml_output: str) -> NmapResult:
    """Parse Nmap XML output."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        raise Exception(f"Failed to parse Nmap XML output: {e}")

    # Get host info
    host = root.find('.//host')
    if host is None:
        raise Exception("No host found in Nmap output")

    # Get target address
    address = host.find('.//address[@addrtype="ipv4"]')
    if address is None:
        address = host.find('.//address')
    target = address.get('addr') if address is not None else 'unknown'

    # Parse ports
    ports = []
    for port_elem in host.findall('.//port'):
        port_num = int(port_elem.get('portid'))
        protocol = port_elem.get('protocol')

        state_elem = port_elem.find('state')
        state = state_elem.get('state') if state_elem is not None else 'unknown'

        # Skip closed/filtered ports
        if state != 'open':
            continue

        service_elem = port_elem.find('service')
        if service_elem is not None:
            service = service_elem.get('name')
            product = service_elem.get('product')
            version = service_elem.get('version')
        else:
            service = product = version = None

        ports.append(Port(
            port=port_num,
            protocol=protocol,
            state=state,
            service=service,
            product=product,
            version=version
        ))

    # Parse OS detection if available
    os_detection = None
    osmatch = host.find('.//osmatch')
    if osmatch is not None:
        os_detection = {
            'name': osmatch.get('name'),
            'accuracy': osmatch.get('accuracy')
        }

    return NmapResult(
        target=target,
        scan_type='nmap',
        ports=ports,
        os_detection=os_detection
    )


def parse_nmap_output(xml_file: str) -> NmapResult:
    """
    Parse existing Nmap XML output file.

    Args:
        xml_file: Path to Nmap XML output file

    Returns:
        NmapResult with parsed scan data
    """
    with open(xml_file, 'r') as f:
        xml_content = f.read()

    return _parse_nmap_xml(xml_content)


def export_results(result: NmapResult, output_file: str, format: str = 'json'):
    """
    Export scan results to file.

    Args:
        result: NmapResult to export
        output_file: Output file path
        format: Output format ('json', 'txt', 'csv')
    """
    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)

    elif format == 'txt':
        with open(output_file, 'w') as f:
            f.write(f"Nmap Scan Results for {result.target}\n")
            f.write(f"Scan Time: {result.timestamp}\n\n")
            f.write(f"Open Ports ({len(result.ports)}):\n")
            for port in result.ports:
                service_info = f"{port.service}" if port.service else "unknown"
                if port.product:
                    service_info += f" ({port.product}"
                    if port.version:
                        service_info += f" {port.version}"
                    service_info += ")"
                f.write(f"  {port.port}/{port.protocol}: {service_info}\n")

    elif format == 'csv':
        import csv
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Product', 'Version'])
            for port in result.ports:
                writer.writerow([
                    port.port, port.protocol, port.state,
                    port.service or '', port.product or '', port.version or ''
                ])

    print(f"✓ Results exported to {output_file}")
