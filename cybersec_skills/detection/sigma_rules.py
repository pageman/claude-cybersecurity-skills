"""
Sigma Rule Creation and Management Skill

Create and manage Sigma detection rules for threat hunting and SIEM integration.
Sigma is a generic signature format for log events.
"""

import yaml
import uuid
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SigmaRule:
    """Represents a Sigma detection rule."""
    title: str
    description: str
    logsource: Dict[str, str]
    detection: Dict
    level: str = 'medium'
    status: str = 'experimental'
    author: str = 'Claude Cybersecurity Skills'
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    date: str = field(default_factory=lambda: datetime.now().strftime('%Y/%m/%d'))

    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            'title': self.title,
            'id': self.id,
            'status': self.status,
            'description': self.description,
            'references': self.references,
            'author': self.author,
            'date': self.date,
            'tags': self.tags,
            'logsource': self.logsource,
            'detection': self.detection,
            'falsepositives': self.falsepositives,
            'level': self.level
        }

    def to_yaml(self) -> str:
        """Convert rule to YAML format."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    def save(self, filepath: str):
        """Save rule to YAML file."""
        with open(filepath, 'w') as f:
            f.write(self.to_yaml())
        print(f"✓ Sigma rule saved to {filepath}")


def create_sigma_rule(
    title: str,
    description: str,
    logsource_category: str,
    logsource_product: Optional[str] = None,
    detection_selection: Optional[Dict] = None,
    detection_filter: Optional[Dict] = None,
    condition: str = 'selection',
    level: str = 'medium',
    mitre_technique: Optional[str] = None,
    falsepositives: Optional[List[str]] = None,
    references: Optional[List[str]] = None
) -> SigmaRule:
    """
    Create a Sigma detection rule.

    Args:
        title: Rule title
        description: Detailed description of what the rule detects
        logsource_category: Log source category (e.g., 'process_creation', 'network_connection')
        logsource_product: Product name (e.g., 'windows', 'linux', 'aws')
        detection_selection: Selection criteria (fields to match)
        detection_filter: Filter criteria (fields to exclude)
        condition: Detection condition (e.g., 'selection', 'selection and not filter')
        level: Severity level (low, medium, high, critical)
        mitre_technique: MITRE ATT&CK technique ID (e.g., 'T1078')
        falsepositives: List of known false positive scenarios
        references: List of reference URLs

    Returns:
        SigmaRule object
    """
    # Build logsource
    logsource = {'category': logsource_category}
    if logsource_product:
        logsource['product'] = logsource_product

    # Build detection logic
    detection = {}

    if detection_selection:
        detection['selection'] = detection_selection

    if detection_filter:
        detection['filter'] = detection_filter
        if 'and not filter' not in condition:
            condition += ' and not filter'

    detection['condition'] = condition

    # Build tags
    tags = []
    if mitre_technique:
        tags.append(f'attack.{mitre_technique.lower()}')

    print(f"[+] Created Sigma rule: {title}")
    print(f"    Level: {level}")
    print(f"    Logsource: {logsource}")

    return SigmaRule(
        title=title,
        description=description,
        logsource=logsource,
        detection=detection,
        level=level,
        tags=tags,
        falsepositives=falsepositives or [],
        references=references or []
    )


def create_process_execution_rule(
    title: str,
    description: str,
    process_name: Optional[str] = None,
    command_line: Optional[str] = None,
    parent_process: Optional[str] = None,
    level: str = 'medium',
    mitre_technique: Optional[str] = None
) -> SigmaRule:
    """
    Create a Sigma rule for detecting suspicious process execution.

    Args:
        title: Rule title
        description: Rule description
        process_name: Process/executable name to detect
        command_line: Command line pattern to detect
        parent_process: Parent process name
        level: Severity level
        mitre_technique: MITRE ATT&CK technique ID

    Returns:
        SigmaRule object
    """
    selection = {}

    if process_name:
        selection['Image|endswith'] = process_name

    if command_line:
        selection['CommandLine|contains'] = command_line

    if parent_process:
        selection['ParentImage|endswith'] = parent_process

    return create_sigma_rule(
        title=title,
        description=description,
        logsource_category='process_creation',
        logsource_product='windows',
        detection_selection=selection,
        level=level,
        mitre_technique=mitre_technique
    )


def create_network_connection_rule(
    title: str,
    description: str,
    destination_ip: Optional[str] = None,
    destination_port: Optional[int] = None,
    process_name: Optional[str] = None,
    level: str = 'medium',
    mitre_technique: Optional[str] = None
) -> SigmaRule:
    """
    Create a Sigma rule for detecting suspicious network connections.

    Args:
        title: Rule title
        description: Rule description
        destination_ip: Destination IP address
        destination_port: Destination port
        process_name: Process making the connection
        level: Severity level
        mitre_technique: MITRE ATT&CK technique ID

    Returns:
        SigmaRule object
    """
    selection = {}

    if destination_ip:
        selection['DestinationIp'] = destination_ip

    if destination_port:
        selection['DestinationPort'] = destination_port

    if process_name:
        selection['Image|endswith'] = process_name

    return create_sigma_rule(
        title=title,
        description=description,
        logsource_category='network_connection',
        logsource_product='windows',
        detection_selection=selection,
        level=level,
        mitre_technique=mitre_technique
    )


def create_authentication_rule(
    title: str,
    description: str,
    username: Optional[str] = None,
    logon_type: Optional[int] = None,
    workstation_name: Optional[str] = None,
    level: str = 'medium',
    mitre_technique: Optional[str] = None
) -> SigmaRule:
    """
    Create a Sigma rule for detecting suspicious authentication events.

    Args:
        title: Rule title
        description: Rule description
        username: Username to detect
        logon_type: Windows logon type (2=interactive, 3=network, 10=RDP)
        workstation_name: Workstation name pattern
        level: Severity level
        mitre_technique: MITRE ATT&CK technique ID

    Returns:
        SigmaRule object
    """
    selection = {'EventID': 4624}  # Windows successful logon

    if username:
        selection['TargetUserName'] = username

    if logon_type:
        selection['LogonType'] = logon_type

    if workstation_name:
        selection['WorkstationName|contains'] = workstation_name

    return create_sigma_rule(
        title=title,
        description=description,
        logsource_category='authentication',
        logsource_product='windows',
        detection_selection=selection,
        level=level,
        mitre_technique=mitre_technique
    )


def validate_sigma_rule(rule: SigmaRule) -> tuple[bool, List[str]]:
    """
    Validate a Sigma rule for correctness.

    Args:
        rule: SigmaRule to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Check required fields
    if not rule.title:
        errors.append("Rule must have a title")

    if not rule.description:
        errors.append("Rule must have a description")

    if not rule.logsource:
        errors.append("Rule must have a logsource")

    if not rule.detection:
        errors.append("Rule must have detection logic")

    # Validate detection logic
    if 'condition' not in rule.detection:
        errors.append("Detection must include a condition")

    # Validate level
    valid_levels = ['low', 'medium', 'high', 'critical']
    if rule.level not in valid_levels:
        errors.append(f"Level must be one of: {', '.join(valid_levels)}")

    # Validate status
    valid_statuses = ['stable', 'test', 'experimental', 'deprecated']
    if rule.status not in valid_statuses:
        errors.append(f"Status must be one of: {', '.join(valid_statuses)}")

    is_valid = len(errors) == 0

    if is_valid:
        print(f"✓ Rule '{rule.title}' is valid")
    else:
        print(f"✗ Rule '{rule.title}' has {len(errors)} validation errors")
        for error in errors:
            print(f"  - {error}")

    return is_valid, errors


def load_sigma_rule(filepath: str) -> SigmaRule:
    """
    Load Sigma rule from YAML file.

    Args:
        filepath: Path to YAML file

    Returns:
        SigmaRule object
    """
    with open(filepath, 'r') as f:
        data = yaml.safe_load(f)

    return SigmaRule(
        title=data['title'],
        description=data['description'],
        logsource=data['logsource'],
        detection=data['detection'],
        level=data.get('level', 'medium'),
        status=data.get('status', 'experimental'),
        author=data.get('author', 'Unknown'),
        references=data.get('references', []),
        tags=data.get('tags', []),
        falsepositives=data.get('falsepositives', []),
        id=data.get('id', str(uuid.uuid4())),
        date=data.get('date', datetime.now().strftime('%Y/%m/%d'))
    )
