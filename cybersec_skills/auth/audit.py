"""
Audit logging for all security operations.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class AuditLog:
    """Manages audit trail for security operations."""

    def __init__(self):
        self.entries: List[Dict[str, Any]] = []
        self.log_file: Optional[Path] = None

    def add_entry(self, entry: Dict[str, Any]):
        """Add entry to audit log."""
        entry['timestamp'] = datetime.now().isoformat()
        self.entries.append(entry)

        # Write to file if configured
        if self.log_file:
            self._write_to_file(entry)

    def _write_to_file(self, entry: Dict[str, Any]):
        """Append entry to log file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"Warning: Failed to write to audit log: {e}")

    def set_log_file(self, filepath: str):
        """Set audit log file path."""
        self.log_file = Path(filepath)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)


# Global audit log
_audit_log = AuditLog()


def log_operation(
    skill: str,
    operation: str,
    args: tuple = (),
    kwargs: dict = None,
    result: Any = None,
    error: Optional[str] = None
) -> None:
    """
    Log a security operation.

    Args:
        skill: Skill module name
        operation: Operation/function name
        args: Positional arguments
        kwargs: Keyword arguments
        result: Operation result (optional)
        error: Error message if operation failed
    """
    from .authorization import get_current_mode

    kwargs = kwargs or {}

    # Sanitize sensitive data
    safe_kwargs = {
        k: v if k not in ['password', 'token', 'api_key'] else '***'
        for k, v in kwargs.items()
    }

    entry = {
        'timestamp': datetime.now().isoformat(),
        'mode': get_current_mode(),
        'skill': skill,
        'operation': operation,
        'args': str(args)[:200],  # Truncate long args
        'kwargs': safe_kwargs,
        'success': error is None,
        'error': error
    }

    if result is not None:
        entry['result_summary'] = str(result)[:200]

    _audit_log.add_entry(entry)


def get_audit_trail(
    skill: Optional[str] = None,
    operation: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get audit trail entries.

    Args:
        skill: Filter by skill name
        operation: Filter by operation name
        limit: Maximum number of entries to return

    Returns:
        List of audit log entries
    """
    entries = _audit_log.entries

    if skill:
        entries = [e for e in entries if e['skill'] == skill]

    if operation:
        entries = [e for e in entries if e['operation'] == operation]

    return entries[-limit:]


def export_audit_log(filepath: str, format: str = 'json') -> None:
    """
    Export audit log to file.

    Args:
        filepath: Output file path
        format: Output format ('json' or 'csv')
    """
    output_path = Path(filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format == 'json':
        with open(output_path, 'w') as f:
            json.dump(_audit_log.entries, f, indent=2)

    elif format == 'csv':
        import csv
        if not _audit_log.entries:
            return

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=_audit_log.entries[0].keys())
            writer.writeheader()
            writer.writerows(_audit_log.entries)

    else:
        raise ValueError(f"Unsupported format: {format}")

    print(f"✓ Audit log exported to {output_path}")


def set_audit_file(filepath: str) -> None:
    """
    Enable real-time audit logging to file.

    Args:
        filepath: Path to audit log file
    """
    _audit_log.set_log_file(filepath)
    print(f"✓ Audit logging enabled: {filepath}")
