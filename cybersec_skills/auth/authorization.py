"""
Core authorization and scope validation logic.
"""

import json
import ipaddress
import re
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
from functools import wraps


class AuthorizationError(Exception):
    """Raised when operation is not authorized."""
    pass


class ScopeError(Exception):
    """Raised when target is outside authorized scope."""
    pass


class AuthContext:
    """Holds current authorization context."""

    def __init__(self):
        self.mode: Optional[str] = None
        self.scope: List[str] = []
        self.authorization_file: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
        self.initialized: bool = False

    def reset(self):
        """Reset authorization context."""
        self.mode = None
        self.scope = []
        self.authorization_file = None
        self.metadata = {}
        self.initialized = False


# Global authorization context
_auth_context = AuthContext()


def set_context(
    mode: str,
    scope: Optional[List[str]] = None,
    authorization_file: Optional[str] = None,
    **kwargs
) -> None:
    """
    Set authorization context for operations.

    Args:
        mode: Operation mode ('defensive', 'pentest', 'ctf', 'research')
        scope: List of authorized targets (domains, IPs, CIDR ranges)
        authorization_file: Path to authorization document (required for pentest)
        **kwargs: Additional metadata (competition, project_id, etc.)

    Raises:
        AuthorizationError: If required parameters are missing
    """
    valid_modes = ['defensive', 'pentest', 'ctf', 'research']

    if mode not in valid_modes:
        raise AuthorizationError(
            f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}"
        )

    # Pentest mode requires authorization file
    if mode == 'pentest' and not authorization_file:
        raise AuthorizationError(
            "Pentest mode requires authorization_file parameter"
        )

    # Load and validate authorization file if provided
    if authorization_file:
        auth_data = _load_authorization_file(authorization_file)
        scope = scope or auth_data.get('scope', [])
        kwargs.update(auth_data.get('metadata', {}))

    # Offensive modes require scope
    if mode in ['pentest', 'ctf', 'research'] and not scope:
        raise AuthorizationError(
            f"Mode '{mode}' requires scope parameter or authorization file"
        )

    _auth_context.mode = mode
    _auth_context.scope = scope or []
    _auth_context.authorization_file = authorization_file
    _auth_context.metadata = kwargs
    _auth_context.initialized = True

    print(f"✓ Authorization context set: mode={mode}, scope={len(_auth_context.scope)} targets")


def _load_authorization_file(filepath: str) -> Dict[str, Any]:
    """Load and validate authorization file."""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        # Validate required fields
        required = ['scope', 'authorized_by', 'valid_until']
        missing = [f for f in required if f not in data]
        if missing:
            raise AuthorizationError(
                f"Authorization file missing required fields: {', '.join(missing)}"
            )

        # Check expiration
        valid_until = datetime.fromisoformat(data['valid_until'])
        if datetime.now() > valid_until:
            raise AuthorizationError(
                f"Authorization expired on {data['valid_until']}"
            )

        return data

    except FileNotFoundError:
        raise AuthorizationError(f"Authorization file not found: {filepath}")
    except json.JSONDecodeError:
        raise AuthorizationError(f"Invalid JSON in authorization file: {filepath}")


def validate_target(target: str) -> bool:
    """
    Validate if target is within authorized scope.

    Args:
        target: IP address, domain, or URL to validate

    Returns:
        True if target is authorized

    Raises:
        AuthorizationError: If no authorization context set
        ScopeError: If target is outside authorized scope
    """
    if not _auth_context.initialized:
        raise AuthorizationError(
            "No authorization context set. Call set_context() first."
        )

    # Defensive mode doesn't need target validation
    if _auth_context.mode == 'defensive':
        return True

    # Extract domain/IP from target
    normalized_target = _normalize_target(target)

    # Check against scope
    for scope_pattern in _auth_context.scope:
        if _matches_scope(normalized_target, scope_pattern):
            return True

    raise ScopeError(
        f"Target '{target}' is outside authorized scope: {_auth_context.scope}"
    )


def _normalize_target(target: str) -> str:
    """Extract domain or IP from various target formats."""
    # Remove protocol
    target = re.sub(r'^https?://', '', target)
    # Remove port
    target = re.sub(r':\d+$', '', target)
    # Remove path
    target = target.split('/')[0]
    return target.lower()


def _matches_scope(target: str, scope_pattern: str) -> bool:
    """Check if target matches scope pattern."""
    # Try IP/CIDR matching
    try:
        target_ip = ipaddress.ip_address(target)
        scope_network = ipaddress.ip_network(scope_pattern, strict=False)
        return target_ip in scope_network
    except ValueError:
        pass

    # Try domain matching (supports wildcards)
    scope_regex = scope_pattern.replace('.', r'\.')
    scope_regex = scope_regex.replace('*', '.*')
    scope_regex = f'^{scope_regex}$'

    return bool(re.match(scope_regex, target))


def require_authorization(offensive: bool = True):
    """
    Decorator to require authorization for skill operations.

    Args:
        offensive: If True, requires offensive mode authorization
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if authorization context is set
            if not _auth_context.initialized:
                raise AuthorizationError(
                    f"Authorization required for {func.__name__}. "
                    "Call auth.set_context() first."
                )

            # Check if operation is allowed in current mode
            if offensive and _auth_context.mode == 'defensive':
                raise AuthorizationError(
                    f"{func.__name__} is an offensive operation, "
                    "but current mode is 'defensive'"
                )

            # Log operation
            from .audit import log_operation
            log_operation(
                skill=func.__module__,
                operation=func.__name__,
                args=args,
                kwargs=kwargs
            )

            return func(*args, **kwargs)

        return wrapper
    return decorator


def get_current_mode() -> Optional[str]:
    """Get current authorization mode."""
    return _auth_context.mode if _auth_context.initialized else None


def get_scope() -> List[str]:
    """Get current authorized scope."""
    return _auth_context.scope.copy()


def is_initialized() -> bool:
    """Check if authorization context is initialized."""
    return _auth_context.initialized
