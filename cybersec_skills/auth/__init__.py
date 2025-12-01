"""
Authorization and Ethics Framework for Cybersecurity Skills

This module provides authorization validation, scope checking, and audit logging
for all offensive security operations.
"""

from .authorization import (
    set_context,
    validate_target,
    require_authorization,
    get_current_mode,
    AuthorizationError,
    ScopeError
)

from .audit import (
    log_operation,
    get_audit_trail,
    export_audit_log
)

__all__ = [
    'set_context',
    'validate_target',
    'require_authorization',
    'get_current_mode',
    'log_operation',
    'get_audit_trail',
    'export_audit_log',
    'AuthorizationError',
    'ScopeError'
]
