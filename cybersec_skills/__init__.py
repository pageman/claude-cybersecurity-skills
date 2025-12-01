"""
Claude Cybersecurity Skills

A comprehensive collection of cybersecurity skills for Claude Code.
"""

__version__ = '0.1.0'

# Import submodules for easy access
from . import auth
from . import recon
from . import network
from . import vuln_mgmt
from . import detection

__all__ = [
    'auth',
    'recon',
    'network',
    'vuln_mgmt',
    'detection'
]
