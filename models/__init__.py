"""
Attack Data Models Module
==========================

This module defines dataclasses for different attack session types.
Each class represents the structured data captured by a specific honeypot/detector.
"""

from .session_models import (
    SSHSession,
    PortScanSession,
    DNSSession,
    ARPSession,
    ICMPSession,
    AttackType,
)

__all__ = [
    "SSHSession",
    "PortScanSession",
    "DNSSession",
    "ARPSession",
    "ICMPSession",
    "AttackType",
]
