"""
Session Data Models for Multi-Attack Honeypot System
=====================================================

This module defines dataclasses for each attack type's session data.
These models provide:
  - Type safety and validation
  - Clear documentation of captured fields
  - Easy serialization to CSV format
  - Shared interface across all attack types

Design Philosophy:
  Each attack type has unique characteristics, so we use separate
  dataclasses rather than one monolithic class. This makes the code
  more maintainable and allows type-specific validation.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any


class AttackType(Enum):
    """Enumeration of supported attack types for logging and classification."""
    SSH = "ssh"
    PORTSCAN = "portscan"
    DNS = "dns"
    ARP = "arp"
    ICMP = "icmp"


# ═══════════════════════════════════════════════════════════════════════════
# SSH ATTACK SESSION (existing attack type)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SSHSession:
    """
    Data captured from an SSH honeypot session.
    
    Attributes:
        ip_address: Source IP address of attacker
        login_attempts: Number of username/password attempts
        session_duration: Total connection time in seconds
        commands_sent: Number of shell commands entered
        command_types: Count of reconnaissance commands (ls, pwd, whoami, etc.)
        successful_login: Whether attacker reached the fake shell (1=yes, 0=no)
        timestamp: Session start time
        mac_address: MAC address if available (Layer 2)
    """
    ip_address: str
    login_attempts: int
    session_duration: float
    commands_sent: int
    command_types: int
    successful_login: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mac_address: Optional[str] = None
    
    @property
    def attack_type(self) -> str:
        return AttackType.SSH.value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV logging."""
        data = asdict(self)
        data['attack_type'] = self.attack_type
        return data


# ═══════════════════════════════════════════════════════════════════════════
# PORT SCAN SESSION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PortScanSession:
    """
    Data captured from port scanning activity.
    
    Attributes:
        ip_address: Source IP of scanner
        ports_scanned: Comma-separated list of ports hit (e.g., "22,80,443")
        scan_type: Type of scan detected (syn, stealth, aggressive, sweep)
        scan_speed: Ports per second
        stealth_detected: Whether scan used stealth techniques (1=yes, 0=no)
        syn_count: Number of SYN packets detected
        session_duration: Time window of scanning activity
        packet_count: Total packets observed
        timestamp: When scan was first detected
        mac_address: MAC address if available
    """
    ip_address: str
    ports_scanned: str  # e.g., "22,80,443,8080"
    scan_type: str  # syn, stealth, aggressive, sweep
    scan_speed: float  # ports per second
    stealth_detected: int  # 1=yes, 0=no
    syn_count: int
    session_duration: float
    packet_count: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mac_address: Optional[str] = None
    
    @property
    def attack_type(self) -> str:
        return AttackType.PORTSCAN.value
    
    @property
    def port_count(self) -> int:
        """Calculate number of unique ports scanned."""
        if not self.ports_scanned:
            return 0
        return len(set(self.ports_scanned.split(',')))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV logging."""
        data = asdict(self)
        data['attack_type'] = self.attack_type
        return data


# ═══════════════════════════════════════════════════════════════════════════
# DNS ATTACK SESSION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DNSSession:
    """
    Data captured from DNS honeypot interactions.
    
    Attributes:
        ip_address: Source IP of DNS client
        dns_query: The queried domain name
        dns_query_type: Query type (A, AAAA, TXT, ANY, etc.)
        query_rate: Queries per second from this IP
        tunneling_detected: Whether DNS tunneling pattern detected (1=yes, 0=no)
        amplification_detected: Whether amplification attempt detected (1=yes, 0=no)
        session_duration: Duration of DNS activity window
        packet_count: Total DNS packets from this IP
        timestamp: First query timestamp
        mac_address: MAC address if available
    """
    ip_address: str
    dns_query: str  # e.g., "example.com" or suspicious "aGVsbG8ud29ybGQ.evil.com"
    dns_query_type: str  # A, AAAA, TXT, ANY, etc.
    query_rate: float  # queries per second
    tunneling_detected: int  # 1=yes, 0=no
    amplification_detected: int  # 1=yes, 0=no
    session_duration: float
    packet_count: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mac_address: Optional[str] = None
    
    @property
    def attack_type(self) -> str:
        return AttackType.DNS.value
    
    @property
    def subdomain_length(self) -> int:
        """Length of query (long subdomains indicate potential tunneling)."""
        return len(self.dns_query)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV logging."""
        data = asdict(self)
        data['attack_type'] = self.attack_type
        return data


# ═══════════════════════════════════════════════════════════════════════════
# ARP SPOOFING SESSION (Layer 2 attack)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ARPSession:
    """
    Data captured from ARP spoofing/poisoning detection.
    
    Attributes:
        ip_address: IP address involved in spoofing
        mac_address: MAC address from ARP packet (REQUIRED for ARP attacks)
        arp_op_type: ARP operation type (1=request, 2=reply)
        gratuitous_arp: Whether gratuitous ARP detected (1=yes, 0=no)
        ip_conflict: Whether IP conflict detected (1=yes, 0=no)
        mac_conflict: Whether same IP maps to multiple MACs (1=yes, 0=no)
        arp_reply_rate: ARP replies per second
        session_duration: Duration of suspicious ARP activity
        packet_count: Total ARP packets observed
        timestamp: First suspicious ARP packet timestamp
    """
    ip_address: str
    mac_address: str  # Required for ARP attacks
    arp_op_type: int  # 1=request, 2=reply
    gratuitous_arp: int  # 1=yes, 0=no
    ip_conflict: int  # 1=yes, 0=no
    mac_conflict: int  # 1=yes, 0=no
    arp_reply_rate: float  # replies per second
    session_duration: float
    packet_count: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    @property
    def attack_type(self) -> str:
        return AttackType.ARP.value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV logging."""
        data = asdict(self)
        data['attack_type'] = self.attack_type
        return data


# ═══════════════════════════════════════════════════════════════════════════
# ICMP ATTACK SESSION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ICMPSession:
    """
    Data captured from ICMP attack detection.
    
    Attributes:
        ip_address: Source IP of ICMP packets
        icmp_type: ICMP type code (8=echo request, 0=echo reply, etc.)
        icmp_code: ICMP code
        packet_size: Size of ICMP packets in bytes
        icmp_rate: ICMP packets per second
        flood_detected: Whether flood pattern detected (1=yes, 0=no)
        oversized_detected: Whether oversized packets detected (1=yes, 0=no)
        session_duration: Duration of ICMP activity
        packet_count: Total ICMP packets
        timestamp: First ICMP packet timestamp
        mac_address: MAC address if available
    """
    ip_address: str
    icmp_type: int  # ICMP type code
    icmp_code: int  # ICMP code
    packet_size: int  # bytes
    icmp_rate: float  # packets per second
    flood_detected: int  # 1=yes, 0=no
    oversized_detected: int  # 1=yes, 0=no (>65535 bytes)
    session_duration: float
    packet_count: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mac_address: Optional[str] = None
    
    @property
    def attack_type(self) -> str:
        return AttackType.ICMP.value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV logging."""
        data = asdict(self)
        data['attack_type'] = self.attack_type
        return data


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_csv_columns() -> list:
    """
    Return the complete list of CSV columns for the unified logging schema.
    
    This function generates the column order for the CSV file, including:
    - Common fields (timestamp, ip_address, mac_address, attack_type, etc.)
    - Attack-type-specific fields (all types combined)
    
    Fields will be null/empty for non-applicable attack types.
    """
    return [
        # Common fields (all attack types)
        "timestamp",
        "ip_address",
        "mac_address",
        "attack_type",
        "session_duration",
        "packet_count",
        
        # SSH-specific
        "login_attempts",
        "successful_login",
        "commands_sent",
        "command_types",
        
        # PortScan-specific
        "ports_scanned",
        "scan_type",
        "scan_speed",
        "stealth_detected",
        "syn_count",
        
        # DNS-specific
        "dns_query",
        "dns_query_type",
        "query_rate",
        "tunneling_detected",
        "amplification_detected",
        
        # ARP-specific
        "arp_op_type",
        "gratuitous_arp",
        "ip_conflict",
        "mac_conflict",
        "arp_reply_rate",
        
        # ICMP-specific
        "icmp_type",
        "icmp_code",
        "packet_size",
        "icmp_rate",
        "flood_detected",
        "oversized_detected",
    ]
