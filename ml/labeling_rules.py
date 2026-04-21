"""
Multi-Attack Labeling Rules
============================

This module defines the rules for generating synthetic labels for the
ML classification model. Labels are based on behavioral patterns and
detection flags captured during attack sessions.

Label Classes (13 total):
  SSH (3): ssh_normal, ssh_brute_force, ssh_reconnaissance
  PortScan (3): portscan_stealth, portscan_aggressive, portscan_sweep
  DNS (3): dns_normal, dns_tunneling, dns_amplification
  ARP (2): arp_spoofing, arp_poisoning
  ICMP (2): icmp_flood, icmp_ping_of_death

Why Synthetic Labels?
  In a honeypot simulation, we don't have human-labeled ground truth.
  These rules encode domain knowledge about attack patterns into
  automatic labels based on the captured session features.

Rule Design Philosophy:
  1. Use detection flags when available (high confidence)
  2. Use rate/count thresholds as fallback (medium confidence)
  3. Combine multiple indicators for better accuracy
  4. Default to "normal" when no attack indicators present
"""

import pandas as pd
import numpy as np


# ═══════════════════════════════════════════════════════════════════════════
# LABELING THRESHOLDS
# ═══════════════════════════════════════════════════════════════════════════

# SSH Thresholds
SSH_BRUTE_FORCE_LOGIN_THRESHOLD = 10  # >10 login attempts = brute force
SSH_RECON_COMMAND_THRESHOLD = 3       # >=3 commands = reconnaissance

# PortScan Thresholds
PORTSCAN_AGGRESSIVE_SPEED = 10.0      # >10 ports/sec = aggressive
PORTSCAN_SWEEP_PORT_COUNT = 5         # <5 ports but scanned = sweep

# DNS Thresholds
DNS_HIGH_QUERY_RATE = 10.0            # >10 queries/sec = suspicious

# ARP Thresholds
ARP_HIGH_REPLY_RATE = 5.0             # >5 ARP/sec = suspicious

# ICMP Thresholds
ICMP_FLOOD_RATE = 50.0                # >50 packets/sec = flood
ICMP_OVERSIZED_THRESHOLD = 1500       # >1500 bytes = ping of death


def generate_labels(df: pd.DataFrame) -> pd.Series:
    """
    Generate attack type labels based on behavioral rules.
    
    This is the main labeling function that routes to attack-type-specific
    labeling based on the 'attack_type' column (ssh, portscan, dns, arp, icmp).
    
    Args:
        df: DataFrame with attack session data including 'attack_type' column
    
    Returns:
        Series of string labels (one per row)
    """
    labels = pd.Series(index=df.index, dtype='object')
    
    # Handle legacy data without attack_type column (assume SSH)
    if 'attack_type' not in df.columns:
        return label_ssh_attacks(df)
    
    # Label each attack type separately
    ssh_mask = df['attack_type'] == 'ssh'
    portscan_mask = df['attack_type'] == 'portscan'
    dns_mask = df['attack_type'] == 'dns'
    arp_mask = df['attack_type'] == 'arp'
    icmp_mask = df['attack_type'] == 'icmp'
    
    # Apply type-specific labeling
    if ssh_mask.any():
        labels[ssh_mask] = label_ssh_attacks(df[ssh_mask])
    
    if portscan_mask.any():
        labels[portscan_mask] = label_portscan_attacks(df[portscan_mask])
    
    if dns_mask.any():
        labels[dns_mask] = label_dns_attacks(df[dns_mask])
    
    if arp_mask.any():
        labels[arp_mask] = label_arp_attacks(df[arp_mask])
    
    if icmp_mask.any():
        labels[icmp_mask] = label_icmp_attacks(df[icmp_mask])
    
    # Fill any remaining NaN with "unknown"
    labels = labels.fillna('unknown')
    
    return labels


def label_ssh_attacks(df: pd.DataFrame) -> pd.Series:
    """
    Label SSH attack sessions.
    
    Rules:
      - login_attempts > 10 AND commands_sent == 0 → ssh_brute_force
      - commands_sent >= 3 → ssh_reconnaissance
      - Otherwise → ssh_normal
    
    Args:
        df: DataFrame with SSH session data
    
    Returns:
        Series of SSH labels
    """
    labels = pd.Series(index=df.index, dtype='object')
    
    login_attempts = pd.to_numeric(df.get('login_attempts', 0), errors='coerce').fillna(0)
    commands_sent = pd.to_numeric(df.get('commands_sent', 0), errors='coerce').fillna(0)
    
    # Brute force: many login attempts, no shell activity
    brute_force = (login_attempts > SSH_BRUTE_FORCE_LOGIN_THRESHOLD) & (commands_sent == 0)
    
    # Reconnaissance: got shell access and typed commands
    reconnaissance = commands_sent >= SSH_RECON_COMMAND_THRESHOLD
    
    # Apply labels
    labels[:] = 'ssh_normal'
    labels[reconnaissance] = 'ssh_reconnaissance'
    labels[brute_force] = 'ssh_brute_force'
    
    return labels


def label_portscan_attacks(df: pd.DataFrame) -> pd.Series:
    """
    Label port scan sessions.
    
    Rules:
      - stealth_detected == 1 → portscan_stealth
      - scan_speed > 10 → portscan_aggressive
      - Otherwise → portscan_sweep
    
    Args:
        df: DataFrame with port scan data
    
    Returns:
        Series of port scan labels
    """
    labels = pd.Series(index=df.index, dtype='object')
    
    stealth = pd.to_numeric(df.get('stealth_detected', 0), errors='coerce').fillna(0)
    scan_speed = pd.to_numeric(df.get('scan_speed', 0), errors='coerce').fillna(0)
    
    # Default to sweep
    labels[:] = 'portscan_sweep'
    
    # Stealth scan (slow and randomized)
    labels[stealth == 1] = 'portscan_stealth'
    
    # Aggressive scan (fast)
    labels[scan_speed > PORTSCAN_AGGRESSIVE_SPEED] = 'portscan_aggressive'
    
    return labels


def label_dns_attacks(df: pd.DataFrame) -> pd.Series:
    """
    Label DNS attack sessions.
    
    Rules:
      - tunneling_detected == 1 → dns_tunneling
      - amplification_detected == 1 → dns_amplification
      - Otherwise → dns_normal
    
    Args:
        df: DataFrame with DNS session data
    
    Returns:
        Series of DNS labels
    """
    labels = pd.Series(index=df.index, dtype='object')
    
    tunneling = pd.to_numeric(df.get('tunneling_detected', 0), errors='coerce').fillna(0)
    amplification = pd.to_numeric(df.get('amplification_detected', 0), errors='coerce').fillna(0)
    
    labels[:] = 'dns_normal'
    labels[tunneling == 1] = 'dns_tunneling'
    labels[amplification == 1] = 'dns_amplification'
    
    return labels


def label_arp_attacks(df: pd.DataFrame) -> pd.Series:
    """
    Label ARP attack sessions.
    
    Rules:
      - mac_conflict == 1 OR ip_conflict == 1 → arp_poisoning
      - gratuitous_arp == 1 → arp_spoofing
      - Otherwise → arp_spoofing (default for ARP attacks)
    
    Args:
        df: DataFrame with ARP session data
    
    Returns:
        Series of ARP labels
    """
    labels = pd.Series(index=df.index, dtype='object')
    
    mac_conflict = pd.to_numeric(df.get('mac_conflict', 0), errors='coerce').fillna(0)
    ip_conflict = pd.to_numeric(df.get('ip_conflict', 0), errors='coerce').fillna(0)
    gratuitous = pd.to_numeric(df.get('gratuitous_arp', 0), errors='coerce').fillna(0)
    
    # Default to spoofing
    labels[:] = 'arp_spoofing'
    
    # Poisoning: MAC/IP conflicts (more serious)
    labels[(mac_conflict == 1) | (ip_conflict == 1)] = 'arp_poisoning'
    
    return labels


def label_icmp_attacks(df: pd.DataFrame) -> pd.Series:
    """
    Label ICMP attack sessions.
    
    Rules:
      - oversized_detected == 1 → icmp_ping_of_death
      - flood_detected == 1 OR icmp_rate > 50 → icmp_flood
      - Otherwise → icmp_flood (default for ICMP attacks)
    
    Args:
        df: DataFrame with ICMP session data
    
    Returns:
        Series of ICMP labels
    """
    labels = pd.Series(index=df.index, dtype='object')
    
    oversized = pd.to_numeric(df.get('oversized_detected', 0), errors='coerce').fillna(0)
    flood = pd.to_numeric(df.get('flood_detected', 0), errors='coerce').fillna(0)
    icmp_rate = pd.to_numeric(df.get('icmp_rate', 0), errors='coerce').fillna(0)
    
    # Default to flood
    labels[:] = 'icmp_flood'
    
    # Ping of death (oversized packets)
    labels[oversized == 1] = 'icmp_ping_of_death'
    
    return labels


def get_all_labels() -> list:
    """Return list of all possible label classes."""
    return [
        # SSH
        'ssh_normal', 'ssh_brute_force', 'ssh_reconnaissance',
        # PortScan
        'portscan_stealth', 'portscan_aggressive', 'portscan_sweep',
        # DNS
        'dns_normal', 'dns_tunneling', 'dns_amplification',
        # ARP
        'arp_spoofing', 'arp_poisoning',
        # ICMP
        'icmp_flood', 'icmp_ping_of_death'
    ]
