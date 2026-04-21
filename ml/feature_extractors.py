"""
Multi-Attack Feature Engineering Module
========================================

This module extracts features from attack sessions for ML classification.
Handles all 5 attack types with type-specific feature extraction.

Feature Groups:
  - Common features: session_duration, packet_count
  - SSH features: login_attempts, commands_sent, etc.
  - PortScan features: scan_speed, port_count, etc.
  - DNS features: query_rate, tunneling indicators
  - ARP features: arp_rate, conflict flags
  - ICMP features: icmp_rate, flood/oversized flags
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# FEATURE DEFINITIONS BY ATTACK TYPE
# ═══════════════════════════════════════════════════════════════════════════

# Common features across all attack types
COMMON_FEATURES = ['session_duration', 'packet_count']

# Attack-type-specific features
FEATURE_GROUPS = {
    'ssh': ['login_attempts', 'successful_login', 'commands_sent', 'command_types'],
    'portscan': ['scan_speed', 'stealth_detected', 'syn_count'],
    'dns': ['query_rate', 'tunneling_detected', 'amplification_detected'],
    'arp': ['arp_reply_rate', 'gratuitous_arp', 'ip_conflict', 'mac_conflict'],
    'icmp': ['icmp_rate', 'flood_detected', 'oversized_detected', 'packet_size']
}

# All features for unified model
ALL_FEATURES = COMMON_FEATURES + [
    # SSH
    'login_attempts', 'successful_login', 'commands_sent', 'command_types',
    # PortScan
    'scan_speed', 'stealth_detected', 'syn_count',
    # DNS
    'query_rate', 'tunneling_detected', 'amplification_detected',
    # ARP
    'arp_reply_rate', 'gratuitous_arp', 'ip_conflict', 'mac_conflict',
    # ICMP
    'icmp_rate', 'flood_detected', 'oversized_detected', 'packet_size'
]


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract ML features from raw attack log data.
    
    Handles missing values (fills with 0 for numeric, appropriate defaults).
    Converts string columns to numeric where needed.
    
    Args:
        df: Raw DataFrame from attack_logs.csv
    
    Returns:
        DataFrame with numeric features only, ready for ML
    """
    features = pd.DataFrame()
    
    # Common features
    features['session_duration'] = pd.to_numeric(df['session_duration'], errors='coerce').fillna(0)
    features['packet_count'] = pd.to_numeric(df.get('packet_count', 0), errors='coerce').fillna(0)
    
    # SSH features
    features['login_attempts'] = pd.to_numeric(df.get('login_attempts', 0), errors='coerce').fillna(0)
    features['successful_login'] = pd.to_numeric(df.get('successful_login', 0), errors='coerce').fillna(0)
    features['commands_sent'] = pd.to_numeric(df.get('commands_sent', 0), errors='coerce').fillna(0)
    features['command_types'] = pd.to_numeric(df.get('command_types', 0), errors='coerce').fillna(0)
    
    # PortScan features
    features['scan_speed'] = pd.to_numeric(df.get('scan_speed', 0), errors='coerce').fillna(0)
    features['stealth_detected'] = pd.to_numeric(df.get('stealth_detected', 0), errors='coerce').fillna(0)
    features['syn_count'] = pd.to_numeric(df.get('syn_count', 0), errors='coerce').fillna(0)
    
    # Calculate port_count from ports_scanned if available
    if 'ports_scanned' in df.columns:
        features['port_count'] = df['ports_scanned'].apply(
            lambda x: len(str(x).split(',')) if pd.notna(x) and str(x).strip() else 0
        )
    else:
        features['port_count'] = 0
    
    # DNS features
    features['query_rate'] = pd.to_numeric(df.get('query_rate', 0), errors='coerce').fillna(0)
    features['tunneling_detected'] = pd.to_numeric(df.get('tunneling_detected', 0), errors='coerce').fillna(0)
    features['amplification_detected'] = pd.to_numeric(df.get('amplification_detected', 0), errors='coerce').fillna(0)
    
    # ARP features
    features['arp_reply_rate'] = pd.to_numeric(df.get('arp_reply_rate', 0), errors='coerce').fillna(0)
    features['gratuitous_arp'] = pd.to_numeric(df.get('gratuitous_arp', 0), errors='coerce').fillna(0)
    features['ip_conflict'] = pd.to_numeric(df.get('ip_conflict', 0), errors='coerce').fillna(0)
    features['mac_conflict'] = pd.to_numeric(df.get('mac_conflict', 0), errors='coerce').fillna(0)
    
    # ICMP features
    features['icmp_rate'] = pd.to_numeric(df.get('icmp_rate', 0), errors='coerce').fillna(0)
    features['flood_detected'] = pd.to_numeric(df.get('flood_detected', 0), errors='coerce').fillna(0)
    features['oversized_detected'] = pd.to_numeric(df.get('oversized_detected', 0), errors='coerce').fillna(0)
    features['packet_size'] = pd.to_numeric(df.get('packet_size', 0), errors='coerce').fillna(0)
    
    return features


def get_feature_columns() -> List[str]:
    """Return list of all feature column names in expected order."""
    return [
        'session_duration', 'packet_count',
        'login_attempts', 'successful_login', 'commands_sent', 'command_types',
        'scan_speed', 'stealth_detected', 'syn_count', 'port_count',
        'query_rate', 'tunneling_detected', 'amplification_detected',
        'arp_reply_rate', 'gratuitous_arp', 'ip_conflict', 'mac_conflict',
        'icmp_rate', 'flood_detected', 'oversized_detected', 'packet_size'
    ]
