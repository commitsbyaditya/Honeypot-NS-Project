"""
Multi-Attack Classifier - Real-time Attack Type Prediction
============================================================

This module provides real-time attack classification for all 5 attack types.
Enhanced from original attack_classifier.py to support 13 attack classes.

Classes Supported:
  SSH: ssh_normal, ssh_brute_force, ssh_reconnaissance
  PortScan: portscan_stealth, portscan_aggressive, portscan_sweep
  DNS: dns_normal, dns_tunneling, dns_amplification
  ARP: arp_spoofing, arp_poisoning
  ICMP: icmp_flood, icmp_ping_of_death

Usage:
    from ml.attack_classifier_multi import predict_attack, predict_from_session
    
    # Predict from raw features
    label = predict_attack(attack_type='ssh', login_attempts=25, ...)
    
    # Predict from session object
    from models.session_models import SSHSession
    session = SSHSession(...)
    label = predict_from_session(session)
"""

import os
import sys
import joblib
import pandas as pd
from typing import Union, Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ml.feature_extractors import get_feature_columns


# ═══════════════════════════════════════════════════════════════════════════
# PATH CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_CURRENT_DIR, "..", "models", "attack_model.pkl")
LABEL_ENCODER_PATH = os.path.join(_CURRENT_DIR, "..", "models", "label_encoder.pkl")


# ═══════════════════════════════════════════════════════════════════════════
# MODEL LOADING (lazy initialization)
# ═══════════════════════════════════════════════════════════════════════════
_model = None
_label_encoder = None
_is_loaded = False


def _load_model():
    """Load the trained model and label encoder."""
    global _model, _label_encoder, _is_loaded
    
    if _is_loaded:
        return
    
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(LABEL_ENCODER_PATH):
            _model = joblib.load(MODEL_PATH)
            _label_encoder = joblib.load(LABEL_ENCODER_PATH)
            _is_loaded = True
            print("[Classifier] Multi-attack model loaded successfully.")
            print(f"             Classes: {list(_label_encoder.classes_)}")
        else:
            print("[Classifier] WARNING: Model files not found.")
            print("             Run: python ml/train_model_multi.py")
    except Exception as e:
        print(f"[Classifier] ERROR loading model: {e}")


def _build_feature_vector(**kwargs) -> pd.DataFrame:
    """
    Build a feature vector DataFrame from keyword arguments.
    
    Args:
        **kwargs: Feature values (session_duration, login_attempts, etc.)
    
    Returns:
        DataFrame with one row, columns matching training features
    """
    feature_columns = get_feature_columns()
    
    # Initialize with zeros
    features = {col: 0 for col in feature_columns}
    
    # Update with provided values
    for key, value in kwargs.items():
        if key in features:
            features[key] = value if value is not None else 0
    
    return pd.DataFrame([features], columns=feature_columns)


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

def predict_attack(
    attack_type: str = 'ssh',
    session_duration: float = 0,
    packet_count: int = 0,
    # SSH features
    login_attempts: int = 0,
    successful_login: int = 0,
    commands_sent: int = 0,
    command_types: int = 0,
    # PortScan features
    scan_speed: float = 0,
    stealth_detected: int = 0,
    syn_count: int = 0,
    port_count: int = 0,
    # DNS features
    query_rate: float = 0,
    tunneling_detected: int = 0,
    amplification_detected: int = 0,
    # ARP features
    arp_reply_rate: float = 0,
    gratuitous_arp: int = 0,
    ip_conflict: int = 0,
    mac_conflict: int = 0,
    # ICMP features
    icmp_rate: float = 0,
    flood_detected: int = 0,
    oversized_detected: int = 0,
    packet_size: int = 0,
) -> str:
    """
    Predict attack type from session features.
    
    Args:
        attack_type: Type of attack (ssh, portscan, dns, arp, icmp)
        ... (all feature parameters)
    
    Returns:
        Predicted attack label (e.g., 'ssh_brute_force', 'dns_tunneling')
    """
    _load_model()
    
    if not _is_loaded:
        return "Unknown"
    
    try:
        # Build feature vector
        features = _build_feature_vector(
            session_duration=session_duration,
            packet_count=packet_count,
            login_attempts=login_attempts,
            successful_login=successful_login,
            commands_sent=commands_sent,
            command_types=command_types,
            scan_speed=scan_speed,
            stealth_detected=stealth_detected,
            syn_count=syn_count,
            port_count=port_count,
            query_rate=query_rate,
            tunneling_detected=tunneling_detected,
            amplification_detected=amplification_detected,
            arp_reply_rate=arp_reply_rate,
            gratuitous_arp=gratuitous_arp,
            ip_conflict=ip_conflict,
            mac_conflict=mac_conflict,
            icmp_rate=icmp_rate,
            flood_detected=flood_detected,
            oversized_detected=oversized_detected,
            packet_size=packet_size,
        )
        
        # Predict
        prediction = _model.predict(features)
        label = _label_encoder.inverse_transform(prediction)[0]
        
        return label
    
    except Exception as e:
        print(f"[Classifier] Prediction error: {e}")
        return "Unknown"


def predict_from_session(session) -> str:
    """
    Predict attack type from a session object.
    
    Args:
        session: SSHSession, PortScanSession, DNSSession, ARPSession, or ICMPSession
    
    Returns:
        Predicted attack label
    """
    session_dict = session.to_dict()
    attack_type = session.attack_type
    
    # Calculate port_count if ports_scanned exists
    if 'ports_scanned' in session_dict:
        ports = session_dict.get('ports_scanned', '')
        session_dict['port_count'] = len(ports.split(',')) if ports else 0
    
    return predict_attack(attack_type=attack_type, **session_dict)


def get_attack_category(label: str) -> str:
    """
    Get the high-level attack category from a specific label.
    
    Args:
        label: Specific label (e.g., 'ssh_brute_force')
    
    Returns:
        Category (e.g., 'SSH Attack')
    """
    categories = {
        'ssh_normal': 'Normal Activity',
        'ssh_brute_force': 'SSH Attack',
        'ssh_reconnaissance': 'SSH Attack',
        'portscan_stealth': 'Port Scanning',
        'portscan_aggressive': 'Port Scanning',
        'portscan_sweep': 'Port Scanning',
        'dns_normal': 'Normal Activity',
        'dns_tunneling': 'DNS Attack',
        'dns_amplification': 'DNS Attack',
        'arp_spoofing': 'ARP Attack',
        'arp_poisoning': 'ARP Attack',
        'icmp_flood': 'ICMP Attack',
        'icmp_ping_of_death': 'ICMP Attack',
    }
    return categories.get(label, 'Unknown')


def get_severity(label: str) -> str:
    """
    Get severity level for an attack label.
    
    Args:
        label: Attack label
    
    Returns:
        Severity (Low, Medium, High, Critical)
    """
    severity_map = {
        'ssh_normal': 'Low',
        'ssh_brute_force': 'High',
        'ssh_reconnaissance': 'Medium',
        'portscan_stealth': 'Medium',
        'portscan_aggressive': 'High',
        'portscan_sweep': 'Low',
        'dns_normal': 'Low',
        'dns_tunneling': 'Critical',
        'dns_amplification': 'High',
        'arp_spoofing': 'High',
        'arp_poisoning': 'Critical',
        'icmp_flood': 'High',
        'icmp_ping_of_death': 'Critical',
    }
    return severity_map.get(label, 'Unknown')


# ═══════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  Multi-Attack Classifier — Self-Test")
    print("=" * 60)
    
    # Test cases for each attack type
    test_cases = [
        # SSH tests
        {"attack_type": "ssh", "login_attempts": 1, "session_duration": 5, "commands_sent": 0},
        {"attack_type": "ssh", "login_attempts": 25, "session_duration": 10, "commands_sent": 0},
        {"attack_type": "ssh", "login_attempts": 3, "session_duration": 60, "commands_sent": 5, "command_types": 4},
        
        # PortScan tests
        {"attack_type": "portscan", "scan_speed": 25, "stealth_detected": 0, "syn_count": 100},
        {"attack_type": "portscan", "scan_speed": 0.5, "stealth_detected": 1, "syn_count": 10},
        
        # DNS tests
        {"attack_type": "dns", "query_rate": 5, "tunneling_detected": 0, "amplification_detected": 0},
        {"attack_type": "dns", "query_rate": 15, "tunneling_detected": 1, "amplification_detected": 0},
        
        # ARP tests
        {"attack_type": "arp", "gratuitous_arp": 1, "mac_conflict": 0},
        {"attack_type": "arp", "gratuitous_arp": 0, "mac_conflict": 1},
        
        # ICMP tests
        {"attack_type": "icmp", "icmp_rate": 100, "flood_detected": 1, "oversized_detected": 0},
        {"attack_type": "icmp", "icmp_rate": 5, "oversized_detected": 1},
    ]
    
    for case in test_cases:
        result = predict_attack(**case)
        severity = get_severity(result)
        print(f"  {case['attack_type']:8s} | {result:25s} | Severity: {severity}")
    
    print("\nSelf-test complete.")
