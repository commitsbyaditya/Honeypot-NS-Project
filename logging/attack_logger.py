"""
attack_logger.py - Multi-Attack Session Logging Module
=======================================================

Purpose:
    This module provides a unified logger that records attack sessions from
    multiple honeypot types (SSH, PortScan, DNS, ARP, ICMP) into a single
    structured CSV file with attack-type-specific columns.

Why Unified Logging for Multi-Attack Detection:
    Instead of separate CSV files per attack type, we use ONE file with:
      • Common fields: timestamp, ip_address, mac_address, attack_type
      • Type-specific fields: Populated only for relevant attack types
      • Null values: Attack-type-specific fields are empty for other types
    
    Benefits:
      1. CROSS-ATTACK CORRELATION — ML models can detect coordinated attacks
         (e.g., port scan followed by SSH brute-force from same IP)
      
      2. SIMPLIFIED PIPELINE — Single CSV means one data loading function
         for training, dashboard, and analysis
      
      3. TEMPORAL ORDERING — All attacks sorted by timestamp regardless
         of type, enabling timeline analysis
      
      4. FEATURE ENGINEERING — Can compute cross-type features like
         "same IP seen in multiple attack types"

Unified CSV Schema (32 columns):
    Common: timestamp, ip_address, mac_address, attack_type, session_duration, packet_count
    SSH: login_attempts, successful_login, commands_sent, command_types
    PortScan: ports_scanned, scan_type, scan_speed, stealth_detected, syn_count
    DNS: dns_query, dns_query_type, query_rate, tunneling_detected, amplification_detected
    ARP: arp_op_type, gratuitous_arp, ip_conflict, mac_conflict, arp_reply_rate
    ICMP: icmp_type, icmp_code, packet_size, icmp_rate, flood_detected, oversized_detected

Libraries Used:
    - pandas : DataFrame operations and CSV I/O
    - os     : File/directory operations
    - models.session_models : Dataclass definitions for each attack type

Design Notes:
    • Thread-safe: Each write opens, appends one row, closes (no shared handles)
    • Backward compatible: Existing SSH logs can be migrated by adding attack_type column
    • Type validation: Uses dataclasses to enforce correct field types
    • Null handling: Type-specific fields default to empty string or NaN for non-applicable types
"""

import os
import sys
import pandas as pd
from typing import Union

# Import session models for type validation
# Add parent directory to path to import from models/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.session_models import (
    SSHSession, 
    PortScanSession, 
    DNSSession, 
    ARPSession, 
    ICMPSession,
    get_csv_columns
)


# ═══════════════════════════════════════════════════════════════════════════
# UNIFIED COLUMN SCHEMA (32 columns for all attack types)
# ═══════════════════════════════════════════════════════════════════════════
# This schema supports all 5 attack types in a single CSV.
# Fields are populated based on attack_type; others remain null.
LOG_COLUMNS = get_csv_columns()


# ═══════════════════════════════════════════════════════════════════════════
# PATH TO THE CSV LOG FILE
# ═══════════════════════════════════════════════════════════════════════════
# We resolve the path relative to THIS file so that the logger works no
# matter which directory the caller's working directory happens to be.
#
#   ai_honeypot/
#   ├── logging/attack_logger.py   ← we are HERE
#   └── data/attack_logs.csv       ← target file
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_LOG_PATH = os.path.join(_CURRENT_DIR, "..", "data", "attack_logs.csv")


class AttackLogger:
    """
    Unified logger for multi-attack honeypot system.
    
    Supports logging sessions from 5 attack types:
      - SSH password/brute-force attacks
      - Port scanning
      - DNS attacks (tunneling, amplification)
      - ARP spoofing/poisoning
      - ICMP attacks (flood, ping of death)

    Usage from honeypot modules:
    
        from logging.attack_logger import AttackLogger
        from models.session_models import SSHSession, PortScanSession
        
        logger = AttackLogger()
        
        # Log SSH attack
        ssh_session = SSHSession(
            ip_address="192.168.1.105",
            login_attempts=3,
            session_duration=42.7,
            commands_sent=5,
            command_types=3,
            successful_login=1
        )
        logger.log_session(ssh_session)
        
        # Log port scan
        scan_session = PortScanSession(
            ip_address="10.0.0.50",
            ports_scanned="22,80,443",
            scan_type="stealth",
            scan_speed=5.2,
            stealth_detected=1,
            syn_count=150,
            session_duration=28.9,
            packet_count=150
        )
        logger.log_session(scan_session)

    Thread-safe: Each call opens file, appends row, closes (no shared handle).

    Attributes:
        log_file (str): Absolute path to the unified CSV file.
    """

    def __init__(self, log_file: str = _DEFAULT_LOG_PATH):
        """
        Initialize the logger.

        If the CSV file does not exist yet, this constructor creates it
        with the correct header row.  This guarantees that:
          • The honeypot server can start logging from the very first run.
          • pandas.read_csv() will always find valid headers.

        Args:
            log_file: Path to the CSV file.
                      Defaults to  ../data/attack_logs.csv  relative to
                      this module.
        """
        self.log_file = os.path.abspath(log_file)
        self._ensure_csv_exists()

    # ───────────────────────────────────────────────────────────────────
    #  INTERNAL: create the CSV with headers if it doesn't exist
    # ───────────────────────────────────────────────────────────────────
    def _ensure_csv_exists(self):
        """
        Check whether the CSV file exists.  If not, create it with the
        column header row.

        We also create any missing parent directories (e.g. the data/
        folder) so the caller never has to worry about directory setup.
        """
        # os.makedirs with exist_ok=True is safe to call even if the
        # directory already exists — it simply does nothing in that case.
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        if not os.path.exists(self.log_file):
            # Create an empty DataFrame with our predefined columns and
            # write it to CSV.  This produces a file that contains ONLY
            # the header row — no data rows yet.
            empty_df = pd.DataFrame(columns=LOG_COLUMNS)
            empty_df.to_csv(self.log_file, index=False)
            print(f"[Logger] Created new log file: {self.log_file}")

    # ───────────────────────────────────────────────────────────────────
    #  PUBLIC: record one attack session (NEW UNIFIED METHOD)
    # ───────────────────────────────────────────────────────────────────
    def log_session(
        self, 
        session: Union[SSHSession, PortScanSession, DNSSession, ARPSession, ICMPSession]
    ):
        """
        Append a single attack session record to the unified CSV file.
        
        This method accepts any session dataclass (SSHSession, PortScanSession, etc.)
        and converts it to a CSV row with proper null handling for type-specific fields.
        
        Args:
            session: Instance of SSHSession, PortScanSession, DNSSession, 
                     ARPSession, or ICMPSession dataclass
        """
        # Convert session dataclass to dictionary
        session_dict = session.to_dict()
        
        # Create a row with all columns (initialize with empty strings)
        row_data = {col: "" for col in LOG_COLUMNS}
        
        # Populate with session data (only fills relevant fields)
        row_data.update(session_dict)
        
        # Build one-row DataFrame
        new_row = pd.DataFrame([row_data], columns=LOG_COLUMNS)
        
        # Append to CSV
        new_row.to_csv(self.log_file, mode="a", header=False, index=False)
        
        print(
            f"[Logger] Recorded {session.attack_type} session: {session.ip_address}  "
            f"duration={session.session_duration:.2f}s"
        )
    
    # ───────────────────────────────────────────────────────────────────
    #  LEGACY: SSH-only log method (backward compatibility)
    # ───────────────────────────────────────────────────────────────────
    def log_attack(
        self,
        ip_address: str,
        login_attempts: int,
        session_duration: float,
        commands_sent: int,
        command_types: int,
        successful_login: int,
        timestamp: str,
    ):
        """
        LEGACY METHOD for backward compatibility with existing SSH honeypot.
        
        This wraps the old SSH logging interface into the new unified system.
        New code should use log_session() with SSHSession objects instead.
        
        Args:
            ip_address       (str)  : Attacker's source IP
            login_attempts   (int)  : Number of login tries
            session_duration (float): Session length in seconds
            commands_sent    (int)  : Number of shell commands
            command_types    (int)  : Count of recon commands
            successful_login (int)  : 1 if shell reached, else 0
            timestamp        (str)  : Session start time
        """
        # Create SSH session object and use new unified method
        ssh_session = SSHSession(
            ip_address=ip_address,
            login_attempts=login_attempts,
            session_duration=session_duration,
            commands_sent=commands_sent,
            command_types=command_types,
            successful_login=successful_login,
            timestamp=timestamp
        )
        self.log_session(ssh_session)

    # ───────────────────────────────────────────────────────────────────
    #  PUBLIC: load the full log as a DataFrame
    # ───────────────────────────────────────────────────────────────────
    def get_all_logs(self) -> pd.DataFrame:
        """
        Read the entire CSV file and return it as a pandas DataFrame.

        This is useful for:
                    • The ML training pipeline (train_model_multi.py) which needs all
            historical sessions for feature extraction.
          • The Streamlit dashboard which displays metrics and charts.

        Returns:
            pd.DataFrame with columns defined by LOG_COLUMNS.
            Returns an empty DataFrame (with correct columns) if the
            file has headers but no data rows.
        """
        try:
            df = pd.read_csv(self.log_file)
            return df
        except pd.errors.EmptyDataError:
            # The file exists but is completely empty (no header even)
            return pd.DataFrame(columns=LOG_COLUMNS)

    # ───────────────────────────────────────────────────────────────────
    #  PUBLIC: quick count of logged sessions
    # ───────────────────────────────────────────────────────────────────
    def get_log_count(self) -> int:
        """
        Return the total number of attack sessions recorded so far.

        Useful for the dashboard's summary metrics and for deciding
        whether there is enough data to retrain the ML model.
        """
        return len(self.get_all_logs())
