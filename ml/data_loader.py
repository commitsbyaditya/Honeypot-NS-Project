"""
Data Loader - Unified CSV Loading for Multi-Attack Honeypot
============================================================

Handles mixed format CSV files where old SSH logs (7 columns) and 
new multi-attack logs (31+ columns) coexist.

Used by:
  - ml/train_model_multi.py
  - dashboard/dashboard_multi.py
"""

import os
import pandas as pd
from io import StringIO


def load_mixed_csv(data_path: str, verbose: bool = True) -> pd.DataFrame:
    """
    Load attack log data from CSV, handling mixed formats.
    
    Detects and processes:
      - Old format (7 columns): ip_address,login_attempts,session_duration,...
      - New format (31+ columns): timestamp,src_ip,dst_ip,attack_type,...
    
    Args:
        data_path: Path to CSV file
        verbose: Print loading info (default True)
    
    Returns:
        DataFrame with attack session data in unified format
    
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is empty
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found: {data_path}")
    
    # Read file line by line to handle mixed formats
    old_format_rows = []
    new_format_rows = []
    old_header = None
    new_header = None
    
    with open(data_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    if not lines:
        raise ValueError("Dataset is empty")
    
    # First line is the header - detect format
    first_line = lines[0].strip()
    first_cols = first_line.split(',')
    
    # Old format has 7 columns starting with 'ip_address'
    # New format has 31+ columns starting with 'timestamp'
    if first_cols[0] == 'ip_address':
        old_header = first_line
        start_idx = 1
    elif first_cols[0] == 'timestamp':
        new_header = first_line
        start_idx = 1
    else:
        start_idx = 0
    
    for line in lines[start_idx:]:
        line = line.strip()
        if not line:
            continue
        
        cols = line.split(',')
        num_cols = len(cols)
        
        # Old format: 7 columns (ip doesn't start with year like '202')
        # New format: 31+ columns (timestamp starts with year)
        if num_cols == 7 and not cols[0].startswith('202'):
            old_format_rows.append(line)
        elif num_cols >= 20:
            new_format_rows.append(line)
    
    dfs = []
    
    # Process old format data
    if old_format_rows:
        if old_header is None:
            old_header = "ip_address,login_attempts,session_duration,commands_sent,command_types,successful_login,timestamp"
        
        old_csv = old_header + '\n' + '\n'.join(old_format_rows)
        df_old = pd.read_csv(StringIO(old_csv))
        
        # Convert old format to unified format
        df_old_unified = pd.DataFrame({
            'timestamp': df_old['timestamp'],
            'src_ip': df_old['ip_address'],
            'dst_ip': '',
            'attack_type': 'ssh',
            'session_duration': df_old['session_duration'],
            'attack_label': '',
            'login_attempts': df_old['login_attempts'],
            'successful_login': df_old['successful_login'],
            'commands_sent': df_old['commands_sent'],
            'command_types': df_old['command_types'],
            # Fill missing columns with defaults
            'packet_count': 0,
            'scan_speed': 0.0,
            'stealth_detected': 0,
            'syn_count': 0,
            'query_rate': 0.0,
            'tunneling_detected': 0,
            'amplification_detected': 0,
            'arp_reply_rate': 0.0,
            'gratuitous_arp': 0,
            'ip_conflict': 0,
            'mac_conflict': 0,
            'icmp_rate': 0.0,
            'flood_detected': 0,
            'oversized_detected': 0,
            'packet_size': 0
        })
        dfs.append(df_old_unified)
        if verbose:
            print(f"[OK] Loaded {len(df_old_unified)} sessions (legacy SSH format)")
    
    # Process new format data
    if new_format_rows:
        if new_header is None:
            try:
                from models.session_models import get_csv_columns
                new_header = ','.join(get_csv_columns())
            except ImportError:
                # Fallback header
                new_header = "timestamp,src_ip,dst_ip,attack_type,session_duration,attack_label,login_attempts,successful_login,commands_sent,command_types,ports_scanned,unique_ports,scan_speed,stealth_detected,syn_count,query_count,query_rate,tunneling_detected,amplification_detected,arp_reply_count,arp_reply_rate,gratuitous_arp,ip_conflict,mac_conflict,icmp_count,icmp_rate,flood_detected,oversized_detected,packet_size,packet_count,extra_data"
        
        new_csv = new_header + '\n' + '\n'.join(new_format_rows)
        df_new = pd.read_csv(StringIO(new_csv))
        dfs.append(df_new)
        if verbose:
            print(f"[OK] Loaded {len(df_new)} sessions (multi-attack format)")
    
    if not dfs:
        raise ValueError("No valid data found in CSV file")
    
    # Combine both formats
    df = pd.concat(dfs, ignore_index=True)
    
    if verbose:
        print(f"[OK] Total: {len(df)} attack sessions")
    
    return df


def get_attack_type_stats(df: pd.DataFrame) -> dict:
    """Get attack type distribution statistics."""
    if 'attack_type' not in df.columns:
        return {}
    
    stats = {}
    total = len(df)
    for attack_type, count in df['attack_type'].value_counts().items():
        stats[attack_type] = {
            'count': count,
            'percentage': 100 * count / total if total > 0 else 0
        }
    return stats
