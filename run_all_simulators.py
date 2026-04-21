"""
Multi-Attack Simulator Runner
==============================

This script runs all attack simulators in sequence to generate comprehensive
training data for the ML model. Simulates attacks from all 5 attack types.

Usage:
    python run_all_simulators.py [--rounds N] [--quick]
    
    --rounds N    Number of rounds per attack type (default: 3)
    --quick       Quick mode with fewer attacks (1 round)
    --intensive   Intensive mode with more attacks (10 rounds)

Output:
    Generates attack data in data/attack_logs.csv for ML training.

Note:
    - SSH attacks require honeypot server running on port 2222
    - ICMP and ARP require Administrator/root privileges
    - DNS attacks target port 53 (may require elevated privileges)
"""

import sys
import os
import time
import argparse
import random
from datetime import datetime
import subprocess

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ═══════════════════════════════════════════════════════════════════════════
# SHARED IP POOL FOR CROSS-ATTACK CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
def generate_repeat_ip_pool(size=10):
    """
    Generate a pool of IP addresses that will be reused across different
    attack types to create cross-attack correlation in the data.
    
    Args:
        size: Number of IPs in the repeat pool
    
    Returns:
        list: List of IP addresses
    """
    pool = []
    for _ in range(size):
        choice = random.random()
        if choice < 0.5:
            # Cloud/VPS ranges (common for multi-vector attacks)
            first = random.choice([3, 13, 34, 52, 54, 104, 107])
            ip = f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        elif choice < 0.8:
            # Suspicious ranges
            first = random.choice([80, 82, 85, 91, 176, 177, 113, 114])
            ip = f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        else:
            # Mixed public ranges
            first = random.choice([45, 51, 103, 121, 185, 190, 192, 198])
            ip = f"{first}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        pool.append(ip)
    return pool


# Save the IP pool to a temp file for simulators to use
REPEAT_IP_POOL = generate_repeat_ip_pool(12)


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
SIMULATORS = {
    "ssh": {
        "name": "SSH Brute Force & Reconnaissance",
        "script": "attack_simulator.py",
        "requires_server": True,
        "requires_admin": False,
        "default_sessions": 30,
    },
    "portscan": {
        "name": "Port Scanning",
        "script": "attack_simulator_portscan.py",
        "requires_server": False,
        "requires_admin": False,
        "default_rounds": 3,
    },
    "dns": {
        "name": "DNS Attacks",
        "script": "attack_simulator_dns.py",
        "requires_server": False,
        "requires_admin": False,
        "default_rounds": 3,
    },
    "icmp": {
        "name": "ICMP Flood & Ping of Death",
        "script": "attack_simulator_icmp.py",
        "requires_server": False,
        "requires_admin": True,
        "default_rounds": 3,
    },
    "arp": {
        "name": "ARP Spoofing",
        "script": "attack_simulator_arp.py",
        "requires_server": False,
        "requires_admin": True,
        "default_rounds": 2,
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
def print_banner():
    """Print startup banner."""
    print("\n" + "="*70)
    print(" MULTI-ATTACK SIMULATOR RUNNER")
    print("="*70)
    print(" Generates training data for all 5 attack types:")
    print("   1. SSH - Brute force and reconnaissance")
    print("   2. Port Scan - Aggressive, stealth, and sweep scans")
    print("   3. DNS - Tunneling and amplification attacks")
    print("   4. ICMP - Ping floods and ping of death")
    print("   5. ARP - Spoofing and poisoning")
    print("="*70 + "\n")


def check_prerequisites():
    """Check if required servers are running and permissions are available."""
    print("[*] Checking prerequisites...")
    
    # Check if SSH honeypot is running (port 2222)
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 2222))
        sock.close()
        if result != 0:
            print("[!] WARNING: SSH honeypot not detected on port 2222")
            print("    SSH simulator will be skipped unless honeypot is running")
            print("    Start it with: python honeypot/honeypot_server.py")
            return False
        else:
            print("[OK] SSH honeypot detected on port 2222")
            return True
    except Exception as e:
        print(f"[!] Could not check SSH honeypot: {e}")
        return False


def check_admin_privileges():
    """Check if running with Administrator/root privileges."""
    import ctypes
    try:
        if os.name == 'nt':  # Windows
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            is_admin = os.geteuid() == 0
        
        if is_admin:
            print("[OK] Running with Administrator/root privileges")
        else:
            print("[!] WARNING: Not running with admin privileges")
            print("    ICMP and ARP simulators will be skipped")
        
        return is_admin
    except:
        return False


def run_simulator(simulator_type: str, rounds: int = 3, quick: bool = False, auto: bool = False):
    """
    Run a specific attack simulator.
    
    Args:
        simulator_type: Type of attack (ssh, portscan, dns, icmp, arp)
        rounds: Number of rounds to run
        quick: Quick mode flag
    
    Returns:
        bool: True if successful, False otherwise
    """
    config = SIMULATORS[simulator_type]
    script_path = os.path.join(os.path.dirname(__file__), config["script"])
    
    if not os.path.exists(script_path):
        print(f"[!] Simulator script not found: {script_path}")
        return False
    
    print("\n" + "="*70)
    print(f" RUNNING: {config['name']}")
    print("="*70)
    
    try:
        # Run the simulator script
        if simulator_type == "ssh":
            # SSH simulator has different interface
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=False
            )
        elif simulator_type in ["portscan", "icmp", "dns", "arp"]:
            # These simulators support rounds parameter and non-interactive mode.
            args = [sys.executable, script_path, "--rounds", str(rounds)]
            if auto:
                args.append("--auto")
            result = subprocess.run(args, capture_output=False)
        else:
            # Fallback for other simulators.
            result = subprocess.run([sys.executable, script_path], capture_output=False)
        
        if result.returncode == 0:
            print(f"\n[OK] {config['name']} completed successfully")
            return True
        else:
            print(f"\n[!] {config['name']} failed with exit code {result.returncode}")
            return False
            
    except KeyboardInterrupt:
        print(f"\n[!] {config['name']} interrupted by user")
        raise
    except Exception as e:
        print(f"\n[!] Error running {config['name']}: {e}")
        return False


def run_all_simulators(rounds: int = 3, quick: bool = False, intensive: bool = False,
                       skip_types: list = None, auto: bool = False):
    """
    Run all attack simulators in sequence.
    
    Args:
        rounds: Number of rounds per attack type
        quick: Quick mode (1 round)
        intensive: Intensive mode (10 rounds)
        skip_types: List of attack types to skip
    
    Returns:
        dict: Summary of execution results
    """
    if quick:
        rounds = 1
    elif intensive:
        rounds = 10
    
    skip_types = skip_types or []
    
    print_banner()
    
    # Check prerequisites
    has_ssh_server = check_prerequisites()
    has_admin = check_admin_privileges()
    
    print(f"\n[*] Configuration:")
    print(f"    Rounds per attack type: {rounds}")
    print(f"    Mode: {'Quick' if quick else 'Intensive' if intensive else 'Normal'}")
    print(f"    Output: data/attack_logs.csv")
    
    if not auto:
        print("\n" + "="*70)
        response = input("Ready to start? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("Aborted by user.")
            return None
    
    # Track results
    results = {}
    start_time = time.time()
    
    # Run simulators in order
    for attack_type, config in SIMULATORS.items():
        if attack_type in skip_types:
            print(f"\n[SKIP] {config['name']} (user requested skip)")
            results[attack_type] = "skipped"
            continue
        
        # Check if requirements are met
        if config["requires_server"] and not has_ssh_server:
            print(f"\n[SKIP] {config['name']} (SSH honeypot not running)")
            results[attack_type] = "skipped_no_server"
            continue
        
        if config["requires_admin"] and not has_admin:
            print(f"\n[SKIP] {config['name']} (requires admin privileges)")
            results[attack_type] = "skipped_no_admin"
            continue
        
        # Run the simulator
        success = run_simulator(attack_type, rounds, quick, auto)
        results[attack_type] = "success" if success else "failed"
        
        # Brief pause between simulators
        if attack_type != list(SIMULATORS.keys())[-1]:  # Not the last one
            print(f"\n[*] Pausing 3 seconds before next simulator...")
            time.sleep(3)
    
    # Print summary
    duration = time.time() - start_time
    print("\n" + "="*70)
    print(" SIMULATION COMPLETE")
    print("="*70)
    print(f" Total duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
    print(f" Results:")
    
    for attack_type, result in results.items():
        status_icon = "OK" if result == "success" else "FAIL" if result == "failed" else "-"
        print(f"   [{status_icon}] {SIMULATORS[attack_type]['name']}: {result}")
    
    print("="*70)
    print(f"\n[*] Training data saved to: data/attack_logs.csv")
    print("[*] Next steps:")
    print("    1. Review data: python -c \"import pandas as pd; print(pd.read_csv('data/attack_logs.csv').tail(20))\"")
    print("    2. Train model: python ml/train_model_multi.py")
    print("    3. View dashboard: streamlit run dashboard/dashboard_multi.py")
    print("\n")
    
    return results


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def main():
    """Main entry point with command-line argument parsing."""
    parser = argparse.ArgumentParser(
        description="Run all attack simulators to generate training data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_all_simulators.py                  # Normal mode (3 rounds)
  python run_all_simulators.py --quick          # Quick mode (1 round)
  python run_all_simulators.py --rounds 5       # Custom rounds
  python run_all_simulators.py --intensive      # Intensive mode (10 rounds)
  python run_all_simulators.py --skip icmp arp  # Skip ICMP and ARP
        """
    )
    
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Number of rounds per attack type (default: 3)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick mode - 1 round per attack type"
    )
    parser.add_argument(
        "--intensive",
        action="store_true",
        help="Intensive mode - 10 rounds per attack type"
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        choices=list(SIMULATORS.keys()),
        default=[],
        help="Skip specific attack types"
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run without interactive prompts"
    )
    
    args = parser.parse_args()
    
    try:
        results = run_all_simulators(
            rounds=args.rounds,
            quick=args.quick,
            intensive=args.intensive,
            skip_types=args.skip,
            auto=args.auto
        )
        
        if results is None:
            sys.exit(1)
        
        # Exit with error code if any simulator failed
        if any(r == "failed" for r in results.values()):
            sys.exit(1)
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
