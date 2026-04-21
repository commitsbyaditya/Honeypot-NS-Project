"""
Port Scan Attack Simulator
===========================

This module simulates various port scanning techniques for testing the
port scan detector. Generates realistic scan patterns similar to nmap,
masscan, and other scanning tools.

Usage:
    python attack_simulator_portscan.py
    
Educational Purpose:
    Demonstrates how different scan types work and their characteristics.
    Used to generate training data for ML model.
"""

import socket
import time
import random
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.session_models import PortScanSession
import importlib.util

# Load attack_logger
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


class PortScanSimulator:
    """
    Simulate different types of port scans.
    
    Scan Types:
      - Aggressive: Rapid sequential port scanning (20-50 ports/sec)
      - Stealth: Slow randomized scanning (<1 port/sec)
      - Sweep: Quick scan of common ports across multiple IPs
    
    Logs all simulated attacks to data/attack_logs.csv for ML training.
    """
    
    def __init__(self, target_host="127.0.0.1", log_file=None, repeat_ips=None):
        """
        Initialize port scan simulator.
        
        Args:
            target_host: Target IP to scan (default localhost for safety)
            log_file: Path to CSV log file (default: project's data/attack_logs.csv)
            repeat_ips: List of IPs to sometimes reuse (for cross-attack correlation)
        """
        self.target_host = target_host
        self.repeat_ips = repeat_ips or []
        if log_file is None:
            log_file = os.path.join(_CURRENT_DIR, "data", "attack_logs.csv")
        self.logger = AttackLogger(log_file)
        print(f"[PortScanSimulator] Target: {target_host}")
        print(f"[PortScanSimulator] Logging to: {log_file}")
    
    def _log_scan(self, scan_type: str, ports: list, duration: float, syn_count: int = 0):
        """Log a simulated scan session to CSV."""
        port_count = len(ports)
        scan_speed = port_count / duration if duration > 0 else port_count
        
        # Determine stealth flag
        stealth_detected = 1 if scan_type == "stealth" else 0
        
        # Generate realistic source IP (sometimes repeat for correlation)
        source_ip = generate_realistic_ip(prefer_repeat=True, repeat_pool=self.repeat_ips)
        
        # Add timestamp variation (spread attacks over time)
        import datetime as dt
        base_time = dt.datetime.now()
        time_offset = random.randint(-3600, 0)  # Up to 1 hour in the past
        timestamp = (base_time + dt.timedelta(seconds=time_offset)).strftime("%Y-%m-%d %H:%M:%S")
        
        session = PortScanSession(
            ip_address=source_ip,
            ports_scanned=','.join(map(str, sorted(ports)[:20])),  # First 20 ports
            scan_type=scan_type,
            scan_speed=round(scan_speed, 2),
            stealth_detected=stealth_detected,
            syn_count=syn_count,
            session_duration=round(duration, 2),
            packet_count=port_count,
            timestamp=timestamp  # Use the varied timestamp
        )
        
        self.logger.log_session(session)
        print(f"[PortScanSimulator] Logged {scan_type} scan from {source_ip}: {port_count} ports @ {scan_speed:.1f} ports/sec")
    
    def aggressive_scan(self, port_range=(20, 100), count=50):
        """
        Simulate aggressive port scan (rapid sequential).
        
        Characteristics:
          - Fast scan rate (20-50 ports/sec)
          - Sequential port order
          - Many connection attempts
        
        Args:
            port_range: Tuple of (start_port, end_port)
            count: Number of ports to scan
        """
        print(f"\n[AGGRESSIVE SCAN] Scanning {count} ports rapidly...")
        start_time = time.time()
        
        ports = list(range(port_range[0], min(port_range[1], port_range[0] + count)))
        scanned_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.target_host, port))
                sock.close()
            except:
                pass  # Port closed or filtered
            
            scanned_ports.append(port)
            time.sleep(0.02)  # 50 ports/sec
        
        duration = time.time() - start_time
        rate = len(scanned_ports) / duration
        print(f"[AGGRESSIVE SCAN] Complete: {len(scanned_ports)} ports in {duration:.2f}s ({rate:.1f} ports/sec)")
        
        # Log this scan
        self._log_scan("aggressive", scanned_ports, duration)
    
    def stealth_scan(self, ports=None, delay_range=(0.5, 2.0)):
        """
        Simulate stealth scan (slow randomized).
        
        Characteristics:
          - Slow scan rate (<1 port/sec)
          - Randomized port order
          - Random delays between probes
        
        Args:
            ports: List of ports to scan (default: common ports)
            delay_range: Tuple of (min_delay, max_delay) in seconds
        """
        if ports is None:
            ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5900, 8080]
        
        print(f"\n[STEALTH SCAN] Scanning {len(ports)} ports slowly...")
        start_time = time.time()
        
        # Randomize port order
        scan_ports = ports.copy()
        random.shuffle(scan_ports)
        scanned_ports = []
        
        for port in scan_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((self.target_host, port))
                sock.close()
            except:
                pass
            
            scanned_ports.append(port)
            # Random delay (stealth technique)
            delay = random.uniform(*delay_range)
            time.sleep(delay)
        
        duration = time.time() - start_time
        rate = len(scanned_ports) / duration
        print(f"[STEALTH SCAN] Complete: {len(scanned_ports)} ports in {duration:.2f}s ({rate:.2f} ports/sec)")
        
        # Log this scan
        self._log_scan("stealth", scanned_ports, duration)
    
    def ping_sweep(self, base_ip="192.168.1", port=80, host_range=(1, 20)):
        """
        Simulate ping sweep (scan same port on multiple hosts).
        
        Characteristics:
          - Single port, many IPs
          - Sequential IP order
          - Fast rate
        
        Args:
            base_ip: Base IP prefix (e.g., "192.168.1")
            port: Port to check on each host
            host_range: Tuple of (start_host, end_host)
        """
        print(f"\n[PING SWEEP] Scanning {base_ip}.{host_range[0]}-{host_range[1]}:{port}...")
        start_time = time.time()
        
        count = 0
        for host in range(host_range[0], host_range[1] + 1):
            target = f"{base_ip}.{host}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                sock.connect((target, port))
                sock.close()
                count += 1
            except:
                pass
            
            time.sleep(0.05)
        
        duration = time.time() - start_time
        print(f"[PING SWEEP] Complete: {host_range[1]-host_range[0]+1} hosts in {duration:.2f}s")
    
    def syn_scan_simulation(self, ports=None):
        """
        Simulate SYN scan characteristics.
        
        Note: This uses connect() which is actually a full TCP handshake,
        but simulates the timing/pattern of SYN scans for detector testing.
        
        Args:
            ports: List of ports (default: top 20 common ports)
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                    445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        print(f"\n[SYN SCAN] Scanning {len(ports)} ports (SYN pattern)...")
        start_time = time.time()
        scanned_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.target_host, port))
                sock.close()
            except:
                pass
            
            scanned_ports.append(port)
            time.sleep(0.01)  # Fast SYN scan
        
        duration = time.time() - start_time
        rate = len(scanned_ports) / duration
        print(f"[SYN SCAN] Complete: {len(scanned_ports)} ports in {duration:.2f}s ({rate:.1f} ports/sec)")
        
        # Log this scan (with SYN count = port count for simulation)
        self._log_scan("syn", scanned_ports, duration, syn_count=len(scanned_ports))


def run_simulation_suite(target="127.0.0.1", rounds=3):
    """
    Run a full suite of port scan simulations.
    
    Args:
        target: Target IP address
        rounds: Number of times to run each scan type
    """
    print("=" * 70)
    print("PORT SCAN ATTACK SIMULATOR")
    print("=" * 70)
    print(f"Target: {target}")
    print(f"Rounds: {rounds} of each scan type")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    simulator = PortScanSimulator(target)
    
    for round_num in range(1, rounds + 1):
        print(f"\n{'='*70}")
        print(f"ROUND {round_num}/{rounds}")
        print(f"{'='*70}")
        
        # Aggressive scan
        simulator.aggressive_scan(port_range=(1000, 1200), count=50)
        time.sleep(2)
        
        # Stealth scan
        simulator.stealth_scan()
        time.sleep(2)
        
        # SYN scan
        simulator.syn_scan_simulation()
        time.sleep(2)
        
        # Ping sweep (only if not localhost)
        if target != "127.0.0.1":
            base_ip = '.'.join(target.split('.')[:3])
            simulator.ping_sweep(base_ip=base_ip, host_range=(1, 10))
            time.sleep(2)
    
    print(f"\n{'='*70}")
    print("SIMULATION COMPLETE")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Check data/attack_logs.csv for logged scans")
    print(f"{'='*70}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Port Scan Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--rounds", type=int, default=3, help="Number of rounds (default: 3)")
    parser.add_argument("--auto", action="store_true", help="Auto-start without prompt")
    
    args = parser.parse_args()
    
    print("\nNOTE: For testing, run the port scan detector in another terminal first:")
    print("  python honeypot/portscan_detector.py")
    print("\nOr integrate with honeypot_manager.py when ready.\n")
    
    if not args.auto:
        input("Press Enter to start simulation...")
    
    run_simulation_suite(target=args.target, rounds=args.rounds)
