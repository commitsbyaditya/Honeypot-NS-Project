"""
DNS Honeypot - Fake DNS Resolver
=================================

This module implements a fake DNS server that responds to DNS queries
and detects malicious DNS activity including tunneling, amplification
attacks, and subdomain enumeration.

DNS Attacks in Network Security:
    DNS is a critical network protocol that attackers abuse in various ways:
      
      • DNS Tunneling - Exfiltrating data through DNS queries/responses
        (e.g., encoding data in subdomains: "aGVsbG8.evil.com")
      
      • DNS Amplification - DDoS technique where attackers send small queries
        to DNS servers that generate large responses to a victim IP
      
      • Subdomain Enumeration - Rapidly querying subdomains to map network
        (e.g., admin.example.com, vpn.example.com, etc.)
      
      • Cache Poisoning - Injecting false DNS records (we detect attempts)

Detection Strategy:
    1. Parse incoming DNS queries (UDP port 53)
    2. Respond with fake A/AAAA records (act like real DNS server)
    3. Analyze query patterns:
       - Long subdomain names (>50 chars) = potential tunneling
       - High query rate (>10/sec) = enumeration or amplification
       - Unusual record types (TXT, NULL, ANY) = suspicious
       - Repeated queries from same IP = enumeration
    4. Log suspicious sessions

Educational Value:
    - DNS protocol structure and parsing
    - Application-layer attack detection
    - Data exfiltration techniques
    - DDoS amplification vectors
"""

import socket
import struct
import threading
import time
from collections import defaultdict
from datetime import datetime
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.session_models import DNSSession

# Load attack_logger using importlib (avoids conflict with built-in logging module)
_PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_PARENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
AttackLogger = _attack_logger_mod.AttackLogger


class DNSHoneypot:
    """
    Fake DNS server that detects malicious DNS activity.
    
    Protocol: UDP on port 53 (requires admin/root privileges)
    
    Detection Features:
      - DNS Tunneling: Long subdomain names, unusual encodings
      - Amplification: ANY queries, large response requests
      - Enumeration: Rapid subdomain queries from same IP
      - Suspicious types: TXT, NULL records (often used in attacks)
    
    DNS Packet Format (simplified):
      Header: Transaction ID, Flags, Question count, Answer count
      Question: Domain name, Query type (A, AAAA, TXT, ANY, etc.)
      Answer: We respond with fake IP addresses
    
    Attributes:
        port: DNS listening port (default 53)
        logger: AttackLogger instance
        running: Server status flag
        query_tracker: Tracks queries per IP for pattern detection
    """
    
    # Detection thresholds
    TUNNELING_SUBDOMAIN_LENGTH = 50  # chars
    HIGH_QUERY_RATE = 10.0  # queries per second
    AMPLIFICATION_TYPES = ['ANY', 'TXT', 'NULL']
    
    def __init__(self, port=53, logger: AttackLogger = None):
        """
        Initialize DNS honeypot.
        
        Args:
            port: DNS port to listen on (default 53, requires admin)
            logger: AttackLogger instance
        """
        self.port = port
        self.logger = logger or AttackLogger()
        self.running = False
        self.sock = None
        
        # Track queries per IP: {ip: {queries: [], first_seen: time}}
        self.query_tracker = defaultdict(lambda: {'queries': [], 'first_seen': time.time()})
        self.tracker_lock = threading.Lock()
        
        print(f"[DNSHoneypot] Initialized on port {port}")
        print("[DNSHoneypot] Note: Requires administrator/root privileges for port 53")
    
    def _parse_dns_query(self, data: bytes) -> dict:
        """
        Parse DNS query packet and extract key information.
        
        Simplified DNS parsing - extracts transaction ID, domain name,
        and query type. Real DNS parsing is more complex.
        
        Args:
            data: Raw DNS query packet bytes
        
        Returns:
            dict with 'transaction_id', 'domain', 'query_type'
        """
        try:
            # DNS Header: 12 bytes
            # Transaction ID (2 bytes), Flags (2), Questions (2), etc.
            transaction_id = struct.unpack('>H', data[0:2])[0]
            
            # Extract domain name from question section (after 12 byte header)
            # Domain is encoded as length-prefixed labels
            domain_parts = []
            i = 12
            while i < len(data) and data[i] != 0:
                length = data[i]
                if length == 0:
                    break
                i += 1
                domain_parts.append(data[i:i+length].decode('utf-8', errors='ignore'))
                i += length
            
            domain = '.'.join(domain_parts) if domain_parts else "unknown.domain"
            
            # Query type is after the null terminator (2 bytes)
            i += 1  # Skip null terminator
            if i + 2 <= len(data):
                query_type_code = struct.unpack('>H', data[i:i+2])[0]
                query_type = {
                    1: 'A', 5: 'CNAME', 15: 'MX', 16: 'TXT',
                    28: 'AAAA', 255: 'ANY', 10: 'NULL'
                }.get(query_type_code, f'TYPE{query_type_code}')
            else:
                query_type = 'A'
            
            return {
                'transaction_id': transaction_id,
                'domain': domain,
                'query_type': query_type
            }
        except Exception as e:
            print(f"[DNSHoneypot] Parse error: {e}")
            return {'transaction_id': 0, 'domain': 'parse.error', 'query_type': 'A'}
    
    def _build_dns_response(self, transaction_id: int, domain: str) -> bytes:
        """
        Build a fake DNS response packet with a fake IP address.
        
        Response format (simplified):
          - Header: Transaction ID, Response flags, 1 answer
          - Question: Echo the original question
          - Answer: Fake A record pointing to 127.0.0.1
        
        Args:
            transaction_id: From original query
            domain: Domain name from query
        
        Returns:
            DNS response packet bytes
        """
        # DNS Header for response
        # Transaction ID (2 bytes)
        header = struct.pack('>H', transaction_id)
        # Flags: 0x8180 = Standard query response, no error
        header += struct.pack('>H', 0x8180)
        # Question count: 1, Answer count: 1, Authority: 0, Additional: 0
        header += struct.pack('>HHHH', 1, 1, 0, 0)
        
        # Question section (echo original)
        question = b''
        for part in domain.split('.'):
            question += bytes([len(part)]) + part.encode('utf-8')
        question += b'\x00'  # Null terminator
        question += struct.pack('>HH', 1, 1)  # Type A, Class IN
        
        # Answer section (fake A record)
        answer = b'\xc0\x0c'  # Pointer to domain name in question
        answer += struct.pack('>HH', 1, 1)  # Type A, Class IN
        answer += struct.pack('>I', 300)  # TTL: 300 seconds
        answer += struct.pack('>H', 4)  # Data length: 4 bytes (IPv4)
        answer += socket.inet_aton('127.0.0.1')  # Fake IP address
        
        return header + question + answer
    
    def _detect_attack_patterns(self, ip_address: str, domain: str, query_type: str) -> dict:
        """
        Analyze query for attack patterns.
        
        Args:
            ip_address: Source IP
            domain: Queried domain
            query_type: DNS query type
        
        Returns:
            dict with detection flags
        """
        with self.tracker_lock:
            tracker = self.query_tracker[ip_address]
            tracker['queries'].append({
                'domain': domain,
                'type': query_type,
                'time': time.time()
            })
            
            # Calculate query rate
            query_count = len(tracker['queries'])
            duration = time.time() - tracker['first_seen']
            query_rate = query_count / duration if duration > 0 else query_count
            
            # Detect tunneling (long subdomain = data encoding)
            tunneling_detected = 1 if len(domain) > self.TUNNELING_SUBDOMAIN_LENGTH else 0
            
            # Detect amplification (ANY queries, etc.)
            amplification_detected = 1 if query_type in self.AMPLIFICATION_TYPES else 0
            
            return {
                'query_rate': query_rate,
                'tunneling_detected': tunneling_detected,
                'amplification_detected': amplification_detected,
                'query_count': query_count,
                'duration': duration
            }
    
    def _should_log_session(self, ip_address: str) -> bool:
        """
        Determine if we should log this IP's DNS session.
        
        Criteria:
          - High query rate (>10/sec)
          - Tunneling detected
          - Amplification detected
          - Or 20+ queries total
        """
        tracker = self.query_tracker[ip_address]
        if not tracker['queries']:
            return False
        
        last_query = tracker['queries'][-1]
        duration = time.time() - tracker['first_seen']
        query_rate = len(tracker['queries']) / duration if duration > 0 else 0
        
        # Check if any query triggered alerts
        tunneling = any(len(q['domain']) > self.TUNNELING_SUBDOMAIN_LENGTH 
                       for q in tracker['queries'])
        amplification = any(q['type'] in self.AMPLIFICATION_TYPES 
                           for q in tracker['queries'])
        
        return (query_rate > self.HIGH_QUERY_RATE or 
                tunneling or 
                amplification or 
                len(tracker['queries']) >= 20)
    
    def _log_dns_session(self, ip_address: str):
        """Log DNS session for an IP address."""
        with self.tracker_lock:
            tracker = self.query_tracker[ip_address]
            if not tracker['queries']:
                return
            
            duration = time.time() - tracker['first_seen']
            query_count = len(tracker['queries'])
            query_rate = query_count / duration if duration > 0 else query_count
            
            # Get most recent query details
            last_query = tracker['queries'][-1]
            
            # Aggregate detection flags
            tunneling = any(len(q['domain']) > self.TUNNELING_SUBDOMAIN_LENGTH 
                           for q in tracker['queries'])
            amplification = any(q['type'] in self.AMPLIFICATION_TYPES 
                               for q in tracker['queries'])
            
            # Create session object
            dns_session = DNSSession(
                ip_address=ip_address,
                dns_query=last_query['domain'],
                dns_query_type=last_query['type'],
                query_rate=round(query_rate, 2),
                tunneling_detected=1 if tunneling else 0,
                amplification_detected=1 if amplification else 0,
                session_duration=round(duration, 2),
                packet_count=query_count,
                timestamp=datetime.fromtimestamp(tracker['first_seen']).strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self.logger.log_session(dns_session)
            print(f"[DNSHoneypot] Logged DNS session from {ip_address}: "
                  f"{query_count} queries @ {query_rate:.1f} q/s, "
                  f"tunneling={tunneling}, amplification={amplification}")
            
            # Clear tracker
            del self.query_tracker[ip_address]
    
    def start(self):
        """Start the DNS honeypot server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', self.port))
            self.running = True
            
            print(f"[DNSHoneypot] Listening on 0.0.0.0:{self.port}")
            
            # Start session timeout monitor
            monitor_thread = threading.Thread(target=self._monitor_sessions, daemon=True)
            monitor_thread.start()
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(512)  # DNS queries are usually <512 bytes
                    ip_address = addr[0]
                    
                    # Parse query
                    query_info = self._parse_dns_query(data)
                    domain = query_info['domain']
                    query_type = query_info['query_type']
                    
                    print(f"[DNSHoneypot] Query from {ip_address}: {domain} ({query_type})")
                    
                    # Detect attack patterns
                    detection = self._detect_attack_patterns(ip_address, domain, query_type)
                    
                    # Send fake response
                    response = self._build_dns_response(query_info['transaction_id'], domain)
                    self.sock.sendto(response, addr)
                    
                    # Check if we should log this session
                    if self._should_log_session(ip_address):
                        self._log_dns_session(ip_address)
                
                except Exception as e:
                    if self.running:
                        print(f"[DNSHoneypot] Error handling query: {e}")
        
        except PermissionError:
            print(f"[DNSHoneypot] ERROR: Permission denied for port {self.port}")
            print("[DNSHoneypot] Run as Administrator/root or use port >1024")
        except Exception as e:
            print(f"[DNSHoneypot] ERROR: {e}")
        finally:
            self.stop()
    
    def _monitor_sessions(self):
        """Background thread to log timed-out sessions."""
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            
            with self.tracker_lock:
                current_time = time.time()
                timed_out = []
                
                for ip_address, tracker in self.query_tracker.items():
                    if not tracker['queries']:
                        continue
                    
                    idle_time = current_time - tracker['queries'][-1]['time']
                    if idle_time > 60 and len(tracker['queries']) >= 5:
                        timed_out.append(ip_address)
                
                # Log timed-out sessions
                for ip_address in timed_out:
                    self._log_dns_session(ip_address)
    
    def stop(self):
        """Stop the DNS honeypot server."""
        self.running = False
        if self.sock:
            self.sock.close()
        print("[DNSHoneypot] Stopped")


if __name__ == "__main__":
    print("DNS Honeypot Server")
    print("=" * 60)
    print("Note: This requires Administrator/root privileges for port 53")
    print("Press Ctrl+C to stop\n")
    
    honeypot = DNSHoneypot(port=53)
    try:
        honeypot.start()
    except KeyboardInterrupt:
        print("\n[DNSHoneypot] Shutting down...")
        honeypot.stop()
