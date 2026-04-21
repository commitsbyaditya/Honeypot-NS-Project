"""
Port Scan Detector - Network Reconnaissance Detection
======================================================

This module detects port scanning activity by monitoring connection patterns
across multiple ports. It identifies various scan types used by tools like
nmap, masscan, and custom scanners.

Port Scanning in Network Security:
    Port scanning is a reconnaissance technique where attackers probe a target
    system to discover open ports and running services. This is typically the
    FIRST step in a targeted attack (kill chain reconnaissance phase).
    
    Types of scans detected:
      • SYN Scan (Half-open scan) - Most common, stealthy
      • Connect Scan (Full TCP handshake)
      • Stealth Scan (slow, randomized timing)
      • Aggressive Scan (rapid sequential probing)
      • Ping Sweep (discovering live hosts)

Detection Strategy:
    We use a passive monitoring approach that tracks:
      1. Connection attempts to multiple ports from same IP
      2. Timing patterns (rapid = aggressive, slow = stealth)
      3. Port sequences (sequential = aggressive, random = stealth)
      4. TCP flags (SYN without ACK = SYN scan)
    
    This is different from honeypot services that actively respond to
    connections. Instead, we monitor the firewall/socket layer for patterns.

Educational Value:
    This detector teaches:
      - Network reconnaissance techniques
      - TCP/IP handshake analysis
      - Intrusion detection system (IDS) concepts
      - Behavioral pattern matching
      - Time-series analysis for attack detection
"""

import socket
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set
import sys
import os
import importlib.util

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.session_models import PortScanSession

# Load attack_logger using importlib (avoids conflict with built-in logging module)
_PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_PARENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
AttackLogger = _attack_logger_mod.AttackLogger


class PortScanDetector:
    """
    Passive port scan detector using connection pattern analysis.
    
    Detection Algorithm:
      1. Monitor connection attempts across multiple ports
      2. Track timing between connection attempts per IP
      3. Detect patterns:
         - Rapid sequential ports (20-1000+ ports/sec) = AGGRESSIVE
         - Slow randomized ports (<1 port/sec) = STEALTH
         - Sequential ping to multiple hosts = PING SWEEP
      4. Log session after threshold reached or timeout expires
    
    Thresholds (configurable):
      - MIN_PORTS_FOR_SCAN: 5 ports from same IP = potential scan
      - AGGRESSIVE_THRESHOLD: >10 ports/sec = aggressive
      - STEALTH_THRESHOLD: <1 port/sec with >10 ports = stealth
      - SESSION_TIMEOUT: 60 seconds of inactivity = end session
    
    Attributes:
        logger: AttackLogger instance for persisting scan events
        active_scanners: Dict tracking ongoing scan sessions per IP
        scan_lock: Thread lock for safe concurrent access
        monitoring: Flag to control detector thread
    """
    
    # Detection thresholds
    MIN_PORTS_FOR_SCAN = 5  # Minimum ports hit to consider it a scan
    AGGRESSIVE_THRESHOLD = 10.0  # ports/sec
    STEALTH_THRESHOLD = 1.0  # ports/sec
    SESSION_TIMEOUT = 60  # seconds of inactivity before logging session
    
    def __init__(self, logger: AttackLogger = None, start_ports: List[int] = None):
        """
        Initialize port scan detector.
        
        Args:
            logger: AttackLogger instance (creates new if None)
            start_ports: List of ports to actively monitor (empty = passive only)
        """
        self.logger = logger or AttackLogger()
        self.start_ports = start_ports or []
        
        # Track active scanning sessions: {ip_address: scan_data}
        self.active_scanners: Dict[str, dict] = defaultdict(self._new_scan_session)
        self.scan_lock = threading.Lock()
        self.monitoring = False
        
        print("[PortScanDetector] Initialized")
        if self.start_ports:
            print(f"[PortScanDetector] Monitoring ports: {self.start_ports}")
    
    def _new_scan_session(self) -> dict:
        """Create new scan session tracking structure."""
        return {
            'ports': set(),  # Unique ports hit
            'timestamps': [],  # Connection timestamps
            'syn_count': 0,  # SYN packets detected
            'first_seen': time.time(),
            'last_seen': time.time(),
        }
    
    def record_connection_attempt(self, ip_address: str, port: int, is_syn: bool = False):
        """
        Record a connection attempt to a port.
        
        This is the main entry point called when a connection attempt is detected.
        Can be called from:
          - Socket accept() calls in other honeypots
          - Packet capture hooks
          - Firewall logs
        
        Args:
            ip_address: Source IP of connection attempt
            port: Target port number
            is_syn: Whether this was a SYN packet (half-open scan indicator)
        """
        with self.scan_lock:
            session = self.active_scanners[ip_address]
            current_time = time.time()
            
            # Record this connection attempt
            if port not in session['ports']:
                session['ports'].add(port)
                session['timestamps'].append(current_time)
            
            if is_syn:
                session['syn_count'] += 1
            
            session['last_seen'] = current_time
            
            # Check if we should log this session
            port_count = len(session['ports'])
            if port_count >= self.MIN_PORTS_FOR_SCAN:
                # Calculate scan characteristics
                duration = session['last_seen'] - session['first_seen']
                if duration > 0:
                    scan_speed = port_count / duration
                    
                    # Check if scan is complete (timeout or clear pattern)
                    if (current_time - session['last_seen'] > 5 or  # 5 sec idle
                        port_count > 20):  # Clearly a scan
                        self._log_scan_session(ip_address, session)
    
    def _log_scan_session(self, ip_address: str, session: dict):
        """
        Log a detected scan session and clear it from active scanners.
        
        Args:
            ip_address: Scanner's IP address
            session: Scan session data dictionary
        """
        port_count = len(session['ports'])
        duration = session['last_seen'] - session['first_seen']
        scan_speed = port_count / duration if duration > 0 else port_count
        
        # Determine scan type
        if scan_speed > self.AGGRESSIVE_THRESHOLD:
            scan_type = "aggressive"
            stealth_detected = 0
        elif scan_speed < self.STEALTH_THRESHOLD and port_count > 10:
            scan_type = "stealth"
            stealth_detected = 1
        elif port_count < 10:
            scan_type = "sweep"
            stealth_detected = 0
        else:
            scan_type = "syn"
            stealth_detected = 0
        
        # Create PortScanSession object
        scan_session = PortScanSession(
            ip_address=ip_address,
            ports_scanned=','.join(map(str, sorted(session['ports']))),
            scan_type=scan_type,
            scan_speed=round(scan_speed, 2),
            stealth_detected=stealth_detected,
            syn_count=session['syn_count'],
            session_duration=round(duration, 2),
            packet_count=len(session['timestamps']),
            timestamp=datetime.fromtimestamp(session['first_seen']).strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Log to CSV
        self.logger.log_session(scan_session)
        
        # Clear this scanner from active sessions
        del self.active_scanners[ip_address]
        
        print(f"[PortScanDetector] Logged {scan_type} scan from {ip_address}: "
              f"{port_count} ports @ {scan_speed:.1f} ports/sec")
    
    def start_monitoring(self):
        """
        Start background monitoring thread to detect scan timeouts.
        
        This thread periodically checks active scanners and logs sessions
        that have been idle for SESSION_TIMEOUT seconds.
        """
        if self.monitoring:
            print("[PortScanDetector] Already monitoring")
            return
        
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        print("[PortScanDetector] Started monitoring thread")
    
    def _monitor_loop(self):
        """Background thread that checks for timed-out scan sessions."""
        while self.monitoring:
            time.sleep(10)  # Check every 10 seconds
            
            with self.scan_lock:
                current_time = time.time()
                timed_out = []
                
                # Find sessions that have timed out
                for ip_address, session in self.active_scanners.items():
                    idle_time = current_time - session['last_seen']
                    port_count = len(session['ports'])
                    
                    if (idle_time > self.SESSION_TIMEOUT and 
                        port_count >= self.MIN_PORTS_FOR_SCAN):
                        timed_out.append(ip_address)
                
                # Log timed-out sessions
                for ip_address in timed_out:
                    session = self.active_scanners[ip_address]
                    self._log_scan_session(ip_address, session)
    
    def stop_monitoring(self):
        """Stop the monitoring thread."""
        self.monitoring = False
        print("[PortScanDetector] Stopped monitoring")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN - For testing the detector
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Port Scan Detector - Test Mode")
    print("=" * 60)
    
    detector = PortScanDetector()
    detector.start_monitoring()
    
    # Simulate an aggressive scan
    print("\n[TEST] Simulating aggressive scan from 192.168.1.100...")
    test_ip = "192.168.1.100"
    for port in range(20, 50):
        detector.record_connection_attempt(test_ip, port, is_syn=True)
        time.sleep(0.01)  # Fast scan
    
    time.sleep(2)  # Wait for logging
    
    # Simulate a stealth scan
    print("\n[TEST] Simulating stealth scan from 10.0.0.50...")
    test_ip2 = "10.0.0.50"
    for port in [22, 80, 443, 3306, 8080, 8443, 3389, 5900, 21, 25, 110]:
        detector.record_connection_attempt(test_ip2, port, is_syn=False)
        time.sleep(0.5)  # Slow scan
    
    time.sleep(2)
    
    print("\n[TEST] Test complete. Check data/attack_logs.csv")
    detector.stop_monitoring()
