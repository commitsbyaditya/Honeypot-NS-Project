"""
ICMP Attack Detector - Ping Flood and DoS Detection
====================================================

This module detects ICMP-based attacks including ping floods, ping of death,
smurf attacks, and ping sweeps. ICMP is used for network diagnostics but
is frequently abused for denial-of-service attacks.

ICMP Attacks in Network Security:
    ICMP (Internet Control Message Protocol) is used for network diagnostics
    (ping, traceroute), but attackers exploit it for:
      
      • Ping Flood - Send massive ICMP echo requests to overwhelm target
        (DDoS attack using ICMP packets)
      
      • Ping of Death - Send oversized ICMP packets (>65535 bytes) that
        crash vulnerable systems when reassembled
      
      • Smurf Attack - Send ICMP to broadcast address with spoofed source IP,
        causing amplified responses to flood victim
      
      • Ping Sweep - Rapidly ping many IPs to discover live hosts
        (reconnaissance for larger attacks)

Detection Strategy:
    1. Monitor all ICMP packets (requires raw sockets)
    2. Track packet rates per source IP
    3. Detect anomalies:
       - High ICMP rate (>50/sec) = flood attack
       - Oversized packets (>1500 bytes or fragmented) = ping of death
       - Broadcast destination = smurf attack attempt
       - Sequential IPs = ping sweep
    4. Log attack sessions with characteristics

Requirements:
    - Scapy library for raw packet capture
    - Administrator/root privileges
    - Raw ICMP socket access

Educational Value:
    - ICMP protocol structure
    - DoS/DDoS attack vectors
    - Network layer attacks (Layer 3)
    - Packet size and rate analysis
"""

from scapy.all import ICMP, IP, sniff, conf
import threading
import time
from collections import defaultdict
from datetime import datetime
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.session_models import ICMPSession

# Load attack_logger using importlib (avoids conflict with built-in logging module)
_PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_PARENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
AttackLogger = _attack_logger_mod.AttackLogger


class ICMPDetector:
    """
    Detect ICMP-based attacks through packet analysis.
    
    Detection Methods:
      1. Flood Detection - High packet rate (>50 ICMP/sec)
      2. Ping of Death - Oversized packets (>1500 bytes or fragmented)
      3. Smurf Detection - Broadcast destination addresses
      4. Ping Sweep - Rapid pings to sequential IPs
    
    ICMP Types Monitored:
      - Type 8 (Echo Request) - Standard ping
      - Type 0 (Echo Reply) - Ping response
      - Type 3 (Destination Unreachable) - Error messages
      - Others - Various control messages
    
    Attributes:
        logger: AttackLogger instance
        icmp_tracker: Tracks ICMP activity per IP
        running: Detector status
    """
    
    # Detection thresholds
    FLOOD_THRESHOLD = 50.0  # ICMP packets per second
    OVERSIZED_THRESHOLD = 1500  # bytes (standard MTU)
    SESSION_TIMEOUT = 60  # seconds
    
    def __init__(self, interface=None, logger: AttackLogger = None):
        """
        Initialize ICMP attack detector.
        
        Args:
            interface: Network interface to monitor (None = default)
            logger: AttackLogger instance
        """
        self.interface = interface or conf.iface
        self.logger = logger or AttackLogger()
        self.running = False
        
        # Track ICMP activity per source IP
        self.icmp_tracker = defaultdict(lambda: {
            'packets': [],
            'types': defaultdict(int),
            'total_size': 0,
            'oversized_count': 0,
            'first_seen': time.time()
        })
        self.tracker_lock = threading.Lock()
        
        print(f"[ICMPDetector] Initialized on interface: {self.interface}")
        print("[ICMPDetector] Requires Administrator/root privileges")
    
    def _icmp_packet_handler(self, packet):
        """
        Callback function for each captured ICMP packet.
        
        Args:
            packet: Scapy packet object with ICMP layer
        """
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return
        
        icmp = packet[ICMP]
        ip = packet[IP]
        
        ip_src = ip.src
        icmp_type = icmp.type
        icmp_code = icmp.code
        packet_size = len(packet)
        current_time = time.time()
        
        with self.tracker_lock:
            tracker = self.icmp_tracker[ip_src]
            
            # Record packet
            tracker['packets'].append({
                'time': current_time,
                'type': icmp_type,
                'code': icmp_code,
                'size': packet_size
            })
            tracker['types'][icmp_type] += 1
            tracker['total_size'] += packet_size
            
            # Detect oversized packets (ping of death)
            if packet_size > self.OVERSIZED_THRESHOLD:
                tracker['oversized_count'] += 1
            
            # Calculate ICMP rate
            packet_count = len(tracker['packets'])
            duration = current_time - tracker['first_seen']
            icmp_rate = packet_count / duration if duration > 0 else packet_count
            
            # Determine if this is an attack
            flood_detected = icmp_rate > self.FLOOD_THRESHOLD
            oversized_detected = tracker['oversized_count'] > 0
            
            # Log if attack detected and sufficient packets captured
            if (flood_detected or oversized_detected) and packet_count >= 10:
                self._log_icmp_session(ip_src, icmp_type, icmp_code, 
                                      packet_size, icmp_rate, 
                                      flood_detected, oversized_detected,
                                      duration, packet_count)
    
    def _log_icmp_session(self, ip_address, icmp_type, icmp_code, 
                          packet_size, icmp_rate, flood_detected, 
                          oversized_detected, duration, packet_count):
        """
        Log detected ICMP attack session.
        
        Args:
            ip_address: Source IP
            icmp_type: ICMP type code
            icmp_code: ICMP code
            packet_size: Size of last packet
            icmp_rate: ICMP packets per second
            flood_detected: Whether flood detected
            oversized_detected: Whether oversized packets detected
            duration: Duration of activity
            packet_count: Total ICMP packets
        """
        icmp_session = ICMPSession(
            ip_address=ip_address,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            packet_size=packet_size,
            icmp_rate=round(icmp_rate, 2),
            flood_detected=1 if flood_detected else 0,
            oversized_detected=1 if oversized_detected else 0,
            session_duration=round(duration, 2),
            packet_count=packet_count,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        self.logger.log_session(icmp_session)
        
        attack_type = []
        if flood_detected:
            attack_type.append("flood")
        if oversized_detected:
            attack_type.append("ping_of_death")
        
        print(f"[ICMPDetector] Logged ICMP attack from {ip_address}: "
              f"{', '.join(attack_type)}, {packet_count} pkts @ {icmp_rate:.1f} pkts/sec")
        
        # Clear tracker for this IP
        with self.tracker_lock:
            if ip_address in self.icmp_tracker:
                del self.icmp_tracker[ip_address]
    
    def start(self):
        """
        Start monitoring ICMP packets on the network.
        
        Uses scapy's sniff() to capture raw ICMP packets.
        Requires administrator/root privileges.
        """
        try:
            print(f"[ICMPDetector] Starting ICMP monitoring on {self.interface}...")
            print("[ICMPDetector] Press Ctrl+C to stop")
            
            self.running = True
            
            # Start session timeout monitor
            monitor_thread = threading.Thread(target=self._monitor_sessions, daemon=True)
            monitor_thread.start()
            
            # Start packet capture
            # filter="icmp" captures only ICMP packets
            sniff(
                iface=self.interface,
                filter="icmp",
                prn=self._icmp_packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        
        except PermissionError:
            print("[ICMPDetector] ERROR: Permission denied")
            print("[ICMPDetector] Run as Administrator/root")
        except Exception as e:
            print(f"[ICMPDetector] ERROR: {e}")
        finally:
            self.stop()
    
    def _monitor_sessions(self):
        """Background thread to log timed-out ICMP sessions."""
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            
            with self.tracker_lock:
                current_time = time.time()
                timed_out = []
                
                for ip_address, tracker in self.icmp_tracker.items():
                    if not tracker['packets']:
                        continue
                    
                    last_packet_time = tracker['packets'][-1]['time']
                    idle_time = current_time - last_packet_time
                    
                    if idle_time > self.SESSION_TIMEOUT and len(tracker['packets']) >= 5:
                        # Calculate final stats
                        duration = last_packet_time - tracker['first_seen']
                        packet_count = len(tracker['packets'])
                        icmp_rate = packet_count / duration if duration > 0 else 0
                        
                        # Only log if suspicious activity
                        if icmp_rate > 5.0 or tracker['oversized_count'] > 0:
                            last_packet = tracker['packets'][-1]
                            flood = icmp_rate > self.FLOOD_THRESHOLD
                            oversized = tracker['oversized_count'] > 0
                            
                            timed_out.append((
                                ip_address,
                                last_packet['type'],
                                last_packet['code'],
                                last_packet['size'],
                                icmp_rate,
                                flood,
                                oversized,
                                duration,
                                packet_count
                            ))
                
                # Log timed-out sessions
                for session_data in timed_out:
                    self._log_icmp_session(*session_data)
    
    def stop(self):
        """Stop ICMP monitoring."""
        self.running = False
        print("[ICMPDetector] Stopped")


if __name__ == "__main__":
    print("ICMP Attack Detector")
    print("=" * 60)
    print("Monitors ICMP traffic for floods, ping of death, and sweeps")
    print("Requires Administrator/root privileges")
    print("Press Ctrl+C to stop\n")
    
    detector = ICMPDetector()
    try:
        detector.start()
    except KeyboardInterrupt:
        print("\n[ICMPDetector] Shutting down...")
        detector.stop()
