"""
ARP Spoof Detector - Man-in-the-Middle Attack Detection
========================================================

This module detects ARP spoofing and poisoning attacks at Layer 2.
ARP (Address Resolution Protocol) attacks are used for man-in-the-middle
(MITM) attacks on local networks.

ARP Spoofing in Network Security:
    ARP maps IP addresses to MAC addresses on local networks. Attackers
    exploit ARP's lack of authentication to:
      
      • ARP Spoofing - Send fake ARP replies claiming to be another host
        (e.g., attacker claims to be the gateway, intercepts all traffic)
      
      • ARP Poisoning - Corrupt ARP caches of multiple hosts to redirect
        traffic through attacker's machine
      
      • Gratuitous ARP - Unsolicited ARP broadcasts to update caches
        (legitimate for IP changes, but also used in attacks)
      
      • MAC Flooding - Overwhelm switch CAM tables to force hub mode

Detection Strategy:
    1. Monitor all ARP packets on the network (requires promiscuous mode)
    2. Track IP-MAC mappings over time
    3. Detect anomalies:
       - Same IP with multiple different MACs = spoofing
       - Gratuitous ARP broadcasts = potential attack
       - Rapid ARP replies from same MAC = scanning or poisoning
       - IP conflicts (two MACs claim same IP)
    4. Log suspicious ARP activity patterns

Requirements:
    - Scapy library for raw packet capture
    - Administrator/root privileges
    - Network interface in promiscuous mode

Educational Value:
    - Layer 2 protocol vulnerabilities
    - Man-in-the-middle attack vectors
    - Network sniffing and packet analysis
    - ARP cache poisoning prevention
"""

from scapy.all import ARP, sniff, conf
import threading
import time
from collections import defaultdict
from datetime import datetime
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.session_models import ARPSession

# Load attack_logger using importlib (avoids conflict with built-in logging module)
_PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_PARENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
AttackLogger = _attack_logger_mod.AttackLogger


class ARPSpoofDetector:
    """
    Detect ARP spoofing and poisoning attacks using packet analysis.
    
    Detection Methods:
      1. IP-MAC Mapping Conflicts - Track historical mappings, alert on changes
      2. Gratuitous ARP Detection - Unsolicited ARP replies
      3. High ARP Rate - Rapid ARP traffic from single MAC (scanning/flooding)
      4. Duplicate IPs - Multiple MACs claiming same IP
    
    Layer 2 Attack Detection:
      This operates at the data link layer, below IP. We see raw Ethernet
      frames with ARP packets. This is lower-level than other honeypots.
    
    Attributes:
        logger: AttackLogger instance
        ip_mac_map: Historical IP-MAC mappings {ip: mac}
        arp_tracker: Tracks ARP activity per IP {ip: {arp_packets: [], ...}}
        running: Detector status
    """
    
    # Detection thresholds
    HIGH_ARP_RATE = 5.0  # ARP packets per second
    SESSION_TIMEOUT = 60  # seconds
    
    def __init__(self, interface=None, logger: AttackLogger = None):
        """
        Initialize ARP spoof detector.
        
        Args:
            interface: Network interface to monitor (None = default interface)
            logger: AttackLogger instance
        """
        self.interface = interface or conf.iface  # Default interface from scapy
        self.logger = logger or AttackLogger()
        self.running = False
        
        # Track known IP-MAC mappings (learned over time)
        self.ip_mac_map = {}  # {ip_address: mac_address}
        
        # Track ARP activity per IP
        self.arp_tracker = defaultdict(lambda: {
            'arp_packets': [],
            'mac_addresses': set(),
            'gratuitous_count': 0,
            'first_seen': time.time()
        })
        self.tracker_lock = threading.Lock()
        
        print(f"[ARPSpoofDetector] Initialized on interface: {self.interface}")
        print("[ARPSpoofDetector] Requires Administrator/root privileges")
    
    def _arp_packet_handler(self, packet):
        """
        Callback function for each captured ARP packet.
        
        Scapy calls this for every ARP packet seen on the network.
        
        Args:
            packet: Scapy packet object with ARP layer
        """
        if not packet.haslayer(ARP):
            return
        
        arp = packet[ARP]
        ip_src = arp.psrc  # Source IP
        mac_src = arp.hwsrc  # Source MAC
        ip_dst = arp.pdst  # Destination IP
        op = arp.op  # Operation: 1=request, 2=reply
        
        current_time = time.time()
        
        with self.tracker_lock:
            # Detect gratuitous ARP (source IP = destination IP in reply)
            is_gratuitous = (op == 2 and ip_src == ip_dst)
            
            # Check for IP-MAC conflicts (known mapping changed)
            ip_conflict = 0
            mac_conflict = 0
            if ip_src in self.ip_mac_map:
                if self.ip_mac_map[ip_src] != mac_src:
                    mac_conflict = 1  # Same IP now has different MAC!
                    print(f"[ARPSpoofDetector] WARNING: IP-MAC conflict detected!")
                    print(f"  IP {ip_src} changed from {self.ip_mac_map[ip_src]} to {mac_src}")
            else:
                # Learn this mapping
                self.ip_mac_map[ip_src] = mac_src
            
            # Track this ARP packet
            tracker = self.arp_tracker[ip_src]
            tracker['arp_packets'].append({
                'time': current_time,
                'mac': mac_src,
                'op': op,
                'gratuitous': is_gratuitous
            })
            tracker['mac_addresses'].add(mac_src)
            
            if is_gratuitous:
                tracker['gratuitous_count'] += 1
            
            # Check if we have duplicate MAC addresses for this IP
            if len(tracker['mac_addresses']) > 1:
                ip_conflict = 1
            
            # Calculate ARP rate
            packet_count = len(tracker['arp_packets'])
            duration = current_time - tracker['first_seen']
            arp_rate = packet_count / duration if duration > 0 else packet_count
            
            # Log if suspicious activity detected
            if (mac_conflict or 
                is_gratuitous or 
                ip_conflict or 
                arp_rate > self.HIGH_ARP_RATE and packet_count > 10):
                
                self._log_arp_session(ip_src, mac_src, op, is_gratuitous, 
                                     ip_conflict, mac_conflict, arp_rate, 
                                     duration, packet_count)
    
    def _log_arp_session(self, ip_address, mac_address, arp_op, 
                         gratuitous, ip_conflict, mac_conflict, 
                         arp_rate, duration, packet_count):
        """
        Log detected ARP spoofing activity.
        
        Args:
            ip_address: Source IP from ARP
            mac_address: Source MAC from ARP
            arp_op: ARP operation type (1=request, 2=reply)
            gratuitous: Whether gratuitous ARP detected
            ip_conflict: Whether IP conflict detected
            mac_conflict: Whether MAC changed for known IP
            arp_rate: ARP packets per second
            duration: Duration of activity
            packet_count: Total ARP packets observed
        """
        arp_session = ARPSession(
            ip_address=ip_address,
            mac_address=mac_address,
            arp_op_type=arp_op,
            gratuitous_arp=1 if gratuitous else 0,
            ip_conflict=ip_conflict,
            mac_conflict=mac_conflict,
            arp_reply_rate=round(arp_rate, 2),
            session_duration=round(duration, 2),
            packet_count=packet_count,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        self.logger.log_session(arp_session)
        
        attack_type = []
        if gratuitous:
            attack_type.append("gratuitous_arp")
        if ip_conflict:
            attack_type.append("ip_conflict")
        if mac_conflict:
            attack_type.append("mac_conflict")
        if arp_rate > self.HIGH_ARP_RATE:
            attack_type.append("high_rate")
        
        print(f"[ARPSpoofDetector] Logged ARP attack from {ip_address} ({mac_address}): "
              f"{', '.join(attack_type)}, {packet_count} pkts @ {arp_rate:.1f} pkts/sec")
        
        # Clear tracker for this IP
        with self.tracker_lock:
            if ip_address in self.arp_tracker:
                del self.arp_tracker[ip_address]
    
    def start(self):
        """
        Start monitoring ARP packets on the network.
        
        This uses scapy's sniff() function which captures raw packets.
        Requires administrator/root privileges and promiscuous mode.
        """
        try:
            print(f"[ARPSpoofDetector] Starting ARP monitoring on {self.interface}...")
            print("[ARPSpoofDetector] Press Ctrl+C to stop")
            
            self.running = True
            
            # Start session timeout monitor
            monitor_thread = threading.Thread(target=self._monitor_sessions, daemon=True)
            monitor_thread.start()
            
            # Start packet capture (blocking call)
            # filter="arp" captures only ARP packets
            # prn=callback function called for each packet
            # store=0 don't store packets in memory (streaming)
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self._arp_packet_handler,
                store=0,
                stop_filter=lambda x: not self.running
            )
        
        except PermissionError:
            print("[ARPSpoofDetector] ERROR: Permission denied")
            print("[ARPSpoofDetector] Run as Administrator/root")
        except Exception as e:
            print(f"[ARPSpoofDetector] ERROR: {e}")
        finally:
            self.stop()
    
    def _monitor_sessions(self):
        """Background thread to log timed-out ARP sessions."""
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            
            with self.tracker_lock:
                current_time = time.time()
                timed_out = []
                
                for ip_address, tracker in self.arp_tracker.items():
                    if not tracker['arp_packets']:
                        continue
                    
                    last_packet_time = tracker['arp_packets'][-1]['time']
                    idle_time = current_time - last_packet_time
                    
                    if idle_time > self.SESSION_TIMEOUT and len(tracker['arp_packets']) >= 5:
                        # Calculate final stats
                        duration = last_packet_time - tracker['first_seen']
                        packet_count = len(tracker['arp_packets'])
                        arp_rate = packet_count / duration if duration > 0 else 0
                        
                        if arp_rate > 1.0 or tracker['gratuitous_count'] > 0:
                            last_packet = tracker['arp_packets'][-1]
                            timed_out.append((
                                ip_address,
                                last_packet['mac'],
                                last_packet['op'],
                                tracker['gratuitous_count'] > 0,
                                len(tracker['mac_addresses']) > 1,
                                0,
                                arp_rate,
                                duration,
                                packet_count
                            ))
                
                # Log timed-out sessions
                for session_data in timed_out:
                    self._log_arp_session(*session_data)
    
    def stop(self):
        """Stop ARP monitoring."""
        self.running = False
        print("[ARPSpoofDetector] Stopped")


if __name__ == "__main__":
    print("ARP Spoof Detector")
    print("=" * 60)
    print("Monitors ARP traffic for spoofing and poisoning attacks")
    print("Requires Administrator/root privileges")
    print("Press Ctrl+C to stop\n")
    
    detector = ARPSpoofDetector()
    try:
        detector.start()
    except KeyboardInterrupt:
        print("\n[ARPSpoofDetector] Shutting down...")
        detector.stop()
