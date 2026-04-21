"""
Generate Sample Attack Data
============================

Quick script to generate diverse attack data for testing the dashboard
and ML model. Creates attacks from multiple IPs across different times.

Usage:
    python generate_sample_data.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("\n" + "="*70)
print(" GENERATING SAMPLE ATTACK DATA")
print("="*70)
print(" This will create 50-100 attack sessions across all 5 attack types")
print(" with varied IPs and timestamps for testing the dashboard.")
print("="*70 + "\n")

response = input("Continue? (yes/no): ").strip().lower()
if response not in ['yes', 'y']:
    print("Aborted.")
    sys.exit(0)

# Import simulators after confirmation
from attack_simulator_portscan import PortScanSimulator
from attack_simulator_icmp import ICMPSimulator
from attack_simulator_dns import DNSSimulator
import random

# Generate a pool of IPs to reuse for correlation
repeat_ips = [
    "45.142.88.201", "52.89.177.34", "103.214.5.119",
    "176.58.122.90", "185.220.101.45", "198.235.24.142",
    "13.107.21.200", "91.199.119.55", "52.180.44.139",
    "114.35.199.72"
]

print(f"\n[*] Using {len(repeat_ips)} IPs for cross-attack correlation")
print("[*] Generating portscan attacks...")

# Generate port scans (20 attacks)
ps_sim = PortScanSimulator(repeat_ips=repeat_ips)
for i in range(20):
    if i % 5 == 0:
        ps_sim.aggressive_scan(port_range=(1000+i*10, 1050+i*10), count=40)
    elif i % 5 == 1:
        ps_sim.stealth_scan()
    else:
        ps_sim.syn_scan_simulation()

print("[*] Generating ICMP attacks...")

# Generate ICMP attacks (15 attacks) - requires admin
try:
    icmp_sim = ICMPSimulator(repeat_ips=repeat_ips)
    for i in range(15):
        if i % 3 == 0:
            icmp_sim.normal_ping(count=8)
        elif i % 3 == 1:
            icmp_sim.ping_flood(count=100, duration=1.0)
        else:
            icmp_sim.ping_of_death(count=5)
    print("[✓] ICMP attacks generated")
except Exception as e:
    print(f"[!] ICMP generation failed (may need admin): {e}")

print("[*] Generating DNS attacks...")

# Generate DNS attacks (25 attacks)
dns_sim = DNSSimulator(repeat_ips=repeat_ips)
for i in range(25):
    if i % 4 == 0:
        dns_sim.normal_lookups(count=12)
    elif i % 4 == 1:
        dns_sim.dns_tunneling(count=20)
    elif i % 4 == 2:
        dns_sim.amplification_attack(count=30)
    else:
        dns_sim.subdomain_enumeration(count=25)

print("\n" + "="*70)
print(" SAMPLE DATA GENERATION COMPLETE")
print("="*70)
print(f" Generated approximately 60+ attack sessions")
print(f" Data saved to: data/attack_logs.csv")
print(f" Cross-attack correlation: {len(repeat_ips)} IPs used across types")
print("="*70)
print("\nNext steps:")
print("  1. View dashboard: streamlit run dashboard/dashboard_multi.py")
print("  2. Train model: python ml/train_model_multi.py")
print("\n")
