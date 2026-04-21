"""
Honeypot Manager - Multi-Attack Orchestration System
=====================================================

This module manages all honeypot services and detectors, running them
concurrently as separate processes with health monitoring.

Features:
  - Launches all 5 attack detection systems
  - Process isolation (one crash doesn't affect others)
  - Health monitoring with auto-restart
  - Graceful shutdown handling
  - Configuration file support

Usage:
    python honeypot_manager.py [--config config.yaml]
    
    Requires: Administrator/root privileges for some detectors
"""

import multiprocessing
import threading
import signal
import time
import socket
import sys
import os
import yaml
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE PROCESS FUNCTIONS (must be module-level for Windows pickling)
# ─────────────────────────────────────────────────────────────────────────────

def _run_ssh_honeypot_process(port):
    """Run SSH honeypot in subprocess (standalone function for pickling)."""
    try:
        from honeypot.honeypot_server import HoneypotServer
        honeypot = HoneypotServer(port=port)
        honeypot.start()
    except Exception as e:
        print(f"[SSH Honeypot] Error: {e}")


def _run_portscan_detector_process():
    """Run port scan detector in subprocess (standalone function for pickling)."""
    try:
        from honeypot.portscan_detector import PortScanDetector
        detector = PortScanDetector()
        detector.start_monitoring()
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"[PortScan Detector] Error: {e}")


def _run_dns_honeypot_process(port):
    """Run DNS honeypot in subprocess (standalone function for pickling)."""
    try:
        from honeypot.dns_honeypot import DNSHoneypot
        honeypot = DNSHoneypot(port=port)
        honeypot.start()
    except Exception as e:
        print(f"[DNS Honeypot] Error: {e}")


def _run_arp_detector_process(interface):
    """Run ARP spoof detector in subprocess (standalone function for pickling)."""
    try:
        from honeypot.arp_spoof_detector import ARPSpoofDetector
        detector = ARPSpoofDetector(interface=interface)
        detector.start()
    except Exception as e:
        print(f"[ARP Detector] Error: {e}")


def _run_icmp_detector_process(interface):
    """Run ICMP detector in subprocess (standalone function for pickling)."""
    try:
        from honeypot.icmp_detector import ICMPDetector
        detector = ICMPDetector(interface=interface)
        detector.start()
    except Exception as e:
        print(f"[ICMP Detector] Error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# HONEYPOT MANAGER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class HoneypotManager:
    """
    Orchestrates all honeypot services and attack detectors.
    
    Architecture:
      - Each detector runs in its own process (multiprocessing)
      - Process isolation prevents cascade failures
      - Health monitor thread checks and restarts failed services
      - Signal handlers for graceful shutdown
    
    Services Managed:
      1. SSH Honeypot (port 2222)
      2. Port Scan Detector (passive)
      3. DNS Honeypot (port 53)
      4. ARP Spoof Detector (raw sockets)
      5. ICMP Detector (raw sockets)
    
    Attributes:
        config: Configuration dictionary from YAML
        processes: Dict of running processes {name: Process}
        running: Manager status flag
    """
    
    def __init__(self, config_path="config.yaml"):
        """
        Initialize honeypot manager.
        
        Args:
            config_path: Path to configuration YAML file
        """
        self.config = self._load_config(config_path)
        self.config_path = config_path
        self.processes = {}
        self.running = False
        self._next_restart_allowed = {}
        self.instance_lock_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'data',
            '.honeypot_manager.lock'
        )
        self._instance_lock_acquired = False
        self.log_file = self.config.get('general', {}).get('log_file', 'data/attack_logs.csv')
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        print("=" * 70)
        print("MULTI-ATTACK HONEYPOT NETWORK SECURITY SYSTEM")
        print("=" * 70)
        print(f"Config: {config_path}")
        print(f"Log file: {os.path.abspath(self.log_file)}")
        print("=" * 70)
    
    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                print(f"[Manager] Loaded config from {config_path}")
                return config
        except FileNotFoundError:
            print(f"[Manager] Config not found: {config_path}, using defaults")
            return self._default_config()
        except Exception as e:
            print(f"[Manager] Error loading config: {e}, using defaults")
            return self._default_config()
    
    def _default_config(self):
        """Return default configuration."""
        return {
            'general': {'log_file': 'data/attack_logs.csv', 'auto_restart': True},
            'network': {'interface': ''},
            'ssh_honeypot': {'enabled': True, 'port': 2222},
            'portscan_detector': {'enabled': True},
            'dns_honeypot': {'enabled': True, 'port': 53},
            'arp_detector': {'enabled': True},
            'icmp_detector': {'enabled': True}
        }
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n[Manager] Received signal {signum}, shutting down...")
        self.stop()

    def _is_process_running(self, pid):
        """Return True if PID exists in the OS process table."""
        if not pid or pid <= 0:
            return False

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    def _acquire_instance_lock(self):
        """Ensure only one honeypot manager instance runs at a time."""
        lock_dir = os.path.dirname(self.instance_lock_path)
        if lock_dir:
            os.makedirs(lock_dir, exist_ok=True)

        if os.path.exists(self.instance_lock_path):
            try:
                with open(self.instance_lock_path, 'r', encoding='utf-8') as f:
                    existing_pid = int(f.read().strip())
            except Exception:
                existing_pid = None

            if existing_pid and self._is_process_running(existing_pid):
                print(f"[Manager] Another honeypot_manager instance is already running (PID: {existing_pid})")
                print("[Manager] Stop the existing instance before starting a new one.")
                return False

            # Stale lock file from a dead process.
            try:
                os.remove(self.instance_lock_path)
            except OSError:
                print("[Manager] Could not remove stale lock file. Exiting for safety.")
                return False

        try:
            with open(self.instance_lock_path, 'w', encoding='utf-8') as f:
                f.write(str(os.getpid()))
            self._instance_lock_acquired = True
            return True
        except OSError as e:
            print(f"[Manager] Failed to create instance lock: {e}")
            return False

    def _release_instance_lock(self):
        """Release manager singleton lock if this process owns it."""
        if not self._instance_lock_acquired:
            return

        try:
            if os.path.exists(self.instance_lock_path):
                with open(self.instance_lock_path, 'r', encoding='utf-8') as f:
                    owner_pid = int(f.read().strip())
                if owner_pid == os.getpid():
                    os.remove(self.instance_lock_path)
        except Exception:
            pass
        finally:
            self._instance_lock_acquired = False
    
    # ─────────────────────────────────────────────────────────────────
    # PROCESS MANAGEMENT
    # ─────────────────────────────────────────────────────────────────
    
    def _is_udp_port_available(self, port):
        """Return True if a UDP port can be bound on all interfaces."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _start_service(self, name, target, args=(), is_restart=False):
        """
        Start a service as a separate process.
        
        Args:
            name: Service name for tracking
            target: Function to run in process
            args: Arguments to pass to target function
        """
        if name in self.processes and self.processes[name].is_alive():
            print(f"[Manager] {name} already running")
            return

        if is_restart:
            now = time.time()
            next_allowed = self._next_restart_allowed.get(name, 0)
            if now < next_allowed:
                return

            if name == 'DNS Honeypot':
                dns_port = args[0] if args else self.config.get('dns_honeypot', {}).get('port', 53)
                if not self._is_udp_port_available(dns_port):
                    cooldown_seconds = 60
                    self._next_restart_allowed[name] = now + cooldown_seconds
                    print(
                        f"[Manager] DNS port {dns_port} is busy. "
                        f"Retrying DNS Honeypot in {cooldown_seconds}s."
                    )
                    return
        
        process = multiprocessing.Process(target=target, args=args, name=name, daemon=True)
        process.start()
        self.processes[name] = process
        print(f"[Manager] Started {name} (PID: {process.pid})")
    
    def _stop_service(self, name):
        """Stop a specific service."""
        if name in self.processes:
            process = self.processes[name]
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
            del self.processes[name]
            print(f"[Manager] Stopped {name}")
    
    def _get_service_configs(self):
        """Get configuration for each service (used for restart)."""
        interface = self.config.get('network', {}).get('interface', None)
        interface = interface if interface else None
        
        return {
            'SSH Honeypot': (_run_ssh_honeypot_process, (self.config.get('ssh_honeypot', {}).get('port', 2222),)),
            'PortScan Detector': (_run_portscan_detector_process, ()),
            'DNS Honeypot': (_run_dns_honeypot_process, (self.config.get('dns_honeypot', {}).get('port', 53),)),
            'ARP Detector': (_run_arp_detector_process, (interface,)),
            'ICMP Detector': (_run_icmp_detector_process, (interface,))
        }
    
    def _health_monitor(self):
        """
        Background thread that monitors service health.
        
        Checks if processes are still alive and restarts them if:
          - Process has died unexpectedly
          - auto_restart is enabled in config
        """
        auto_restart = self.config.get('general', {}).get('auto_restart', True)
        service_configs = self._get_service_configs()
        
        while self.running:
            time.sleep(10)  # Check every 10 seconds
            
            if not auto_restart:
                continue
            
            for name, process in list(self.processes.items()):
                if not process.is_alive():
                    now = time.time()
                    if now < self._next_restart_allowed.get(name, 0):
                        continue

                    print(f"[Manager] {name} died, restarting...")
                    
                    if name in service_configs:
                        target, args = service_configs[name]
                        self._start_service(name, target, args, is_restart=True)
    
    # ─────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────
    
    def start(self):
        """
        Start all enabled honeypot services.
        
        Reads config to determine which services to enable.
        Launches each as a separate process.
        Starts health monitoring thread.
        """
        if not self._acquire_instance_lock():
            return

        self.running = True
        print("\n[Manager] Starting services...")
        print("-" * 70)
        
        service_configs = self._get_service_configs()
        interface = self.config.get('network', {}).get('interface', None)
        interface = interface if interface else None
        
        # Start SSH Honeypot
        if self.config.get('ssh_honeypot', {}).get('enabled', True):
            target, args = service_configs['SSH Honeypot']
            self._start_service('SSH Honeypot', target, args)
        
        # Start Port Scan Detector
        if self.config.get('portscan_detector', {}).get('enabled', True):
            target, args = service_configs['PortScan Detector']
            self._start_service('PortScan Detector', target, args)
        
        # Start DNS Honeypot
        if self.config.get('dns_honeypot', {}).get('enabled', True):
            target, args = service_configs['DNS Honeypot']
            self._start_service('DNS Honeypot', target, args)
        
        # Start ARP Detector
        if self.config.get('arp_detector', {}).get('enabled', True):
            target, args = service_configs['ARP Detector']
            self._start_service('ARP Detector', target, args)
        
        # Start ICMP Detector
        if self.config.get('icmp_detector', {}).get('enabled', True):
            target, args = service_configs['ICMP Detector']
            self._start_service('ICMP Detector', target, args)
        
        print("-" * 70)
        print(f"[Manager] {len(self.processes)} services started")
        print("[Manager] Press Ctrl+C to stop all services")
        print("-" * 70)
        
        # Start health monitor thread
        monitor_thread = threading.Thread(target=self._health_monitor, daemon=True)
        monitor_thread.start()
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
        finally:
            if self.running:
                self.stop()
            else:
                self._release_instance_lock()
    
    def stop(self):
        """Stop all honeypot services gracefully."""
        if not self.running and not self.processes:
            self._release_instance_lock()
            return

        print("\n[Manager] Stopping all services...")
        self.running = False
        
        for name in list(self.processes.keys()):
            self._stop_service(name)
        
        self._release_instance_lock()
        print("[Manager] All services stopped")
        print("=" * 70)
    
    def status(self):
        """Print status of all services."""
        print("\n" + "=" * 70)
        print("SERVICE STATUS")
        print("=" * 70)
        
        for name, process in self.processes.items():
            status = "RUNNING" if process.is_alive() else "STOPPED"
            pid = process.pid if process.is_alive() else "N/A"
            print(f"  {name:20s} | {status:10s} | PID: {pid}")
        
        print("=" * 70)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Multi-Attack Honeypot Network Security System"
    )
    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    parser.add_argument(
        '--status', '-s',
        action='store_true',
        help='Show service status and exit'
    )
    
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print("MULTI-ATTACK HONEYPOT NETWORK SECURITY SYSTEM")
    print("=" * 70)
    print("Educational Network Security Monitoring Platform")
    print("=" * 70)
    print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nNOTE: Some services require Administrator/root privileges:")
    print("  - DNS Honeypot (port 53)")
    print("  - ARP Detector (raw sockets)")
    print("  - ICMP Detector (raw sockets)")
    print("\nWindows: Run as Administrator")
    print("Linux: Use sudo or grant CAP_NET_RAW capability")
    print("=" * 70 + "\n")
    
    manager = HoneypotManager(config_path=args.config)
    
    if args.status:
        manager.status()
    else:
        manager.start()


if __name__ == "__main__":
    main()
