"""
attack_simulator.py - Automated Honeypot Traffic Generator
==========================================================

Purpose:
    This script generates realistic, structured attack traffic against the 
    local honeypot server. It connects to port 2222 via TCP sockets and
    behaves exactly like a real client, typing usernames, passwords, and 
    shell commands with human-like delays.

    This allows us to rapidly build a large, balanced dataset (attack_logs.csv) 
    for training the machine learning classifier.

Attacker Profiles:
    1. Normal User (Benign)
       - Low login attempts (1-2)
       - Moderate command count (2-5)
       - Longer session duration (reading output)
    
    2. Brute Force Attacker
       - High login attempts (10-30)
       - Zero commands executed (they never get past the login screen)
       - Very short delays between attempts (automated script)
    
    3. Reconnaissance Attacker
       - Moderate login attempts (2-5)
       - High command count using specific recon commands (ls, pwd, uname, etc.)
       - Medium session duration

Usage:
    Ensure the honeypot is running first:
        python honeypot/honeypot_server.py
    
    Then run the simulator in a separate terminal:
        python attack_simulator.py
"""

import socket
import time
import random

# ═══════════════════════════════════════════════════════════════════════════
# SIMULATOR CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2222

MIN_SESSIONS = 100
MAX_SESSIONS = 200

# Constants matching the honeypot server logic
MAX_SERVER_LOGINS = 3  # The server drops us into the shell after 3 attempts

# Common credentials for brute forcing
USERS = ["root", "admin", "user", "guest", "oracle", "postgres"]
PASSWORDS = ["123456", "password", "admin", "admin123", "root", "toor"]

# Benign / general commands
NORMAL_COMMANDS = ["help", "clear", "echo hello", "date", "uptime", "exit"]

# Reconnaissance commands (matching the server's tracking list)
RECON_COMMANDS = ["ls -la", "pwd", "whoami", "uname -a", "id", "cat /etc/passwd", "netstat -tulpn"]


def connect_and_play(profile: dict):
    """
    Open a TCP socket to the honeypot and execute a scripted session.
    
    Args:
        profile: Dictionary defining connection behavior.
                 {
                     "type": "Brute Force",
                     "logins": 15,
                     "commands": 0,
                     "cmd_pool": [],
                     "delay_range": (0.01, 0.1)
                 }
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        
        # ── Step 1: Consume the fake SSH banner ────────────────────────
        s.recv(1024)
        time.sleep(0.5)

        # ── PHASE 1: Login Attempts ─────────────────────────────────────
        # The honeypot accepts up to MAX_SERVER_LOGINS attempts.
        # If the profile requires more (e.g. 15 for brute force), the 
        # honeypot will abruptly close the connection after 3, which 
        # naturally raises an exception here — correctly simulating an 
        # attacker being dropped.
        for _ in range(profile["logins"]):
            user = random.choice(USERS)
            pwd = random.choice(PASSWORDS)
            
            # The honeypot sends "login: "
            s.recv(1024)
            time.sleep(random.uniform(*profile["delay_range"]))
            s.sendall(f"{user}\n".encode("utf-8"))
            
            # The honeypot sends "Password: "
            s.recv(1024)
            time.sleep(random.uniform(*profile["delay_range"]))
            s.sendall(f"{pwd}\n".encode("utf-8"))
            
            # Wait a moment for the honeypot to process ("Access denied" or success)
            time.sleep(random.uniform(*profile["delay_range"]))

        # ── PHASE 2: Shell Commands ─────────────────────────────────────
        # We only reach here if the honeypot hasn't dropped us.  The server
        # accepted the final login attempt and dropped us into the fake shell.
        if profile["commands"] > 0:
            # Consume the fake welcome banner ("Welcome to Ubuntu...")
            s.recv(1024)
            time.sleep(0.5)

            for _ in range(profile["commands"]):
                cmd = random.choice(profile["cmd_pool"])
                
                # The honeypot sends "root@ubuntu:~# "
                s.recv(1024)
                time.sleep(random.uniform(*profile["delay_range"]))
                
                # Attacker types a command
                s.sendall(f"{cmd}\n".encode("utf-8"))
                
                # Wait for fake output ("command not found")
                time.sleep(random.uniform(*profile["delay_range"]))

        # Clean exit
        s.sendall(b"exit\n")
        
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, ConnectionAbortedError, socket.timeout):
        # We expect connections to drop, especially during brute force attacks
        # where we try 30 logins but the server disconnects after 3.
        pass
    finally:
        s.close()


def main():
    print("=====================================================")
    print("   AI HONEYPOT — AUTOMATED TRAFFIC SIMULATOR")
    print(f"   Target: {TARGET_HOST}:{TARGET_PORT}")
    print("=====================================================")
    
    total_sessions = random.randint(MIN_SESSIONS, MAX_SESSIONS)
    print(f"[*] Planning to generate {total_sessions} sessions...\n")
    
    for i in range(1, total_sessions + 1):
        # Determine which attacker profile to simulate for this session
        rand_val = random.random()
        
        if rand_val < 0.20:
            # 20% Normal User
            # Low logins, low commands, slow typing
            profile = {
                "type": "Normal User",
                "logins": random.randint(1, 2),
                "commands": random.randint(2, 5),
                "cmd_pool": NORMAL_COMMANDS,
                "delay_range": (1.0, 3.0)  # Slow, human-like typing delays
            }
        elif rand_val < 0.60:
            # 40% Brute Force Scanner
            # High logins, zero commands, extremely fast
            profile = {
                "type": "Brute Force",
                "logins": random.randint(10, 30),
                "commands": 0,
                "cmd_pool": [],
                "delay_range": (0.01, 0.05)  # Machine speed
            }
        else:
            # 40% Reconnaissance Attacker
            # Moderate logins, heavy recon commands, medium delay
            profile = {
                "type": "Reconnaissance",
                "logins": random.randint(2, 5),
                "commands": random.randint(6, 12),
                "cmd_pool": RECON_COMMANDS,
                "delay_range": (0.5, 1.5)
            }
            
        print(f"[{i:03d}/{total_sessions}] Simulating {profile['type']:<15} attack...")
        connect_and_play(profile)
        
        # Small delay between entirely distinct attacker sessions
        time.sleep(random.uniform(0.1, 0.5))

    print("\n[+] Simulation complete. Check data/attack_logs.csv for the new dataset.")

if __name__ == "__main__":
    main()
