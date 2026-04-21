"""
honeypot_server.py - Fake SSH Login Honeypot Server
=====================================================

Purpose:
    This module implements a deceptive SSH-like honeypot server. It does NOT
    run a real SSH daemon — instead it opens a raw TCP socket on port 2222
    and speaks plain text that *looks* like an SSH login prompt to anyone
    who connects (e.g. via PuTTY, netcat, or a bot scanner).

    The goal is to:
      • Lure attackers into thinking they found a real SSH service.
      • Record every username / password combination they try.
      • Measure how long they stay connected and how many commands they type
        after the fake "login".
      • Feed all captured data into the attack_logger module so it ends up
        in data/attack_logs.csv for ML training and dashboard display.

How TCP Sockets Work (crash-course in comments):
    1. socket()   — Create an endpoint for communication.  We use AF_INET
                     (IPv4) and SOCK_STREAM (TCP, i.e. reliable, ordered,
                     connection-oriented byte stream).
    2. bind()     — Attach our socket to an address (host, port).
    3. listen()   — Tell the OS we want to accept incoming connections.
                     The argument is the *backlog* — how many pending
                     connections can queue before the OS starts refusing.
    4. accept()   — Block until a client connects.  Returns a NEW socket
                     object dedicated to that one client, plus the client's
                     (ip, port) tuple.
    5. recv/send  — Read from / write to the client socket.  Data travels
                     as raw bytes, so we .encode() strings before sending
                     and .decode() bytes after receiving.
    6. close()    — Tear down the connection and free the file descriptor.

    Because accept() is blocking, we spawn a new thread for every client
    so the main loop can keep accepting new connections concurrently.

Libraries Used:
    - socket    : Low-level TCP networking (create, bind, listen, accept).
    - threading : One thread per client so multiple attackers are handled
                  simultaneously without blocking each other.
    - time      : Measure session duration (start vs. end timestamps).
    - datetime  : Human-readable timestamps for the CSV log.
    - importlib : Load attack_logger from the 'logging/' directory without
                  shadowing Python's built-in logging module.

Note:
    This is a SIMULATED honeypot for educational / demonstration purposes.
    Do NOT expose it to the public internet without proper network controls.
"""

import socket
import threading
import time
from datetime import datetime
import sys
import os
import importlib.util

# ═══════════════════════════════════════════════════════════════════════════
# IMPORT ATTACK LOGGER
# ═══════════════════════════════════════════════════════════════════════════
# Our project has a folder called "logging/" which clashes with Python's
# built-in "logging" module.  To avoid the conflict we load attack_logger.py
# by its absolute file path using importlib rather than a normal import.
# ═══════════════════════════════════════════════════════════════════════════
_PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _PARENT_DIR)

_logger_spec = importlib.util.spec_from_file_location(
    "attack_logger",
    os.path.join(_PARENT_DIR, "logging", "attack_logger.py"),
)
_attack_logger_mod = importlib.util.module_from_spec(_logger_spec)
_logger_spec.loader.exec_module(_attack_logger_mod)
AttackLogger = _attack_logger_mod.AttackLogger

# Import the multi-attack ML classifier for real-time labeling
from ml.attack_classifier_multi import predict_attack


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
HOST = "0.0.0.0"           # Bind to ALL network interfaces (IPv4)
PORT = 2222                # Fake SSH port (real SSH uses 22)
MAX_LOGIN_ATTEMPTS = 3     # How many username/password tries before "locking"
MAX_COMMANDS = 10          # Max fake shell commands we'll accept per session
RECV_TIMEOUT = 60          # Seconds to wait for client input before timeout
RECV_BUFFER = 4096         # Max bytes to read in a single recv() call

# ── Reconnaissance commands ────────────────────────────────────────────────
# These are common Linux commands an attacker types during the
# reconnaissance phase to learn about the system.  We count how many
# of these appear in a session because a high count is a strong
# indicator of a deliberate, human-driven intrusion (as opposed to a
# dumb brute-force bot that never reaches the shell).
RECON_COMMANDS = {
    "ls", "dir", "pwd", "whoami", "id", "uname", "hostname",
    "ifconfig", "ip", "netstat", "ss", "ps", "cat", "head",
    "tail", "find", "grep", "env", "export", "echo", "df",
    "mount", "w", "who", "last", "history",
}

# ── Fake banners & prompts ────────────────────────────────────────────────
# These strings are crafted to look like a real OpenSSH server.
#
# WHY ASCII INSTEAD OF UNICODE:
#   Windows Telnet and many raw TCP clients do not render Unicode box-drawing
#   characters (═, ║, ╔, ╗, etc.) correctly.  They show up as garbled
#   question-marks or mojibake, which immediately reveals the server is fake.
#   Using plain ASCII characters (=, -, |) ensures the banner looks clean
#   and realistic in ANY terminal — PuTTY, Telnet, netcat, or a bot scanner.
SSH_BANNER = (
    "\r\n"
    "============================================\r\n"
    "  Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0)\r\n"
    "  OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
    "============================================\r\n"
    "\r\n"
)
LOGIN_PROMPT = "login: "
PASSWORD_PROMPT = "Password: "
AUTH_FAIL_MSG = "\r\nAccess denied.\r\n\r\n"
LOCKOUT_MSG = (
    "\r\n*** Too many failed attempts. Connection terminated. ***\r\n"
)
SHELL_PROMPT = "root@ubuntu:~# "
SHELL_WELCOME = (
    "\r\nWelcome to Ubuntu 22.04.3 LTS\r\n"
    "Last login: Mon Mar  9 14:22:07 2026 from 10.0.0.1\r\n\r\n"
)
# Keep fake responses ASCII-only for the same reason as the banner
FAKE_RESPONSE = (
    "\r\n-bash: {cmd}: command not found\r\n"
)


class HoneypotServer:
    """
    Fake SSH honeypot that captures attacker credentials and behaviour.

    For every client connection the server:
      1. Sends a realistic-looking SSH banner.
      2. Prompts for username + password up to MAX_LOGIN_ATTEMPTS times.
      3. On the final attempt, pretends the login succeeded and drops the
         attacker into a fake shell (this encourages them to type more
         commands, giving us richer data).
      4. Records a summary of the session — IP, login attempts, duration,
         commands entered — via AttackLogger.

    Attributes:
        host (str)       : Network interface to bind to.
        port (int)       : TCP port to listen on.
        logger           : AttackLogger instance for CSV persistence.
        classifier       : AttackClassifier for real-time payload labelling.
        server_socket    : The listening TCP socket.
    """

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.logger = AttackLogger()

        # ── Create the TCP socket ──────────────────────────────────────
        # AF_INET   = IPv4 address family
        # SOCK_STREAM = TCP (connection-oriented, reliable, ordered bytes)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # SO_REUSEADDR lets us restart the server immediately after a crash
        # without waiting for the OS TIME_WAIT period to expire on the port.
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # ───────────────────────────────────────────────────────────────────
    #  HELPER: safely send a string to the client
    # ───────────────────────────────────────────────────────────────────
    @staticmethod
    def _send(client: socket.socket, text: str):
        """
        Encode a string to UTF-8 and send it over the socket.

        Sockets only understand raw bytes, so we must .encode() every
        Python string before sending.  If the connection is already dead
        a BrokenPipeError will be raised and caught by the caller.
        """
        client.sendall(text.encode("utf-8"))

    # ───────────────────────────────────────────────────────────────────
    #  HELPER: receive one FULL LINE of text from the client
    # ───────────────────────────────────────────────────────────────────
    @staticmethod
    def receive_line(client: socket.socket) -> str | None:
        """
        Read from the socket until a newline character is received,
        then return the complete line as a stripped string.

        WHY LINE-BUFFERING IS NECESSARY:
        ─────────────────────────────────
        TCP is a STREAM protocol — it delivers a continuous flow of bytes
        with NO inherent message boundaries.  A single recv() call may
        return:
          • Just 1 byte     (Telnet sends each keystroke individually)
          • A partial line   (network split the data mid-word)
          • Multiple lines   (fast client sent everything at once)

        If we treat a single recv() as a "complete input", we process
        whatever fragment arrived first — often a single character — and
        the honeypot acts on incomplete data.

        The fix: keep calling recv() and ACCUMULATING bytes in a buffer
        until we see '\\n' (the Enter key).  Only then do we treat the
        buffer content as one complete user input.

        Returns:
            str  — the full line the user typed (whitespace stripped).
            None — if the client disconnected (recv returned b'').
        """
        buffer = b""   # Accumulate raw bytes here

        try:
            while True:
                # recv(1024) reads UP TO 1024 bytes that are currently
                # available.  It may return fewer — even just 1 byte —
                # depending on network conditions and client behaviour.
                chunk = client.recv(1024)

                if not chunk:
                    # recv() returned empty bytes → the remote end has
                    # closed the TCP connection (sent a FIN packet).
                    # If we already have partial data, return it;
                    # otherwise signal disconnect with None.
                    if buffer:
                        return buffer.decode("utf-8", errors="replace").strip()
                    return None

                # Append the new bytes to our running buffer
                buffer += chunk

                # Check whether the buffer now contains a newline.
                # The newline means the user pressed Enter, so the
                # input line is complete and we can stop reading.
                if b"\n" in buffer:
                    # Take everything up to (and including) the first \n.
                    # Any bytes AFTER the \n are discarded — in a real
                    # honeypot you could save them for the next read,
                    # but for our use-case one line at a time is enough.
                    line = buffer.split(b"\n", 1)[0]
                    return line.decode("utf-8", errors="replace").strip()

        except (socket.timeout, ConnectionResetError, OSError):
            # Timeout or broken connection — return whatever we have
            if buffer:
                return buffer.decode("utf-8", errors="replace").strip()
            return None

    # ───────────────────────────────────────────────────────────────────
    #  PHASE 1: Fake login prompt (captures credentials)
    # ───────────────────────────────────────────────────────────────────
    def _run_login_phase(self, client: socket.socket) -> tuple:
        """
        Present username/password prompts and collect every attempt.

        The honeypot NEVER truly authenticates — it rejects the first
        (MAX_LOGIN_ATTEMPTS - 1) attempts with "Access denied" and then
        *pretends* the last attempt succeeded.  This maximises the number
        of credential pairs we capture, and the fake success lures the
        attacker into typing post-login commands.

        Returns:
            (login_attempts, credentials_list)
            where credentials_list = [(username, password), ...]
        """
        credentials = []

        for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
            # ── Ask for username ───────────────────────────────────────
            self._send(client, LOGIN_PROMPT)
            username = self.receive_line(client)
            if username is None:
                # Client disconnected mid-login
                break

            # ── Ask for password ───────────────────────────────────────
            self._send(client, PASSWORD_PROMPT)
            password = self.receive_line(client)
            if password is None:
                break

            credentials.append((username, password))

            if attempt < MAX_LOGIN_ATTEMPTS:
                # Reject early attempts to encourage more credential entries
                self._send(client, AUTH_FAIL_MSG)
            else:
                # On the LAST attempt, pretend login succeeded
                self._send(client, SHELL_WELCOME)

        return len(credentials), credentials

    # ───────────────────────────────────────────────────────────────────
    #  PHASE 2: Fake shell (captures post-login commands)
    # ───────────────────────────────────────────────────────────────────
    def _run_shell_phase(self, client: socket.socket) -> tuple:
        """
        Simulate a bash shell prompt and record every command entered.

        All commands receive a "command not found" response — we do not
        execute anything.  The session ends when the attacker types 'exit',
        'quit', disconnects, or exceeds MAX_COMMANDS.

        Returns:
            (command_count, commands_list)
        """
        commands = []

        for _ in range(MAX_COMMANDS):
            self._send(client, SHELL_PROMPT)
            cmd = self.receive_line(client)

            if cmd is None:
                # Client disconnected
                break

            commands.append(cmd)

            # Let the attacker leave gracefully
            if cmd.lower() in ("exit", "quit", "logout"):
                self._send(client, "\r\nConnection closed.\r\n")
                break

            # Send a fake "command not found" response for anything else
            self._send(client, FAKE_RESPONSE.format(cmd=cmd))

        return len(commands), commands

    # ───────────────────────────────────────────────────────────────────
    #  CONNECTION HANDLER (one thread per client)
    # ───────────────────────────────────────────────────────────────────
    def handle_connection(self, client: socket.socket, address: tuple):
        """
        Full lifecycle for one attacker session.

        How the honeypot captures behaviour:
          1. We record the wall-clock time when the connection starts.
          2. Phase 1 (login) — every username/password pair is stored.
          3. Phase 2 (shell) — every typed command is stored.
          4. When the session ends (disconnect, timeout, or exit) we
             compute session_duration = now - start_time.
          5. A structured summary is logged via AttackLogger.

        Args:
            client  : The dedicated socket for this client, returned by
                      accept().  It is independent of the listening socket.
            address : (ip_address, port) tuple identifying the remote end.
        """
        ip = address[0]
        port = address[1]
        session_start = time.time()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[{timestamp}] [+] Connection from {ip}:{port}")

        # Set a per-recv timeout so idle attackers don't hold threads forever.
        # This is different from the listening socket timeout.
        client.settimeout(RECV_TIMEOUT)

        login_attempts = 0
        command_count = 0
        command_types = 0      # Count of recon commands (ls, pwd, whoami, etc.)
        successful_login = 0   # 1 if attacker reached the fake shell
        all_payloads = []      # Every piece of text the attacker sent

        try:
            # ── Step 1: Send the fake SSH banner ───────────────────────
            # This is the first thing the attacker sees — it must look
            # convincing enough that they believe this is a real server.
            self._send(client, SSH_BANNER)

            # ── Step 2: Run the fake login prompt ──────────────────────
            login_attempts, credentials = self._run_login_phase(client)

            # Flatten credentials into the payload list for logging
            for user, pwd in credentials:
                all_payloads.append(f"{user} {pwd}")

            # ── Step 3: If the attacker "logged in", run the fake shell ─
            # We only enter this phase if all MAX_LOGIN_ATTEMPTS were used,
            # meaning the server pretended the last one succeeded.
            if login_attempts == MAX_LOGIN_ATTEMPTS:
                successful_login = 1
                command_count, commands = self._run_shell_phase(client)
                all_payloads.extend(commands)

                # Count how many commands are reconnaissance commands.
                # We check only the first word of each command because
                # attackers often pass arguments (e.g. "ls -la /etc").
                for cmd in commands:
                    first_word = cmd.split()[0].lower() if cmd.strip() else ""
                    if first_word in RECON_COMMANDS:
                        command_types += 1

        except (BrokenPipeError, ConnectionResetError):
            # Client force-closed the connection — that's fine, we still log.
            print(f"[{timestamp}] [!] Client {ip}:{port} disconnected abruptly")
        except socket.timeout:
            print(f"[{timestamp}] [!] Session timed out: {ip}:{port}")
        except Exception as exc:
            print(f"[{timestamp}] [!] Error with {ip}:{port} -> {exc}")
        finally:
            # ── Step 4: Compute session duration ───────────────────────
            session_duration = round(time.time() - session_start, 2)

            # ── Step 5: Persist the session to the CSV log ─────────────
            # The logger stores one row per session with exactly the
            # fields the ML pipeline and dashboard expect:
            #   ip_address, login_attempts, session_duration,
            #   commands_sent, command_types, successful_login, timestamp
            self.logger.log_attack(
                ip_address=ip,
                login_attempts=login_attempts,
                session_duration=session_duration,
                commands_sent=command_count,
                command_types=command_types,
                successful_login=successful_login,
                timestamp=timestamp,
            )

            print(
                f"[{timestamp}] [-] Session ended: {ip}:{port}  "
                f"logins={login_attempts}  cmds={command_count}  "
                f"duration={session_duration}s"
            )

            # ── Step 6: Predict behavioral intent ───────────────────────
            # Send the metrics to the ML model to classify the session.
            attack_type = predict_attack(
                attack_type='ssh',
                login_attempts=login_attempts,
                session_duration=session_duration,
                commands_sent=command_count,
                command_types=command_types,
                successful_login=successful_login,
                # Multi-attack features (zeros for SSH)
                packet_count=0,
                scan_speed=0.0,
                stealth_detected=0,
                syn_count=0,
                query_rate=0.0,
                tunneling_detected=0,
                amplification_detected=0,
                arp_reply_rate=0.0,
                gratuitous_arp=0,
                ip_conflict=0,
                mac_conflict=0,
                icmp_rate=0.0,
                flood_detected=0,
                oversized_detected=0,
                packet_size=0,
            )
            print(f"[{timestamp}] [!] Detected Attack Type: {attack_type}")

            # ── Step 8: Close the client socket ─────────────────────────
            # This sends a TCP FIN to the remote end.  The listening socket
            # in start() remains open and keeps accepting new connections.
            client.close()

    # ───────────────────────────────────────────────────────────────────
    #  MAIN SERVER LOOP
    # ───────────────────────────────────────────────────────────────────
    def start(self):
        """
        Bind, listen, and accept connections in an infinite loop.

        How this works under the hood:
          • bind()   attaches our socket to (HOST, PORT).  The OS now
                     knows that TCP packets arriving on PORT should be
                     delivered to our process.
          • listen() puts the socket into "passive" mode — it will not
                     initiate connections, only receive them.
          • accept() blocks the calling thread until a SYN packet arrives
                     from a client.  It then completes the TCP three-way
                     handshake (SYN → SYN-ACK → ACK) and returns a brand-
                     new socket object dedicated to that single client.

        We spawn a daemon thread for each accepted connection so the main
        loop remains free to accept the next one immediately.  Daemon
        threads are killed automatically when the main thread exits
        (e.g. on Ctrl+C).
        """
        # Attach the socket to our chosen (host, port)
        self.server_socket.bind((self.host, self.port))

        # Start listening — backlog of 5 pending connections
        self.server_socket.listen(5)

        print("=" * 62)
        print("   HONEYPOT SSH SERVER  ===  ACTIVE")
        print(f"   Listening on {self.host}:{self.port}")
        print(f"   Max login attempts per session: {MAX_LOGIN_ATTEMPTS}")
        print("=" * 62)
        print("Waiting for connections ...\n")

        try:
            while True:
                # accept() BLOCKS here until a client connects.
                # It returns:
                #   client_socket — a NEW socket for talking to THIS client
                #   address       — (ip, port) of the remote client
                client_socket, address = self.server_socket.accept()

                # Spawn a thread so this client is handled concurrently.
                # daemon=True means the thread dies if the main program exits.
                handler = threading.Thread(
                    target=self.handle_connection,
                    args=(client_socket, address),
                    daemon=True,
                )
                handler.start()

        except KeyboardInterrupt:
            print("\n[*] Honeypot shutting down (Ctrl+C) ...")
        finally:
            # Close the listening socket and release the port
            self.server_socket.close()
            print("[*] Server socket closed.")


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# Run directly:  python honeypot_server.py
# Connect with:  nc localhost 2222   or   telnet localhost 2222
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    server = HoneypotServer()
    server.start()
