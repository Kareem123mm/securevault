import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

import socket
import threading
import time
import json
import collections

# ─── ANSI ESCAPE CODES ────────────────────────────────────────────────────────
CLEAR       = "\033[2J\033[H"
GREEN       = "\033[92m"
RED         = "\033[91m"
YELLOW      = "\033[93m"
BLUE        = "\033[94m"
CYAN        = "\033[96m"
WHITE       = "\033[97m"
BOLD        = "\033[1m"
DIM         = "\033[2m"
RESET       = "\033[0m"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"


# ─── SERVER MONITOR ───────────────────────────────────────────────────────────
class ServerMonitor:

    def __init__(self, server_host="127.0.0.1", server_port=5000):
        self.host = server_host
        self.port = server_port
        self.running = False
        self.refresh_rate = 1.0  # seconds

        # Stats tracked by monitor
        self.stats = {
            "start_time":           time.time(),
            "total_connections":    0,
            "active_connections":   0,
            "total_messages":       0,
            "store_operations":     0,
            "retrieve_operations":  0,
            "handshakes":           0,
            "errors":               0,
            "bytes_sent":           0,
            "bytes_received":       0,
            "last_connection":      "None",
            "last_operation":       "None",
            "last_operation_time":  "Never",
            "server_status":        "UNKNOWN",
            "patients_stored":      0,
        }

        # Activity log — keep last 10 entries
        self.activity_log = collections.deque(maxlen=10)

        # Lock for thread safety
        self.lock = threading.Lock()

    # ─── SERVER HEALTH CHECK ──────────────────────────────────────────────────
    def check_server_alive(self):
        """
        Check if the server port is occupied using bind().
        This avoids opening a real connection (no spam in server logs).
        Returns True if the port is in use (server running), False if free.
        """
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            test_sock.bind(('127.0.0.1', self.port))
            test_sock.close()
            return False  # bind succeeded → port free → server NOT running
        except OSError:
            test_sock.close()
            return True   # bind failed → port in use → server IS running
        except Exception:
            test_sock.close()
            return False

    # ─── SERVER STATS FILE READER ─────────────────────────────────────────────
    def read_server_stats(self):
        """
        Read live stats written by the server process to
        performance_results/server_status.json.
        Returns the parsed dict, or None if the file is absent / stale (>10 s).
        """
        try:
            status_path = os.path.join(
                os.path.dirname(__file__),
                '..',
                'performance_results',
                'server_status.json'
            )
            if not os.path.exists(status_path):
                return None
            with open(status_path, 'r') as f:
                data = json.load(f)
            # Treat file as stale if older than 10 seconds
            if time.time() - data.get('timestamp', 0) > 10:
                return None
            return data
        except:
            return None

    # ─── COMPOSITE STATUS CHECK ───────────────────────────────────────────────
    def get_server_status(self):
        """
        Primary:  stats JSON file (reliable; no Windows bind() quirks).
        Fallback: bind() probe (used only when file doesn't exist yet).

        Returns (alive: bool, server_stats: dict | None)
        """
        stats = self.read_server_stats()
        if stats is not None:
            age = time.time() - stats.get('timestamp', 0)
            if age < 10:
                return True, stats    # fresh file → server is ONLINE
            else:
                return False, None    # stale file → server probably stopped
        # No file yet — fall back to bind() probe
        alive = self.check_server_alive()
        return alive, None

    # ─── ACTIVITY LOG ─────────────────────────────────────────────────────────
    def log_activity(self, message, level="INFO"):
        """
        Append a timestamped entry to the activity log.
        level: INFO | SUCCESS | WARNING | ERROR
        """
        timestamp = time.strftime("%H:%M:%S")
        with self.lock:
            self.activity_log.append({
                "time":    timestamp,
                "level":   level,
                "message": message,
            })

    # ─── FORMATTING HELPERS ───────────────────────────────────────────────────
    def format_uptime(self):
        """Return monitor uptime as HH:MM:SS string."""
        elapsed = int(time.time() - self.stats["start_time"])
        hours   = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def format_bytes(self, n):
        """Return human-readable byte count."""
        if n < 1024:
            return f"{n} B"
        elif n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        else:
            return f"{n / 1024 / 1024:.1f} MB"

    def draw_bar(self, value, max_value, width=20, colour=GREEN):
        """Return a coloured progress bar string."""
        filled = int((value / max_value) * width) if max_value > 0 else 0
        filled = min(filled, width)
        bar = "█" * filled + "░" * (width - filled)
        return f"{colour}{bar}{RESET}"

    # ─── DASHBOARD RENDERER ───────────────────────────────────────────────────
    def draw_dashboard(self):
        """Clear the terminal and redraw the entire dashboard."""
        type_colours = {
            "HANDSHAKE_START":    BLUE,
            "CERT_VALIDATED":     GREEN,
            "KEY_EXCHANGE":       CYAN,
            "SESSION_KEY_DERIVED": GREEN,
            "RC6_ENCRYPT":        YELLOW,
            "RC6_DECRYPT":        YELLOW,
            "XTEA_ENCRYPT":       CYAN,
            "XTEA_DECRYPT":       CYAN,
            "ELGAMAL_ENCRYPT":    BLUE,
            "ELGAMAL_DECRYPT":    BLUE,
            "SIGNATURE_CREATED":  GREEN,
            "SIGNATURE_VERIFIED": GREEN,
            "RECORD_STORED":      GREEN,
            "RECORD_RETRIEVED":   CYAN,
            "RECORD_DELETED":     RED,
            "LIST_REQUEST":       WHITE,
            "SESSION_CLOSED":     DIM,
            "KEY_GENERATED":      BLUE,
        }

        type_icons = {
            "HANDSHAKE_START":    "HS",
            "CERT_VALIDATED":     "CV",
            "KEY_EXCHANGE":       "KE",
            "SESSION_KEY_DERIVED":"SK",
            "RC6_ENCRYPT":        "RE",
            "RC6_DECRYPT":        "RD",
            "XTEA_ENCRYPT":       "XE",
            "XTEA_DECRYPT":       "XD",
            "ELGAMAL_ENCRYPT":    "EE",
            "ELGAMAL_DECRYPT":    "ED",
            "SIGNATURE_CREATED":  "SC",
            "SIGNATURE_VERIFIED": "SV",
            "RECORD_STORED":      "RS",
            "RECORD_RETRIEVED":   "RR",
            "RECORD_DELETED":     "RL",
            "LIST_REQUEST":       "LR",
            "SESSION_CLOSED":     "SC",
            "KEY_GENERATED":      "KG",
        }

        # ── Primary status: JSON file beats bind() probe on Windows ───────────
        alive, server_stats = self.get_server_status()

        if alive and server_stats is not None:
            status_colour = GREEN
            status_text   = "ONLINE"
            status_note   = f"  {DIM}(live stats){RESET}"
        elif alive:
            status_colour = GREEN
            status_text   = "ONLINE"
            status_note   = ""
        else:
            status_colour = RED
            status_text   = "OFFLINE"
            status_note   = (
                f"  {DIM}(no data yet){RESET}"
                if server_stats is None else ""
            )

        with self.lock:
            stats = dict(self.stats)
            log   = list(self.activity_log)

        # ── Overlay live server stats from JSON file (if fresh) ────────────────
        if server_stats is not None:
            stats['total_connections']   = server_stats.get('total_connections',   stats['total_connections'])
            stats['store_operations']    = server_stats.get('total_store',         stats['store_operations'])
            stats['retrieve_operations'] = server_stats.get('total_retrieve',      stats['retrieve_operations'])
            stats['handshakes']          = server_stats.get('total_handshakes',    stats['handshakes'])
            stats['errors']              = server_stats.get('total_errors',        stats['errors'])
            stats['bytes_sent']          = server_stats.get('bytes_sent',          stats['bytes_sent'])
            stats['bytes_received']      = server_stats.get('bytes_received',      stats['bytes_received'])
            stats['patients_stored']     = server_stats.get('patients_stored',     stats['patients_stored'])
            stats['last_operation']      = server_stats.get('last_operation',      stats['last_operation'])
            stats['last_operation_time'] = server_stats.get('last_operation_time', stats['last_operation_time'])
            stats['last_connection']     = server_stats.get('last_client',         stats['last_connection'])
            # Swap activity log source to server-written entries
            if 'activity_log' in server_stats and server_stats['activity_log']:
                log = server_stats['activity_log']

        lines = []
        width = 60

        # ── Header ────────────────────────────────────────────────────────────
        lines.append(f"{CLEAR}")
        lines.append(f"{BLUE}{BOLD}{'=' * width}{RESET}")
        lines.append(f"{BLUE}{BOLD}   SECUREVAULT SERVER MONITOR{RESET}")
        lines.append(f"{BLUE}{BOLD}{'=' * width}{RESET}")
        lines.append(
            f"  {DIM}Monitoring: {self.host}:{self.port}   "
            f"Refresh: {self.refresh_rate}s   "
            f"Press Ctrl+C to exit{RESET}"
        )
        lines.append("")

        # ── Server status ─────────────────────────────────────────────────────
        lines.append(f"{BOLD}  SERVER STATUS{RESET}")
        lines.append(f"  {'─' * 56}")
        lines.append(
            f"  Status:          {status_colour}{BOLD}{status_text}{RESET}"
            + status_note
        )
        lines.append(f"  Monitor uptime:  {self.format_uptime()}")
        lines.append(f"  Last checked:    {time.strftime('%H:%M:%S')}")
        lines.append("")

        # ── Connection stats ──────────────────────────────────────────────────
        lines.append(f"{BOLD}  CONNECTIONS{RESET}")
        lines.append(f"  {'─' * 56}")
        lines.append(f"  Total:           {WHITE}{stats['total_connections']}{RESET}")
        lines.append(f"  Active:          {CYAN}{stats['active_connections']}{RESET}")
        lines.append(f"  Last from:       {stats['last_connection']}")
        lines.append("")

        # ── Operations ────────────────────────────────────────────────────────
        lines.append(f"{BOLD}  OPERATIONS{RESET}")
        lines.append(f"  {'─' * 56}")
        lines.append(f"  Total messages:  {stats['total_messages']}")
        lines.append(f"  Handshakes:      {GREEN}{stats['handshakes']}{RESET}")
        lines.append(f"  Store (upload):  {GREEN}{stats['store_operations']}{RESET}")
        lines.append(f"  Retrieve:        {CYAN}{stats['retrieve_operations']}{RESET}")
        lines.append(
            f"  Errors:          "
            f"{''+RED if stats['errors'] > 0 else ''}"
            f"{stats['errors']}{RESET}"
        )
        lines.append(f"  Patients stored: {WHITE}{stats['patients_stored']}{RESET}")
        lines.append("")

        # ── Network traffic ───────────────────────────────────────────────────
        lines.append(f"{BOLD}  NETWORK TRAFFIC{RESET}")
        lines.append(f"  {'─' * 56}")
        lines.append(f"  Sent:            {self.format_bytes(stats['bytes_sent'])}")
        lines.append(f"  Received:        {self.format_bytes(stats['bytes_received'])}")
        lines.append("")

        # ── Last operation ────────────────────────────────────────────────────
        lines.append(f"{BOLD}  LAST OPERATION{RESET}")
        lines.append(f"  {'─' * 56}")
        lines.append(f"  Type:            {YELLOW}{stats['last_operation']}{RESET}")
        lines.append(f"  Time:            {stats['last_operation_time']}")
        lines.append("")

        # --- CRYPTOGRAPHIC EVENTS ---
        lines.append(f"{BOLD}  CRYPTOGRAPHIC EVENTS (live){RESET}")
        lines.append(f"  {'─'*56}")

        crypto_events = []
        if server_stats and 'crypto_events' in server_stats:
            crypto_events = server_stats['crypto_events']

        if not crypto_events:
            lines.append(f"  {DIM}Waiting for cryptographic operations...{RESET}")
            lines.append(f"  {DIM}Connect a client to see the full encryption flow{RESET}")
        else:
            # Show last 12 events in reverse order (newest first)
            for entry in reversed(crypto_events[-12:]):
                event_type = entry.get('type', 'UNKNOWN')
                colour = type_colours.get(event_type, WHITE)
                icon   = type_icons.get(event_type, '  ')
                time_s = entry.get('time', '??:??:??')
                detail = entry.get('details', '')
                
                # Truncate detail to fit terminal width
                max_detail = 48
                if len(detail) > max_detail:
                    detail = detail[:max_detail] + '...'
                
                # Format: TIME  ICON  TYPE          detail
                type_padded = event_type[:18].ljust(18)
                lines.append(
                    f"  {DIM}{time_s}{RESET}  "
                    f"{colour}{icon} {type_padded}{RESET}  "
                    f"{DIM}{detail}{RESET}"
                )

        lines.append("")

        # --- SYSTEM FLOW SUMMARY ---
        lines.append(f"{BOLD}  SYSTEM FLOW SUMMARY{RESET}")
        lines.append(f"  {'─'*56}")

        if server_stats:
            # Count each operation type from crypto_events
            all_events = server_stats.get('crypto_events', [])
            counts = {}
            for e in all_events:
                t = e.get('type', '')
                counts[t] = counts.get(t, 0) + 1
            
            # Display as a table
            flow_items = [
                ("Handshakes completed",  "HANDSHAKE_START",    BLUE),
                ("Certificates validated","CERT_VALIDATED",     GREEN),
                ("Key exchanges",         "KEY_EXCHANGE",       CYAN),
                ("Session keys derived",  "SESSION_KEY_DERIVED",GREEN),
                ("RC6 encryptions",       "RC6_ENCRYPT",        YELLOW),
                ("RC6 decryptions",       "RC6_DECRYPT",        YELLOW),
                ("XTEA encryptions",      "XTEA_ENCRYPT",       CYAN),
                ("XTEA decryptions",      "XTEA_DECRYPT",       CYAN),
                ("Records stored",        "RECORD_STORED",      GREEN),
                ("Records retrieved",     "RECORD_RETRIEVED",   CYAN),
            ]
            
            for label, key, colour in flow_items:
                count = counts.get(key, 0)
                if count > 0:
                    bar = "█" * min(count * 3, 20)
                    lines.append(
                        f"  {label:<26} "
                        f"{colour}{bar}{RESET} "
                        f"{WHITE}{count}{RESET}"
                    )
                else:
                    lines.append(
                        f"  {label:<26} "
                        f"{DIM}{'░' * 10}{RESET} "
                        f"{DIM}0{RESET}"
                    )
        else:
            lines.append(f"  {DIM}No data yet{RESET}")

        lines.append("")
        lines.append(f"{BLUE}{BOLD}{'='*width}{RESET}")
        lines.append(f"  {DIM}Ctrl+C to exit   │   "
                     f"Crypto events update on every client operation{RESET}")

        print("\n".join(lines), flush=True)

    # ─── MAIN MONITORING LOOP ─────────────────────────────────────────────────
    def start_monitoring(self):
        """Start the blocking monitoring loop. Press Ctrl+C to exit."""
        self.running = True
        print(HIDE_CURSOR, end="", flush=True)

        self.log_activity("Monitor started", "INFO")

        # Initial status check — prefer JSON file over bind() probe
        alive, _ = self.get_server_status()
        if alive:
            self.stats["server_status"] = "ONLINE"
            self.log_activity(
                f"Server found at {self.host}:{self.port}", "SUCCESS"
            )
        else:
            self.stats["server_status"] = "OFFLINE"
            self.log_activity(
                f"Server NOT found at {self.host}:{self.port} — "
                f"start socket_server.py",
                "WARNING",
            )

        try:
            while self.running:
                # Use get_server_status() as the single source of truth
                alive, _ = self.get_server_status()
                new_status = "ONLINE" if alive else "OFFLINE"

                if new_status != self.stats["server_status"]:
                    if alive:
                        self.log_activity(
                            f"Server came ONLINE at {self.host}:{self.port}",
                            "SUCCESS",
                        )
                    else:
                        self.log_activity("Server went OFFLINE", "ERROR")
                    self.stats["server_status"] = new_status

                self.draw_dashboard()
                time.sleep(self.refresh_rate)

        except KeyboardInterrupt:
            pass
        finally:
            print(SHOW_CURSOR, end="", flush=True)
            print(f"\n{YELLOW}Monitor stopped.{RESET}\n")

    # ─── EXTERNAL STATS UPDATER ───────────────────────────────────────────────
    def update_stats(self, event_type, details=None):
        """
        Thread-safe method to push events into the monitor from external code.

        event_type values:
            "connection"    — new client connected  (details: address string)
            "disconnect"    — client disconnected   (details: address string)
            "store"         — a record was stored   (details: record id / name)
            "retrieve"      — a record was fetched  (details: record id / name)
            "handshake"     — handshake completed   (details: client info)
            "error"         — an error occurred     (details: error message)
            "bytes_sent"    — bytes sent            (details: int byte count)
            "bytes_received"— bytes received        (details: int byte count)
        """
        with self.lock:
            if event_type == "connection":
                self.stats["total_connections"]  += 1
                self.stats["active_connections"] += 1
                self.stats["last_connection"]     = details or "unknown"
                self.activity_log.append({
                    "time":    time.strftime("%H:%M:%S"),
                    "level":   "SUCCESS",
                    "message": f"New connection: {details}",
                })

            elif event_type == "disconnect":
                self.stats["active_connections"] = max(
                    0, self.stats["active_connections"] - 1
                )
                self.activity_log.append({
                    "time":    time.strftime("%H:%M:%S"),
                    "level":   "INFO",
                    "message": f"Disconnected: {details}",
                })

            elif event_type == "store":
                self.stats["store_operations"]    += 1
                self.stats["total_messages"]      += 1
                self.stats["patients_stored"]     += 1
                self.stats["last_operation"]       = "STORE"
                self.stats["last_operation_time"]  = time.strftime("%H:%M:%S")
                self.activity_log.append({
                    "time":    time.strftime("%H:%M:%S"),
                    "level":   "SUCCESS",
                    "message": f"Record stored: {details}",
                })

            elif event_type == "retrieve":
                self.stats["retrieve_operations"] += 1
                self.stats["total_messages"]      += 1
                self.stats["last_operation"]       = "RETRIEVE"
                self.stats["last_operation_time"]  = time.strftime("%H:%M:%S")
                self.activity_log.append({
                    "time":    time.strftime("%H:%M:%S"),
                    "level":   "SUCCESS",
                    "message": f"Record retrieved: {details}",
                })

            elif event_type == "handshake":
                self.stats["handshakes"]          += 1
                self.stats["total_messages"]      += 1
                self.stats["last_operation"]       = "HANDSHAKE"
                self.stats["last_operation_time"]  = time.strftime("%H:%M:%S")
                self.activity_log.append({
                    "time":    time.strftime("%H:%M:%S"),
                    "level":   "SUCCESS",
                    "message": f"Handshake complete: {details}",
                })

            elif event_type == "error":
                self.stats["errors"] += 1
                self.activity_log.append({
                    "time":    time.strftime("%H:%M:%S"),
                    "level":   "ERROR",
                    "message": f"Error: {details}",
                })

            elif event_type == "bytes_sent":
                self.stats["bytes_sent"] += details or 0

            elif event_type == "bytes_received":
                self.stats["bytes_received"] += details or 0


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    host = "127.0.0.1"
    port = 5000

    # Allow command-line args: python monitor.py --host 192.168.1.5 --port 5000
    if "--host" in sys.argv:
        idx  = sys.argv.index("--host")
        host = sys.argv[idx + 1]
    if "--port" in sys.argv:
        idx  = sys.argv.index("--port")
        port = int(sys.argv[idx + 1])

    print(f"{BLUE}{BOLD}SecureVault Server Monitor{RESET}")
    print(f"Connecting to {host}:{port}...")
    time.sleep(1)

    monitor = ServerMonitor(host, port)
    monitor.start_monitoring()
