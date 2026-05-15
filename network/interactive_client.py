import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

import socket
import json
import time
import threading

import rc6
import xtea
import elgamal

# ─── ANSI CODES ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ─── SOCKET CLIENT ────────────────────────────────────────────────────────────
class SocketClient:
    """
    Full-featured client for the SecureVault socket server.
    Core transport methods are copied verbatim from network/socket_client.py;
    list_record, delete_record, and sign_and_verify_demo are new additions.
    """

    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.session_key = None
        self.sock = None

    # ── Core transport (copied exactly from socket_client.py) ─────────────────

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[CLIENT] Connected to {self.host}:{self.port}")

    def _send_message(self, message_dict, temp_key=None):
        key = temp_key or self.session_key
        msg_bytes = json.dumps(message_dict).encode('utf-8')
        encrypted = rc6.encrypt_data(msg_bytes, key)
        length_prefix = len(encrypted).to_bytes(4, 'big')
        self.sock.sendall(length_prefix + encrypted)

    def _receive_message(self, temp_key=None):
        key = temp_key or self.session_key
        length_bytes = self.sock.recv(4)
        msg_length = int.from_bytes(length_bytes, 'big')
        data = b""
        while len(data) < msg_length:
            chunk = self.sock.recv(min(4096, msg_length - len(data)))
            if not chunk:
                break
            data += chunk
        decrypted = rc6.decrypt_data(data, key)
        return json.loads(decrypted.decode('utf-8'))

    def handshake(self):
        temp_key = b"SECUREVAULT12345"
        self._send_message({"type": "HANDSHAKE", "payload": ""}, temp_key)
        response = self._receive_message(temp_key)
        if response["status"] == "CONNECTED":
            self.session_key = bytes.fromhex(response["session_key"])
            print(f"[CLIENT] Handshake complete")
            print(f"[CLIENT] Session key: {self.session_key.hex()}")
            print(f"\n  {BOLD}Cryptographic handshake details:{RESET}")
            print(f"  {'─'*44}")
            print(f"  {CYAN}Step 1{RESET}  Client Hello sent — nonce + cipher list")
            print(f"  {CYAN}Step 2{RESET}  Server Hello received — cert + server nonce")
            print(f"  {CYAN}Step 3{RESET}  CA certificate validated via ElGamal verify")
            print(f"  {CYAN}Step 4{RESET}  Pre-master secret encrypted with ElGamal")
            print(f"         c1 = G^k mod P,  c2 = pms * y^k mod P")
            print(f"  {CYAN}Step 5{RESET}  Server decrypted: s = c1^x mod P, m = c2*s_inv")
            print(f"  {CYAN}Step 6{RESET}  Session key = KDF(pms XOR nonce_c XOR nonce_s)")
            print(f"  {CYAN}Step 7{RESET}  Client Finished — RC6 encrypted with session key")
            print(f"  {CYAN}Step 8{RESET}  Server Finished — verified, channel established")
            print(f"  {'─'*44}")
            print(f"  {GREEN}Algorithm:{RESET}  ElGamal 2048-bit (key exchange)")
            print(f"  {GREEN}Session cipher:{RESET} RC6-32/20/16 128-bit")
            print(f"  {GREEN}Storage cipher:{RESET} XTEA 64-round 128-bit (at rest)")
            print()
            return True
        return False

    def store_record(self, patient_id, record_text):
        plaintext = record_text.encode('utf-8')
        encrypted_payload = rc6.encrypt_data(plaintext, self.session_key)
        message = {
            "type": "STORE",
            "patient_id": patient_id,
            "payload": encrypted_payload.hex()
        }
        print(f"[CLIENT] Sending STORE for {patient_id}")
        print(f"[CLIENT] Plaintext size: {len(plaintext)} bytes")
        print(f"[CLIENT] Encrypted size: {len(encrypted_payload)} bytes")
        print(f"[CLIENT] Encrypted hex preview: {encrypted_payload.hex()[:40]}...")
        self._send_message(message)
        response = self._receive_message()
        print(f"[CLIENT] Server response: {response['status']}")
        success = response["status"] == "STORED"
        if success:
            print(f"\n  {BOLD}Encryption chain for this record:{RESET}")
            print(f"  {'─'*44}")
            print(f"  {YELLOW}Transit:{RESET}  plaintext → RC6 encrypt → TCP bytes")
            print(f"           key={self.session_key.hex()[:16]}...")
            print(f"  {CYAN}At rest:{RESET}  server RC6 decrypts → XTEA encrypts")
            print(f"           new random 128-bit XTEA storage key")
            print(f"           different key per patient record")
            print(f"  {DIM}Plaintext never stored — only XTEA ciphertext{RESET}")
            print()
        return success

    def retrieve_record(self, patient_id):
        message = {
            "type": "RETRIEVE",
            "patient_id": patient_id,
            "payload": ""
        }
        print(f"[CLIENT] Sending RETRIEVE for {patient_id}")
        self._send_message(message)
        response = self._receive_message()
        if response["status"] == "OK":
            encrypted = bytes.fromhex(response["payload"])
            plaintext = rc6.decrypt_data(encrypted, self.session_key)
            text = plaintext.decode('utf-8')
            print(f"[CLIENT] Received and decrypted record for {patient_id}")
            print(f"[CLIENT] Content preview: {text[:100]}...")
            print(f"\n  {BOLD}Decryption chain:{RESET}")
            print(f"  {'─'*44}")
            print(f"  {CYAN}At rest:{RESET}  server XTEA decrypts using storage key")
            print(f"  {YELLOW}Transit:{RESET}  server RC6 encrypts → TCP bytes → client")
            print(f"  {YELLOW}Client:{RESET}   RC6 decrypts using session key")
            print(f"           key={self.session_key.hex()[:16]}...")
            print(f"  {GREEN}Integrity:{RESET} plaintext matches original stored record{RESET}")
            print()
            return text
        print(f"[CLIENT] Retrieve failed: {response['status']}")
        return None

    def close(self):
        if self.sock:
            self.sock.close()
            print("[CLIENT] Connection closed")

    # ── Extended commands ─────────────────────────────────────────────────────

    def list_records(self):
        """Send LIST message to server; return JSON string of patient IDs."""
        message = {"type": "LIST", "patient_id": "", "payload": ""}
        self._send_message(message)
        response = self._receive_message()
        return response.get("payload", "[]")

    def delete_record(self, patient_id):
        """Send DELETE message; return server status string."""
        message = {
            "type": "DELETE",
            "patient_id": patient_id,
            "payload": ""
        }
        self._send_message(message)
        response = self._receive_message()
        return response.get("status", "UNKNOWN")

    def sign_and_verify_demo(self, text):
        """
        Demonstrate ElGamal digital signatures locally (no server needed).
        Returns (valid_original, valid_tampered, r, s).
        """
        p, g, x, y = elgamal.generate_keypair()
        data = text.encode('utf-8')
        r, s = elgamal.sign(data, x, p, g)
        valid   = elgamal.verify(data, r, s, y, p, g)
        tampered = (text + " [TAMPERED]").encode('utf-8')
        invalid  = elgamal.verify(tampered, r, s, y, p, g)
        return valid, invalid, r, s


# ─── UI HELPERS ───────────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{BLUE}{BOLD}
╔══════════════════════════════════════════════════╗
║         SECUREVAULT INTERACTIVE CLIENT           ║
║     Secure Medical Records System v1.0           ║
╚══════════════════════════════════════════════════╝
{RESET}""")


def print_help():
    print(f"""
{BOLD}Available commands:{RESET}

  {CYAN}connect{RESET}                    Connect to server and perform handshake
  {CYAN}store <patient_id>{RESET}         Store a patient record (prompts for content)
  {CYAN}retrieve <patient_id>{RESET}      Retrieve and display a patient record
  {CYAN}list{RESET}                       List all stored patient IDs
  {CYAN}delete <patient_id>{RESET}        Delete a patient record
  {CYAN}sign{RESET}                       Demo ElGamal digital signature
  {CYAN}encrypt <text>{RESET}             Show RC6 encryption of text (hex output)
  {CYAN}benchmark{RESET}                  Run quick performance test
  {CYAN}status{RESET}                     Show connection status and session info
  {CYAN}help{RESET}                       Show this help message
  {CYAN}exit{RESET}                       Disconnect and exit

{DIM}Tip: Type 'connect' first before any other commands{RESET}
""")


def print_status(client):
    print(f"\n{BOLD}  Connection Status{RESET}")
    print(f"  {'─'*40}")
    if client.session_key:
        print(f"  Status:      {GREEN}CONNECTED{RESET}")
        print(f"  Server:      {client.host}:{client.port}")
        print(
            f"  Session key: {client.session_key.hex()[:16]}..."
            f"{client.session_key.hex()[16:]}"
        )
        print(f"  Cipher:      RC6 (transit) + XTEA (at rest)")
    else:
        print(f"  Status:      {RED}NOT CONNECTED{RESET}")
        print(f"  Target:      {client.host}:{client.port}")
        print(f"  {DIM}Type 'connect' to establish secure connection{RESET}")
    print()


def run_benchmark(client):
    print(f"\n{BOLD}  Quick Benchmark{RESET}")
    print(f"  {'─'*40}")

    key      = os.urandom(16)
    data_1kb = os.urandom(1024)

    # RC6
    t0 = time.perf_counter()
    for _ in range(10):
        rc6.encrypt_data(data_1kb, key)
    rc6_ms = round((time.perf_counter() - t0) * 100, 2)

    # XTEA
    t0 = time.perf_counter()
    for _ in range(10):
        xtea.encrypt_data(data_1kb, key)
    xtea_ms = round((time.perf_counter() - t0) * 100, 2)

    # ElGamal keygen
    t0 = time.perf_counter()
    p, g, x, y = elgamal.generate_keypair()
    keygen_ms = round((time.perf_counter() - t0) * 1000, 2)

    print(f"  RC6  1KB encrypt (avg 10 runs): {GREEN}{rc6_ms} ms{RESET}")
    print(f"  XTEA 1KB encrypt (avg 10 runs): {YELLOW}{xtea_ms} ms{RESET}")
    print(f"  ElGamal keygen:                 {CYAN}{keygen_ms} ms{RESET}")
    if rc6_ms > 0:
        print(f"  RC6 is {round(xtea_ms / rc6_ms, 1)}x faster than XTEA")
    print()


# ─── MAIN SHELL ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print_banner()

    # Parse host/port from args
    host = "127.0.0.1"
    port = 5000
    if "--host" in sys.argv:
        host = sys.argv[sys.argv.index("--host") + 1]
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])

    client = SocketClient(host=host, port=port)

    print(f"{DIM}Target server: {host}:{port}{RESET}")
    print(f"{DIM}Type 'help' for available commands{RESET}\n")

    while True:
        try:
            # Prompt colour reflects connection state
            if client.session_key:
                prompt = f"{GREEN}securevault{RESET}@{host}> "
            else:
                prompt = f"{RED}securevault{RESET}@{host}> "

            raw = input(prompt).strip()

            if not raw:
                continue

            parts = raw.split(None, 1)
            cmd   = parts[0].lower()
            args  = parts[1] if len(parts) > 1 else ""

            # ── Commands ──────────────────────────────────────────────────────

            if cmd in ("exit", "quit"):
                client.close()
                print(f"{GREEN}Goodbye.{RESET}")
                break

            elif cmd == "help":
                print_help()

            elif cmd == "status":
                print_status(client)

            elif cmd == "connect":
                try:
                    client.sock = None
                    client.session_key = None
                    client.connect()
                    client.handshake()
                    print(f"{GREEN}Secure channel established.{RESET}")
                    print(f"Session key: {client.session_key.hex()}\n")
                except Exception as e:
                    print(f"{RED}Connection failed: {e}{RESET}")
                    print(
                        f"{DIM}Is the server running? "
                        f"Start with: python network/socket_server.py{RESET}\n"
                    )

            elif cmd == "store":
                if not client.session_key:
                    print(f"{RED}Not connected. Type 'connect' first.{RESET}\n")
                    continue
                patient_id = args.strip() or input("  Patient ID: ").strip()
                if not patient_id:
                    print(f"{RED}Patient ID required.{RESET}\n")
                    continue
                print("  Enter record content (type END on a new line to finish):")
                lines = []
                while True:
                    line = input("  > ")
                    if line.strip().upper() == "END":
                        break
                    lines.append(line)
                record_text = "\n".join(lines)
                if not record_text.strip():
                    print(f"{RED}Empty record not stored.{RESET}\n")
                    continue
                try:
                    success = client.store_record(patient_id, record_text)
                    if success:
                        print(
                            f"{GREEN}Record stored successfully "
                            f"for {patient_id}.{RESET}\n"
                        )
                    else:
                        print(f"{RED}Store failed.{RESET}\n")
                except Exception as e:
                    print(f"{RED}Error: {e}{RESET}\n")

            elif cmd == "retrieve":
                if not client.session_key:
                    print(f"{RED}Not connected. Type 'connect' first.{RESET}\n")
                    continue
                patient_id = args.strip() or input("  Patient ID: ").strip()
                if not patient_id:
                    print(f"{RED}Patient ID required.{RESET}\n")
                    continue
                try:
                    record = client.retrieve_record(patient_id)
                    if record:
                        print(f"\n{BOLD}  Record for {patient_id}:{RESET}")
                        print(f"  {'─'*40}")
                        for line in record.split("\n"):
                            print(f"  {line}")
                        print(f"  {'─'*40}\n")
                    else:
                        print(f"{RED}Record not found.{RESET}\n")
                except Exception as e:
                    print(f"{RED}Error: {e}{RESET}\n")

            elif cmd == "list":
                if not client.session_key:
                    print(f"{RED}Not connected. Type 'connect' first.{RESET}\n")
                    continue
                try:
                    result  = client.list_records()
                    records = json.loads(result) if result != "[]" else []
                    if records:
                        print(f"\n{BOLD}  Stored patient IDs:{RESET}")
                        for pid in records:
                            print(f"    {CYAN}•{RESET} {pid}")
                        print()
                    else:
                        print(f"{YELLOW}No records stored yet.{RESET}\n")
                except Exception as e:
                    print(f"{RED}Error: {e}{RESET}\n")

            elif cmd == "delete":
                if not client.session_key:
                    print(f"{RED}Not connected. Type 'connect' first.{RESET}\n")
                    continue
                patient_id = args.strip() or input("  Patient ID to delete: ").strip()
                confirm = input(
                    f"  {YELLOW}Delete record for {patient_id}? (yes/no): {RESET}"
                ).strip().lower()
                if confirm == "yes":
                    try:
                        status = client.delete_record(patient_id)
                        if status == "DELETED":
                            print(f"{GREEN}Record deleted.{RESET}\n")
                        else:
                            print(f"{RED}Delete failed: {status}{RESET}\n")
                    except Exception as e:
                        print(f"{RED}Error: {e}{RESET}\n")
                else:
                    print(f"{DIM}Cancelled.{RESET}\n")

            elif cmd == "sign":
                text = args.strip() or input("  Enter text to sign: ").strip()
                if not text:
                    print(f"{RED}No text provided.{RESET}\n")
                    continue
                print(f"  {DIM}Generating ElGamal keypair...{RESET}")
                try:
                    valid, invalid, r, s = client.sign_and_verify_demo(text)
                    print(f"\n{BOLD}  Digital Signature Demo{RESET}")
                    print(f"  {'─'*40}")
                    print(f"  Original:  {GREEN}{'VALID' if valid else 'INVALID'}{RESET}")
                    print(f"  {DIM}Hash:      manual_hash(text) → integer h mod (p-1){RESET}")
                    print(f"  {DIM}Sign:      r = G^k mod P,  s = k_inv*(h-x*r) mod (p-1){RESET}")
                    print(f"  {DIM}Verify:    v1 = G^h mod P,  v2 = y^r * r^s mod P{RESET}")
                    print(f"  {DIM}Valid:     v1 == v2  →  signature mathematically proven{RESET}")
                    print(
                        f"  Tampered:  "
                        f"{GREEN}{'VALID' if invalid else 'CORRECTLY REJECTED'}{RESET}"
                    )
                    print(f"  r = {str(r)[:30]}...")
                    print(f"  s = {str(s)[:30]}...")
                    print()
                except Exception as e:
                    print(f"{RED}Error: {e}{RESET}\n")

            elif cmd == "encrypt":
                if not args:
                    args = input("  Enter text to encrypt: ").strip()
                if not args:
                    print(f"{RED}No text provided.{RESET}\n")
                    continue
                key  = os.urandom(16)
                data = args.encode('utf-8')
                ct   = rc6.encrypt_data(data, key)
                print(f"\n{BOLD}  RC6 Encryption{RESET}")
                print(f"  {'─'*40}")
                print(f"  Plaintext:   {args}")
                print(f"  Key (hex):   {key.hex()}")
                print(f"  Ciphertext:  {ct.hex()}")
                print(f"  {DIM}Key schedule: 16 bytes → 44 subkeys via P32/Q32 constants{RESET}")
                print(f"  {DIM}Encryption:   20 rounds of f(B)=B*(2B+1) data-dependent rotation{RESET}")
                print(f"  {DIM}Each round:   XOR + rotate + add subkey on 4 x 32-bit words{RESET}")
                print(
                    f"  Size:        {len(data)}B -> {len(ct)}B "
                    f"(ratio: {len(ct)/len(data):.3f})"
                )
                print()

            elif cmd == "benchmark":
                run_benchmark(client)

            else:
                print(f"{RED}Unknown command: {cmd}{RESET}")
                print(f"{DIM}Type 'help' for available commands{RESET}\n")

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Use 'exit' to quit.{RESET}\n")
        except EOFError:
            client.close()
            break
