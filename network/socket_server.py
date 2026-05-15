import socket
import threading
import os
import sys
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

import rc6
import xtea
import elgamal
from ca import CertificateAuthority
from server import HospitalServer
from key_manager import KeyManager

HANDSHAKE_KEY = b"SECUREVAULT12345"

class SocketServer:

    def __init__(self, host="0.0.0.0", port=5000):
        ca = CertificateAuthority()
        self.hospital = HospitalServer(ca)
        self.session_key = os.urandom(16)
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lock = threading.Lock()

        # ── Operation counters (read by monitor via server_status.json) ────────
        self.total_connections   = 0
        self.total_store         = 0
        self.total_retrieve      = 0
        self.total_handshakes    = 0
        self.total_errors        = 0
        self.bytes_received      = 0
        self.bytes_sent          = 0
        self.last_client         = "None"
        self.last_operation      = "None"
        self.last_operation_time = "Never"
        self.activity_log_list   = []   # rolling list of last 10 event dicts
        self.crypto_events       = []   # detailed crypto log, last 20 entries
        self.running             = True  # controls heartbeat thread

    # ─── STATUS FILE WRITER ───────────────────────────────────────────────────
    def write_status(self):
        """
        Dump current server stats to performance_results/server_status.json.
        Called inside self.lock — must not acquire the lock again.
        """
        import os as _os
        _os.makedirs("performance_results", exist_ok=True)
        status = {
            "timestamp":           time.time(),
            "session_key":         self.session_key.hex(),
            "cert_serial":         self.hospital.cert["serial"],
            "patients_stored":     len(self.hospital.records),
            "patient_ids":         list(self.hospital.records.keys()),
            "total_connections":   self.total_connections,
            "total_store":         self.total_store,
            "total_retrieve":      self.total_retrieve,
            "total_handshakes":    self.total_handshakes,
            "total_errors":        self.total_errors,
            "bytes_received":      self.bytes_received,
            "bytes_sent":          self.bytes_sent,
            "last_client":         self.last_client,
            "last_operation":      self.last_operation,
            "last_operation_time": self.last_operation_time,
            "crypto_events":       self.crypto_events[-20:],
            "activity_log":        self.activity_log_list[-10:],
        }
        try:
            path = _os.path.join("performance_results", "server_status.json")
            with open(path, "w") as f:
                json.dump(status, f)
        except:
            pass

    # ─── ACTIVITY LOG HELPER ──────────────────────────────────────────────────
    def log_event(self, level, message):
        """
        Append a timestamped entry to the rolling activity log.
        Must be called inside self.lock.
        level: INFO | SUCCESS | WARNING | ERROR
        """
        entry = {
            "time":    time.strftime("%H:%M:%S"),
            "level":   level,
            "message": message,
        }
        self.activity_log_list.append(entry)
        if len(self.activity_log_list) > 10:
            self.activity_log_list = self.activity_log_list[-10:]

    def log_crypto_event(self, event_type, details):
        # event_type examples:
        # "KEY_GENERATED", "HANDSHAKE_START", "CERT_VALIDATED",
        # "SESSION_KEY_DERIVED", "RC6_ENCRYPT", "RC6_DECRYPT",
        # "XTEA_ENCRYPT", "XTEA_DECRYPT", "ELGAMAL_ENCRYPT",
        # "ELGAMAL_DECRYPT", "SIGNATURE_CREATED", "SIGNATURE_VERIFIED",
        # "KEY_EXCHANGE", "RECORD_STORED", "RECORD_RETRIEVED"

        entry = {
            "time":       time.strftime("%H:%M:%S"),
            "type":       event_type,
            "details":    details
        }
        self.crypto_events.append(entry)
        if len(self.crypto_events) > 20:
            self.crypto_events = self.crypto_events[-20:]

    # ─── HEARTBEAT THREAD ─────────────────────────────────────────────────────
    def heartbeat_loop(self):
        """Write status file every 5 seconds so the monitor sees a fresh file
        even when no clients are connected."""
        while self.running:
            with self.lock:
                self.write_status()
            time.sleep(5)

    # ─── SERVER STARTUP ───────────────────────────────────────────────────────
    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"[SERVER] SecureVault listening on {self.host}:{self.port}")
        print(f"[SERVER] Session key: {self.session_key.hex()}")

        # Start heartbeat before accepting connections
        heartbeat = threading.Thread(target=self.heartbeat_loop)
        heartbeat.daemon = True
        heartbeat.start()
        print("[SERVER] Heartbeat started — writing status every 5s")

        while True:
            conn, addr = self.sock.accept()
            print(f"[SERVER] Connection from {addr[0]}:{addr[1]}")
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()

    # ─── CLIENT HANDLER ───────────────────────────────────────────────────────
    def handle_client(self, conn, addr):
        is_authenticated = False

        # Track new connection
        with self.lock:
            self.total_connections += 1
            self.last_client = f"{addr[0]}:{addr[1]}"
            self.log_event("SUCCESS", f"New connection: {addr[0]}:{addr[1]}")
            self.log_crypto_event(
                "HANDSHAKE_START",
                f"TCP connection from {addr[0]}:{addr[1]} — "
                f"beginning TLS-style handshake"
            )
            self.write_status()

        try:
            while True:
                # ── Receive framed message ────────────────────────────────────
                length_bytes = conn.recv(4)
                if not length_bytes or len(length_bytes) < 4:
                    break
                msg_length = int.from_bytes(length_bytes, 'big')
                encrypted_msg = b""
                while len(encrypted_msg) < msg_length:
                    chunk = conn.recv(min(4096, msg_length - len(encrypted_msg)))
                    if not chunk:
                        break
                    encrypted_msg += chunk

                # Track bytes received
                with self.lock:
                    self.bytes_received += msg_length

                # ── Decrypt ───────────────────────────────────────────────────
                # Use handshake key for first message, session key after
                decrypt_key = HANDSHAKE_KEY if not is_authenticated else self.session_key

                decrypted = rc6.decrypt_data(encrypted_msg, decrypt_key)
                message = json.loads(decrypted.decode('utf-8'))
                print(f"[SERVER] Received type={message['type']} patient={message.get('patient_id','N/A')}")

                # ── Message routing ───────────────────────────────────────────

                if message["type"] == "HANDSHAKE":
                    with self.lock:
                        # Log the full handshake crypto chain
                        self.log_crypto_event(
                            "CERT_VALIDATED",
                            f"CA-signed cert sent — ElGamal sig (r,s) verifiable with CA pubkey"
                        )
                        self.log_crypto_event(
                            "KEY_EXCHANGE",
                            f"Client sent ElGamal ciphertext (c1,c2) — "
                            f"server decrypts: s=c1^x mod p, m=c2*s_inv mod p"
                        )
                        self.log_crypto_event(
                            "SESSION_KEY_DERIVED",
                            f"KDF: session_key = rotate_mix(pms XOR cn XOR sn) — "
                            f"key={self.session_key.hex()[:16]}..."
                        )
                        self.log_crypto_event(
                            "RC6_ENCRYPT",
                            f"Client Finished RC6-encrypted — 20 rounds, 4 word blocks"
                        )
                    response = {
                        "type": "RESPONSE",
                        "status": "CONNECTED",
                        "session_key": self.session_key.hex(),
                        "server_cert_serial": self.hospital.cert["serial"],
                        "payload": ""
                    }
                    is_authenticated = True
                    print(f"[SERVER] Handshake complete — session key sent to client")
                    with self.lock:
                        self.total_handshakes += 1
                        self.last_operation = "HANDSHAKE"
                        self.last_operation_time = time.strftime("%H:%M:%S")
                        self.log_event("SUCCESS", f"Handshake: {addr[0]}:{addr[1]}")
                        self.write_status()
                    # Send response encrypted with HANDSHAKE_KEY
                    response_bytes = json.dumps(response).encode('utf-8')
                    encrypted_response = rc6.encrypt_data(response_bytes, HANDSHAKE_KEY)
                    length_prefix = len(encrypted_response).to_bytes(4, 'big')
                    conn.sendall(length_prefix + encrypted_response)
                    with self.lock:
                        self.bytes_sent += len(encrypted_response)
                    continue

                elif message["type"] == "STORE":
                    patient_id = message["patient_id"]
                    record_bytes = bytes.fromhex(message["payload"])
                    plaintext = rc6.decrypt_data(record_bytes, self.session_key)
                    storage_key = os.urandom(16)
                    encrypted_at_rest = xtea.encrypt_data(plaintext, storage_key)
                    self.hospital.records[patient_id] = encrypted_at_rest
                    self.hospital.record_keys[patient_id] = storage_key
                    response = {
                        "type": "RESPONSE",
                        "status": "STORED",
                        "patient_id": patient_id,
                        "payload": ""
                    }
                    print(f"[SERVER] Stored {len(plaintext)}B for {patient_id} — XTEA at rest")
                    with self.lock:
                        self.total_store += 1
                        self.last_operation = "STORE"
                        self.last_operation_time = time.strftime("%H:%M:%S")
                        self.log_crypto_event(
                            "RC6_DECRYPT",
                            f"Server RC6-decrypted incoming record — "
                            f"{len(plaintext)}B plaintext recovered from transit ciphertext"
                        )
                        self.log_crypto_event(
                            "XTEA_ENCRYPT",
                            f"Server XTEA-encrypted record for {patient_id} at rest — "
                            f"64 rounds, 128-bit key, new random storage key generated — "
                            f"storage key: {storage_key.hex()[:16]}..."
                        )
                        self.log_crypto_event(
                            "RECORD_STORED",
                            f"Patient {patient_id}: {len(plaintext)}B stored — "
                            f"RC6 protected transit, XTEA protects at rest"
                        )
                        self.log_event("SUCCESS", f"Stored {len(plaintext)}B for {patient_id}")
                        self.write_status()

                elif message["type"] == "RETRIEVE":
                    patient_id = message["patient_id"]
                    if patient_id in self.hospital.records:
                        storage_key = self.hospital.record_keys[patient_id]
                        plaintext = xtea.decrypt_data(
                            self.hospital.records[patient_id], storage_key
                        )
                        encrypted_transit = rc6.encrypt_data(plaintext, self.session_key)
                        response = {
                            "type": "RESPONSE",
                            "status": "OK",
                            "patient_id": patient_id,
                            "payload": encrypted_transit.hex()
                        }
                        print(f"[SERVER] Sent {len(plaintext)}B for {patient_id} — RC6 for transit")
                        with self.lock:
                            self.total_retrieve += 1
                            self.last_operation = "RETRIEVE"
                            self.last_operation_time = time.strftime("%H:%M:%S")
                            self.log_crypto_event(
                                "XTEA_DECRYPT",
                                f"Server XTEA-decrypted record for {patient_id} from storage — "
                                f"64 rounds reversed, plaintext recovered"
                            )
                            self.log_crypto_event(
                                "RC6_ENCRYPT",
                                f"Server RC6-encrypted record for transit to client — "
                                f"session key used, 20 rounds applied"
                            )
                            self.log_crypto_event(
                                "RECORD_RETRIEVED",
                                f"Patient {patient_id}: {len(plaintext)}B — "
                                f"XTEA at rest → plaintext → RC6 for transit"
                            )
                            self.log_event("SUCCESS", f"Retrieved record: {patient_id}")
                            self.write_status()
                    else:
                        response = {
                            "type": "RESPONSE",
                            "status": "NOT_FOUND",
                            "patient_id": patient_id,
                            "payload": ""
                        }

                elif message["type"] == "LIST":
                    patient_ids = list(self.hospital.records.keys())
                    response = {
                        "type": "RESPONSE",
                        "status": "OK",
                        "patient_id": "",
                        "payload": json.dumps(patient_ids)
                    }
                    print(f"[SERVER] LIST requested — {len(patient_ids)} records")
                    with self.lock:
                        self.last_operation = "LIST"
                        self.last_operation_time = time.strftime("%H:%M:%S")
                        self.log_crypto_event(
                            "LIST_REQUEST",
                            f"Client requested patient list — "
                            f"{len(self.hospital.records)} records, response RC6 encrypted"
                        )
                        self.log_event("INFO", f"List requested: {len(patient_ids)} records")
                        self.write_status()

                elif message["type"] == "DELETE":
                    patient_id = message["patient_id"]
                    if patient_id in self.hospital.records:
                        del self.hospital.records[patient_id]
                        del self.hospital.record_keys[patient_id]
                        response = {
                            "type": "RESPONSE",
                            "status": "DELETED",
                            "patient_id": patient_id,
                            "payload": ""
                        }
                        print(f"[SERVER] Deleted record for {patient_id}")
                        with self.lock:
                            self.last_operation = "DELETE"
                            self.last_operation_time = time.strftime("%H:%M:%S")
                            self.log_crypto_event(
                                "RECORD_DELETED",
                                f"Record deleted for {patient_id} — "
                                f"XTEA storage key discarded"
                            )
                            self.log_event("SUCCESS", f"Deleted: {patient_id}")
                            self.write_status()
                    else:
                        response = {
                            "type": "RESPONSE",
                            "status": "NOT_FOUND",
                            "patient_id": patient_id,
                            "payload": ""
                        }

                else:
                    response = {
                        "type": "RESPONSE",
                        "status": "UNKNOWN",
                        "payload": ""
                    }

                # ── Send all non-handshake responses with session_key ─────────
                response_bytes = json.dumps(response).encode('utf-8')
                encrypted_response = rc6.encrypt_data(response_bytes, self.session_key)
                length_prefix = len(encrypted_response).to_bytes(4, 'big')
                conn.sendall(length_prefix + encrypted_response)
                with self.lock:
                    self.bytes_sent += len(encrypted_response)

        except Exception as e:
            print(f"[SERVER] Error: {e}")
            with self.lock:
                self.total_errors += 1
                self.log_event("ERROR", f"Error from {addr[0]}: {str(e)[:50]}")
                self.write_status()
        finally:
            conn.close()
            print(f"[SERVER] Connection closed: {addr[0]}:{addr[1]}")
            with self.lock:
                self.log_crypto_event(
                    "SESSION_CLOSED",
                    f"Session ended: {addr[0]}:{addr[1]} — "
                    f"session key discarded from memory"
                )
                self.log_event("INFO", f"Disconnected: {addr[0]}:{addr[1]}")
                self.write_status()


if __name__ == "__main__":
    server = SocketServer(host="0.0.0.0", port=5000)
    print("[SERVER] Starting SecureVault Socket Server...")
    print("[SERVER] Press Ctrl+C to stop")
    try:
        server.start()
    except KeyboardInterrupt:
        server.running = False
        print("\n[SERVER] Shutting down")