import socket
import threading
import os
import sys
import json

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

    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"[SERVER] SecureVault listening on {self.host}:{self.port}")
        print(f"[SERVER] Session key: {self.session_key.hex()}")
        while True:
            conn, addr = self.sock.accept()
            print(f"[SERVER] Connection from {addr[0]}:{addr[1]}")
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def handle_client(self, conn, addr):
        is_authenticated = False
        try:
            while True:
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
                
                # Use handshake key for first message, session key after
                decrypt_key = HANDSHAKE_KEY if not is_authenticated else self.session_key
                
                decrypted = rc6.decrypt_data(encrypted_msg, decrypt_key)
                message = json.loads(decrypted.decode('utf-8'))
                print(f"[SERVER] Received type={message['type']} patient={message.get('patient_id','N/A')}")
                
                if message["type"] == "HANDSHAKE":
                    response = {
                        "type": "RESPONSE",
                        "status": "CONNECTED",
                        "session_key": self.session_key.hex(),
                        "server_cert_serial": self.hospital.cert["serial"],
                        "payload": ""
                    }
                    is_authenticated = True
                    print(f"[SERVER] Handshake complete — session key sent to client")
                    # Send response encrypted with HANDSHAKE_KEY
                    response_bytes = json.dumps(response).encode('utf-8')
                    encrypted_response = rc6.encrypt_data(response_bytes, HANDSHAKE_KEY)
                    length_prefix = len(encrypted_response).to_bytes(4, 'big')
                    conn.sendall(length_prefix + encrypted_response)
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
                
                # Send all non-handshake responses with session_key
                response_bytes = json.dumps(response).encode('utf-8')
                encrypted_response = rc6.encrypt_data(response_bytes, self.session_key)
                length_prefix = len(encrypted_response).to_bytes(4, 'big')
                conn.sendall(length_prefix + encrypted_response)
        
        except Exception as e:
            print(f"[SERVER] Error: {e}")
        finally:
            conn.close()
            print(f"[SERVER] Connection closed: {addr[0]}:{addr[1]}")

if __name__ == "__main__":
    server = SocketServer(host="0.0.0.0", port=5000)
    print("[SERVER] Starting SecureVault Socket Server...")
    print("[SERVER] Press Ctrl+C to stop")
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down")