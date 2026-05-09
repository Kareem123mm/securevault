import socket
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import rc6
import xtea
import elgamal

class SocketClient:

    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.session_key = None
        self.sock = None

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
        return response["status"] == "STORED"

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
            return text
        print(f"[CLIENT] Retrieve failed: {response['status']}")
        return None

    def close(self):
        if self.sock:
            self.sock.close()
            print("[CLIENT] Connection closed")

if __name__ == "__main__":
    client = SocketClient(host="127.0.0.1", port=5000)

    print("="*55)
    print("  SECUREVAULT SOCKET CLIENT DEMO")
    print("="*55)

    client.connect()

    print("\n[STEP 1] Performing handshake...")
    client.handshake()

    print("\n[STEP 2] Storing encrypted patient record...")
    record = (
        "PATIENT: John Smith\n"
        "DOB: 1985-03-14\n"
        "BLOOD TYPE: A+\n"
        "DIAGNOSIS: Type 2 Diabetes\n"
        "MEDICATION: Metformin 500mg\n"
        "NOTES: Transmitted over real TCP socket — encrypted RC6"
    )
    success = client.store_record("patient_john_smith", record)
    print(f"Store success: {success}")

    print("\n[STEP 3] Retrieving record from server...")
    retrieved = client.retrieve_record("patient_john_smith")

    print("\n[STEP 4] Verifying data integrity...")
    if retrieved and record in retrieved:
        print("[CLIENT] DATA INTEGRITY: VERIFIED — plaintext matches")
    else:
        print("[CLIENT] DATA INTEGRITY: CHECK MANUALLY")

    print("\n[STEP 5] Connection summary:")
    print(f"  Host: 127.0.0.1:5000")
    print(f"  Session key: {client.session_key.hex()}")
    print(f"  Cipher used: RC6 (transit) + XTEA (at rest on server)")

    client.close()
    print("\nSocket demo complete.")
