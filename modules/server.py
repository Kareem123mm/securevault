import elgamal
import rc6
import xtea
import time

# Import specific classes and functions from other modules in the project
from key_manager import KeyManager
from handshake import perform_handshake
from ca import CertificateAuthority

class HospitalServer:
    """
    Simulates a hospital server that manages patient records, using a secure
    handshake to establish communication and different ciphers for data in
    transit vs. data at rest.
    """

    def __init__(self, ca_instance: CertificateAuthority):
        """
        Initializes the server, generates its own cryptographic identity, and
        gets a certificate from the provided Certificate Authority.
        """
        print("[SERVER] Initializing...")
        self.p, self.g, self.x, self.y = elgamal.generate_keypair()
        self.cert = ca_instance.issue_certificate(
            "hospital_server", "server", self.p, self.g, self.y
        )
        self.ca = ca_instance
        self.records = {}
        self.record_keys = {}
        self.key_mgr = KeyManager()
        self.session_log = []
        print(f"[SERVER] Hospital Server online. Certificate #{self.cert['serial']} issued.")

    def get_certificate(self):
        """Returns the server's current public certificate."""
        return self.cert

    def connect(self, client_cert, client_name, client_x):
        """
        Performs a handshake with a client to establish a secure session.
        
        Returns:
            The derived session key for secure communication.
        """
        session_key, cipher = perform_handshake(
            client_name, client_cert, client_x,
            self.cert, self.x, self.ca
        )
        # Log the session internally
        kid, _ = self.key_mgr.generate_session_key(client_name)
        self.session_log.append({
            "client": client_name,
            "timestamp": time.time(),
            "session_key_id": kid
        })
        return session_key

    def store_record(self, patient_id, rc6_encrypted_data, session_key):
        """
        Receives an encrypted record, decrypts it, and re-encrypts it for
        secure storage at rest.
        - Data in transit is assumed to be RC6 encrypted.
        - Data at rest is stored with XTEA encryption.
        """
        # Decrypt incoming RC6-encrypted data from the client
        plaintext = rc6.decrypt_data(rc6_encrypted_data, session_key)
        
        # Re-encrypt with XTEA for storage at rest using a dedicated key
        storage_kid, storage_key = self.key_mgr.generate_session_key(patient_id)
        encrypted_at_rest = xtea.encrypt_data(plaintext, storage_key)
        
        self.records[patient_id] = encrypted_at_rest
        self.record_keys[patient_id] = storage_key
        print(f"[SERVER] Stored record for {patient_id}: {len(plaintext)}B plaintext -> XTEA at rest")

    def retrieve_record(self, patient_id, session_key):
        """
        Retrieves a stored record, decrypts it from its at-rest format,
        and re-encrypts it for secure transit back to the client.
        """
        if patient_id not in self.records:
            raise KeyError(f"No record found for patient ID {patient_id}")
            
        # Decrypt from XTEA storage using the patient's dedicated storage key
        storage_key = self.record_keys[patient_id]
        plaintext = xtea.decrypt_data(self.records[patient_id], storage_key)
        
        # Re-encrypt with RC6 for transit using the current session key
        encrypted_transit = rc6.encrypt_data(plaintext, session_key)
        print(f"[SERVER] Sending record for {patient_id}: XTEA->plaintext->RC6 for transit")
        return encrypted_transit

    def rotate_server_keys(self):
        """
        Rotates the server's main ElGamal keypair and gets a new certificate.
        """
        print("[SERVER] Rotating server's master ElGamal keypair and certificate...")
        self.p, self.g, self.x, self.y = elgamal.generate_keypair()
        self.cert = self.ca.issue_certificate(
            "hospital_server", "server", self.p, self.g, self.y
        )
        print(f"[SERVER] Keys rotated. New certificate #{self.cert['serial']} is now active.")

    def list_patients(self):
        """Returns a list of patient IDs with stored records."""
        return list(self.records.keys())

    def get_stats(self):
        """Returns a summary of the server's current state."""
        summary = self.key_mgr.get_summary()
        return {
            "patients_stored": len(self.records),
            "total_connections": len(self.session_log),
            "key_summary": summary
        }