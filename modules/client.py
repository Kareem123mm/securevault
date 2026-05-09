import elgamal
import rc6

# Import the derive_session_key function, which is defined in handshake.py
# This function is used by both client and server to derive the same session key.
from handshake import derive_session_key

class DoctorClient:
    """
    Represents a doctor interacting with the hospital system. A doctor can
    connect to the server, and then upload and download patient records.
    Uploaded records are digitally signed by the doctor.
    """

    def __init__(self, name, ca_instance):
        """
        Initializes the doctor client, generating a unique cryptographic identity
        and obtaining a certificate from the Certificate Authority.
        """
        self.name = name
        self.p, self.g, self.x, self.y = elgamal.generate_keypair()
        self.cert = ca_instance.issue_certificate(name, "doctor", self.p, self.g, self.y)
        self.session_key = None
        print(f"[DOCTOR] {name} registered. Certificate #{self.cert['serial']} issued.")

    def connect_to_server(self, server_instance):
        """
        Establishes a secure session with the server by performing a handshake.
        """
        print(f"[DOCTOR] {self.name} attempting to connect to server...")
        self.session_key = server_instance.connect(
            self.cert, self.name, self.x
        )
        print(f"[DOCTOR] {self.name} session established successfully.")

    def upload_record(self, server, patient_id, plaintext_text):
        """
        Signs and encrypts a patient record before uploading it to the server.
        """
        if self.session_key is None:
            raise Exception("Not connected — call connect_to_server first")
        
        plaintext_bytes = plaintext_text.encode('utf-8')
        
        # Sign the plaintext record with the doctor's private ElGamal key
        r, s = elgamal.sign(plaintext_bytes, self.x, self.p, self.g)
        
        # Append signature as metadata to the plaintext before encryption
        package = plaintext_bytes + f"|SIG_R:{r}|SIG_S:{s}".encode()
        
        # Encrypt the entire package (plaintext + signature) with RC6 for transit
        encrypted = rc6.encrypt_data(package, self.session_key)
        
        # Send the encrypted package to the server
        server.store_record(patient_id, encrypted, self.session_key)
        print(f"[DOCTOR] Uploaded record for {patient_id} — signed + RC6 encrypted")

    def download_record(self, server, patient_id):
        """
        Downloads and decrypts a patient record from the server.
        """
        if self.session_key is None:
            raise Exception("Not connected — call connect_to_server first")
            
        # Retrieve the RC6-encrypted record from the server
        encrypted_transit = server.retrieve_record(patient_id, self.session_key)
        
        # Decrypt the record using the current session key
        plaintext_package = rc6.decrypt_data(encrypted_transit, self.session_key)
        
        text = plaintext_package.decode('utf-8')
        print(f"[DOCTOR] Downloaded and decrypted record for {patient_id}")
        
        # Display a preview of the downloaded content
        preview = text[:120].replace('\n', ' ')
        print(f"[DOCTOR] Preview: {preview}...")
        return text

class PatientClient:
    """
    Represents a patient interacting with the hospital system. A patient can
    upload their own records but has more limited capabilities than a doctor.
    """

    def __init__(self, name, ca_instance):
        """
        Initializes the patient client and gets a certificate.
        """
        self.name = name
        self.p, self.g, self.x, self.y = elgamal.generate_keypair()
        self.cert = ca_instance.issue_certificate(name, "patient", self.p, self.g, self.y)
        print(f"[PATIENT] {name} registered. Certificate #{self.cert['serial']} issued.")

    def upload_own_record(self, server, plaintext_text, session_key):
        """
        Encrypts and uploads a record for this patient.
        This simplified method assumes a session key is already established.
        """
        patient_id = f"patient_{self.name.lower().replace(' ', '_')}"
        
        # Encrypt the record with RC6 for transit
        encrypted = rc6.encrypt_data(plaintext_text.encode('utf-8'), session_key)
        
        # Send the encrypted data to the server
        server.store_record(patient_id, encrypted, session_key)
        print(f"[PATIENT] {self.name} uploaded a new record as {patient_id}")
        return patient_id