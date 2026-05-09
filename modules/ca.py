import elgamal
import time
import json

class CertificateAuthority:
    """
    A simple Certificate Authority (CA) for issuing and validating digital
    certificates using the ElGamal signature scheme.
    """

    def __init__(self):
        """
        Initializes the CA by generating its own master keypair and setting up
        storage for issued and revoked certificates.
        """
        print("Initializing Certificate Authority...")
        self.p, self.g, self.x, self.y = elgamal.generate_keypair()
        self.serial_counter = 1
        self.issued_certs = {}
        self.revoked_serials = set()
        print(f"CA initialized. Public key y starts with: {str(self.y)[:20]}...")

    def _cert_to_bytes(self, cert):
        """
        Creates a canonical byte representation of a certificate for signing.
        This ensures that the byte stream is identical during issuance and validation.
        """
        # The string includes the core, immutable fields of the certificate.
        s = f"{cert['serial']}|{cert['owner']}|{cert['role']}|{cert['public_key']['y']}"
        return s.encode('utf-8')

    def issue_certificate(self, owner, role, owner_p, owner_g, owner_y):
        """
        Issues a new digital certificate, signs it with the CA's private key,
        and stores it.

        Returns:
            A dictionary representing the signed certificate.
        """
        cert = {
            "serial": self.serial_counter,
            "owner": owner,
            "role": role,
            "public_key": {"p": owner_p, "g": owner_g, "y": owner_y},
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        
        # Get the canonical bytes to be signed.
        cert_bytes = self._cert_to_bytes(cert)
        
        # Sign the certificate bytes with the CA's private key.
        r, s = elgamal.sign(cert_bytes, self.x, self.p, self.g)
        
        # Attach the signature to the certificate.
        cert["signature_r"] = r
        cert["signature_s"] = s
        
        # Store and update internal state.
        self.issued_certs[self.serial_counter] = cert
        self.serial_counter += 1
        
        print(f"CA issued certificate #{cert['serial']} to {owner} ({role})")
        return cert

    def validate_certificate(self, cert):
        """
        Validates a certificate by checking its revocation status and verifying
        its digital signature against the CA's public key.

        Returns:
            A tuple (bool, str) indicating validity and the reason.
        """
        serial = cert.get("serial")
        if serial in self.revoked_serials:
            return False, "REVOKED"
        
        # Re-create the part of the certificate that was originally signed.
        cert_check = {
            "serial": cert["serial"],
            "owner": cert["owner"],
            "role": cert["role"],
            "public_key": cert["public_key"]
        }
        cert_bytes = self._cert_to_bytes(cert_check)
        
        # Verify the signature using the CA's public key.
        valid = elgamal.verify(
            cert_bytes,
            cert["signature_r"],
            cert["signature_s"],
            self.y, self.p, self.g
        )
        
        if not valid:
            return False, "INVALID SIGNATURE"
            
        return True, "VALID"

    def revoke_certificate(self, serial):
        """
        Revokes a certificate by adding its serial number to the revocation list.
        """
        self.revoked_serials.add(serial)
        print(f"Certificate #{serial} REVOKED")

    def is_revoked(self, serial):
        """Checks if a certificate serial number is in the revocation list."""
        return serial in self.revoked_serials

    def get_public_key(self):
        """Returns the CA's public key components."""
        return {"p": self.p, "g": self.g, "y": self.y}

if __name__ == "__main__":
    # --- DEMO ---
    
    # 1. Initialize the Certificate Authority
    ca = CertificateAuthority()
    
    # 2. Create keypairs for two entities: Alice (a doctor) and a hospital server.
    print("\nGenerating keypairs for Alice and Hospital Server...")
    p1, g1, x1, y1 = elgamal.generate_keypair()
    p2, g2, x2, y2 = elgamal.generate_keypair()
    
    # 3. CA issues certificates to both entities.
    cert_alice = ca.issue_certificate("dr_alice", "doctor", p1, g1, y1)
    cert_server = ca.issue_certificate("hospital_server", "server", p2, g2, y2)
    
    # 4. Validate the freshly issued certificates.
    print("\nValidating certificates...")
    valid, reason = ca.validate_certificate(cert_alice)
    print(f"Alice cert: {reason}")
    valid2, reason2 = ca.validate_certificate(cert_server)
    print(f"Server cert: {reason2}")
    
    # 5. Revoke Alice's certificate and re-validate.
    print("\nRevoking Alice's certificate...")
    ca.revoke_certificate(cert_alice["serial"])
    valid3, reason3 = ca.validate_certificate(cert_alice)
    print(f"Alice after revoke: {reason3}  (expected REVOKED)")
    
    # 6. Tamper with the server's certificate and try to validate it.
    print("\nTesting a tampered certificate...")
    tampered = dict(cert_server)
    tampered["owner"] = "hacker" # Change the owner field
    valid4, reason4 = ca.validate_certificate(tampered)
    print(f"Tampered cert: {reason4}  (expected INVALID SIGNATURE)")