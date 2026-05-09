import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

# Import all the custom-built cryptography modules
import elgamal
import rc6
import xtea
import ca
import server
import client

# Import the specific classes needed for the demonstration
from ca import CertificateAuthority
from server import HospitalServer
from client import DoctorClient, PatientClient

def section(title):
    """Helper function to print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"  {title.upper()}")
    print(f"{'='*60}")

if __name__ == "__main__":
   
    section("SECUREVAULT MEDICAL RECORDS SYSTEM — FULL DEMO")
   
    # [1] CA SETUP: The root of trust for the entire system.
    section("1. Certificate Authority Setup")
    ca_inst = CertificateAuthority()
   
    # [2] SERVER SETUP: The hospital server comes online and gets its identity certificate from the CA.
    section("2. Hospital Server Setup")
    hospital = HospitalServer(ca_inst)
   
    # [3] USER REGISTRATION: Doctors and patients register, generating their own keypairs and receiving certificates.
    section("3. User Registration")
    dr_alice = DoctorClient("Dr_Alice", ca_inst)
    dr_bob   = DoctorClient("Dr_Bob",   ca_inst)
    patient_john = PatientClient("John_Smith", ca_inst)
    print("\n3 users registered with CA-signed certificates.")
   
    # [4] TLS HANDSHAKE: Dr. Alice establishes a secure, encrypted session with the server.
    section("4. TLS-Style Handshake")
    dr_alice.connect_to_server(hospital)
   
    # [5] PATIENT UPLOADS RECORD: A patient record is created and uploaded to the server over the secure channel.
    section("5. Patient Record Upload")
    record_text = (
        "PATIENT: John Smith\n"
        "DOB: 1985-03-14\n"
        "BLOOD TYPE: A+\n"
        "DIAGNOSIS: Type 2 Diabetes\n"
        "HbA1c: 7.8%\n"
        "MEDICATION: Metformin 500mg twice daily\n"
        "ALLERGIES: Penicillin\n"
        "LAST VISIT: 2025-01-15\n"
        "NOTES: Patient responding well to treatment"
    )
    # In this demo, the patient uploads their record using the doctor's secure session.
    patient_id = patient_john.upload_own_record(
        hospital, record_text, dr_alice.session_key
    )
    print(f"Record stored on server under ID: {patient_id}")
    print("Storage Security: Data is now encrypted with XTEA at rest inside the server.")
   
    # [6] DOCTOR RETRIEVES RECORD: Dr. Alice downloads the record, which is re-encrypted for transit.
    section("6. Doctor Record Retrieval")
    retrieved_package = dr_alice.download_record(hospital, patient_id)
    # The doctor's client would normally handle signature verification internally.
    # Here, we manually check if the original text is contained in the retrieved package.
    # Note: The retrieved package may contain signature metadata.
    match = record_text in retrieved_package
    print(f"Data integrity check: {'VERIFIED' if match else 'FAILED'}")
    print("Transport Security: Data was encrypted with RC6 in transit.")
   
    # [7] DIGITAL SIGNATURE: A standalone demonstration of signing a document with a user's private key.
    section("7. Digital Signature Demo")
    test_doc = b"DIAGNOSIS CONFIRMED: Metformin prescribed by Dr_Alice"
    r, s = elgamal.sign(test_doc, dr_alice.x, dr_alice.p, dr_alice.g)
    valid = elgamal.verify(test_doc, r, s, dr_alice.y, dr_alice.p, dr_alice.g)
    print(f"Signature on original diagnosis: {'VALID' if valid else 'INVALID'}")
    
    # Attempt to verify the signature against a tampered document.
    tampered = test_doc + b" [TAMPERED]"
    bad = elgamal.verify(tampered, r, s, dr_alice.y, dr_alice.p, dr_alice.g)
    print(f"Signature on tampered diagnosis: {'VALID (DANGEROUS!)' if bad else 'CORRECTLY REJECTED'}")
   
    # [8] KEY ROTATION: The server rotates its primary keypair and gets a new certificate.
    section("8. Server Key Rotation")
    old_serial = hospital.cert['serial']
    hospital.rotate_server_keys()
    print(f"Server key rotation complete. Old cert: #{old_serial} -> New cert: #{hospital.cert['serial']}")
   
    # [9] CERTIFICATE REVOCATION: The CA revokes Dr. Bob's certificate, making it invalid.
    section("9. Certificate Revocation")
    ca_inst.revoke_certificate(dr_bob.cert['serial'])
    valid_r, reason_r = ca_inst.validate_certificate(dr_bob.cert)
    print(f"Dr. Bob's certificate status after revocation: {reason_r}")
   
    # [10] STATS: Display final statistics from the server's key manager.
    section("10. System Statistics")
    stats = hospital.get_stats()
    print(f"Total patients with records: {stats['patients_stored']}")
    print(f"Total secure connections made:  {stats['total_connections']}")
   
    section("SECUREVAULT DEMONSTRATION COMPLETE")
