import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
# Import all the high-level components of the SecureVault system
from ca import CertificateAuthority
from server import HospitalServer
from client import DoctorClient, PatientClient

# Import the underlying cryptographic modules
import elgamal
import rc6
import xtea

def run_test(name, func):
    """
    A simple test runner that executes a function, catches any exceptions,
    and prints a clear PASSED or FAILED status.
    """
    try:
        func()
        print(f"  {name}: PASSED")
        return True
    except Exception as e:
        print(f"  {name}: FAILED — {e}")
        return False

def test_ca_lifecycle():
    """Tests the full lifecycle of a certificate: issue, validate, revoke."""
    ca = CertificateAuthority()
    p1, g1, x1, y1 = elgamal.generate_keypair()
    cert = ca.issue_certificate("test_user", "doctor", p1, g1, y1)
    
    # 1. Test validation of a new cert
    valid, reason = ca.validate_certificate(cert)
    assert valid and reason == "VALID"
    
    # 2. Test revocation
    ca.revoke_certificate(cert["serial"])
    valid2, reason2 = ca.validate_certificate(cert)
    assert not valid2 and reason2 == "REVOKED"
    
    # 3. Test that serial numbers are sequential
    serials = []
    for i in range(5):
        p_, g_, x_, y_ = elgamal.generate_keypair()
        c = ca.issue_certificate(f"user{i}", "patient", p_, g_, y_)
        serials.append(c["serial"])
    assert serials == sorted(list(set(serials))), "Serial numbers are not unique and sequential"

def test_handshake_completes():
    """Ensures the TLS-style handshake runs to completion without errors."""
    from handshake import perform_handshake # Local import to avoid circular dependency issues
    ca = CertificateAuthority()
    hosp = HospitalServer(ca)
    p1, g1, x1, y1 = elgamal.generate_keypair()
    cert_doc = ca.issue_certificate("test_doc", "doctor", p1, g1, y1)
    
    sk, cipher = perform_handshake("test_doc", cert_doc, x1, hosp.cert, hosp.x, ca)
    assert len(sk) == 16, "Session key should be 16 bytes"
    assert cipher == "RC6", "Handshake should select RC6 as the cipher"

def test_record_store_retrieve():
    """Tests the end-to-end flow of storing and retrieving a record."""
    ca = CertificateAuthority()
    hosp = HospitalServer(ca)
    dr = DoctorClient("test_dr", ca)
    dr.connect_to_server(hosp)
    
    record = "PATIENT: Test\nDIAGNOSIS: Integration test"
    patient_id = "patient_test_001"
    
    # Client encrypts and server stores
    encrypted_for_transit = rc6.encrypt_data(record.encode(), dr.session_key)
    hosp.store_record(patient_id, encrypted_for_transit, dr.session_key)
    
    # Check that the record exists and is encrypted at rest
    assert patient_id in hosp.records
    assert hosp.records[patient_id] != record.encode()
    
    # Server retrieves and client decrypts
    transit_from_server = hosp.retrieve_record(patient_id, dr.session_key)
    recovered = rc6.decrypt_data(transit_from_server, dr.session_key).decode()
    assert record in recovered, "Recovered data does not match original"

def test_encryption_layers():
    """Verifies that different ciphers produce different, non-plaintext results."""
    key = b"SECUREVAULT12345"
    pt = os.urandom(32)
    ct_rc6  = rc6.encrypt_data(pt, key)
    ct_xtea = xtea.encrypt_data(pt, key)
    
    assert ct_rc6  != pt, "RC6 ciphertext is same as plaintext"
    assert ct_xtea != pt, "XTEA ciphertext is same as plaintext"
    assert ct_rc6  != ct_xtea, "RC6 and XTEA produced identical ciphertext"

def test_signature_workflow():
    """Tests the ElGamal sign/verify workflow, including failure cases."""
    p, g, x, y = elgamal.generate_keypair()
    doc = b"SIGNED DOCUMENT CONTENT"
    
    # 1. Test valid signature
    r, s = elgamal.sign(doc, x, p, g)
    assert elgamal.verify(doc, r, s, y, p, g), "Valid signature failed to verify"
    
    # 2. Test tampered document
    assert not elgamal.verify(doc + b"X", r, s, y, p, g), "Tampered document was accepted"
    
    # 3. Test signature from a different key
    p2, g2, x2, y2 = elgamal.generate_keypair()
    r2, s2 = elgamal.sign(doc, x2, p2, g2)
    assert not elgamal.verify(doc, r2, s2, y, p, g), "Signature from wrong key was accepted"

def test_key_rotation():
    """Tests that server can rotate its keys and still function."""
    ca = CertificateAuthority()
    hosp = HospitalServer(ca)
    dr = DoctorClient("rot_dr", ca)
    dr.connect_to_server(hosp)
    
    record = "ROTATION TEST RECORD"
    encrypted = rc6.encrypt_data(record.encode(), dr.session_key)
    hosp.store_record("patient_rot", encrypted, dr.session_key)
    
    old_serial = hosp.cert["serial"]
    hosp.rotate_server_keys()
    assert hosp.cert["serial"] != old_serial, "Server certificate serial did not change after rotation"
    
    # The old session key is still valid for retrieving the record.
    transit = hosp.retrieve_record("patient_rot", dr.session_key)
    recovered = rc6.decrypt_data(transit, dr.session_key).decode()
    assert record in recovered, "Failed to retrieve record after server key rotation"

def test_wrong_key_fails():
    """Tests that decrypting symmetric crypto with the wrong key fails."""
    key_a = os.urandom(16)
    key_b = os.urandom(16)
    pt = os.urandom(48)
    ct = rc6.encrypt_data(pt, key_a)
    try:
        rt = rc6.decrypt_data(ct, key_b)
        assert rt != pt, "Decrypting with wrong key produced original plaintext"
    except ValueError:
        # A ValueError from padding is the expected failure mode.
        pass
    except Exception as e:
        raise Exception(f"Expected ValueError on wrong key, but got {type(e).__name__}")

def test_revoked_cert_rejected():
    """Ensures the CA correctly identifies a revoked certificate."""
    ca = CertificateAuthority()
    p1, g1, x1, y1 = elgamal.generate_keypair()
    cert = ca.issue_certificate("revoke_test", "doctor", p1, g1, y1)
    ca.revoke_certificate(cert["serial"])
    
    valid, reason = ca.validate_certificate(cert)
    assert not valid, "Revoked certificate was considered valid"
    assert reason == "REVOKED", "Reason for invalidity was not 'REVOKED'"

if __name__ == "__main__":
    print("Running integration tests...\n")
    tests = [
        ("CA lifecycle",           test_ca_lifecycle),
        ("Handshake completes",    test_handshake_completes),
        ("Record store/retrieve",  test_record_store_retrieve),
        ("Encryption layers",      test_encryption_layers),
        ("Signature workflow",     test_signature_workflow),
        ("Key rotation",           test_key_rotation),
        ("Wrong key fails",        test_wrong_key_fails),
        ("Revoked cert rejected",  test_revoked_cert_rejected),
    ]
    passed_count = sum(run_test(name, func) for name, func in tests)
    
    print("-" * 30)
    print(f"Integration tests: {passed_count}/{len(tests)} passed")
    
    if passed_count == len(tests):
        print("All integration tests completed successfully!")
    else:
        print("Some integration tests failed.")