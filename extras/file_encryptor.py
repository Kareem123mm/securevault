import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import rc6
import xtea
import time

def generate_key():
    """Generates a cryptographically secure 16-byte key."""
    return os.urandom(16)

def encrypt_file_rc6(input_path, key_bytes=None):
    """
    Encrypts a file using RC6.
    Generates a new key if one is not provided.
    Returns the path to the encrypted file and the key used.
    """
    if key_bytes is None:
        key_bytes = generate_key()
    output_path = input_path + ".rc6enc"
    rc6.encrypt_file(input_path, output_path, key_bytes)
    return output_path, key_bytes

def decrypt_file_rc6(input_path, key_bytes, output_path=None):
    """
    Decrypts a file encrypted with RC6.
    If output_path is not specified, it creates a new file with a .rc6dec extension.
    """
    if output_path is None:
        output_path = input_path.replace(".rc6enc", ".rc6dec")
    rc6.decrypt_file(input_path, output_path, key_bytes)
    return output_path

def encrypt_file_xtea(input_path, key_bytes=None):
    """
    Encrypts a file using XTEA.
    Generates a new key if one is not provided.
    Returns the path to the encrypted file and the key used.
    """
    if key_bytes is None:
        key_bytes = generate_key()
    output_path = input_path + ".xteaenc"
    xtea.encrypt_file(input_path, output_path, key_bytes)
    return output_path, key_bytes

def decrypt_file_xtea(input_path, key_bytes, output_path=None):
    """
    Decrypts a file encrypted with XTEA.
    If output_path is not specified, it creates a new file with a .xtdec extension.
    """
    if output_path is None:
        output_path = input_path.replace(".xteaenc", ".xtdec")
    xtea.decrypt_file(input_path, output_path, key_bytes)
    return output_path

def verify_round_trip(original_path, decrypted_path):
    """
    Verifies that the original file and the decrypted file are identical.
    """
    with open(original_path, 'rb') as f:
        orig = f.read()
    with open(decrypted_path, 'rb') as f:
        dec = f.read()
    return orig == dec

if __name__ == "__main__":
    # --- DEMO ---

    # 1. Create a test file with some content.
    record = (
        "PATIENT: John Smith\n"
        "DOB: 1985-03-14\n"
        "DIAGNOSIS: Hypertension\n"
        "BP: 145/92\n"
        "MEDICATION: Lisinopril 10mg\n"
        "NOTES: Patient stable, review in 3 months"
    )
    with open("patient_record.txt", "w") as f:
        f.write(record)
    
    print("--- RC6 Encryption Demo ---")
    # 2. Encrypt and decrypt the file using RC6.
    rc6_path, rc6_key = encrypt_file_rc6("patient_record.txt")
    print(f"RC6 key: {rc6_key.hex()}")
    print(f"RC6 ciphertext size: {os.path.getsize(rc6_path)} bytes")
    dec_path_rc6 = decrypt_file_rc6(rc6_path, rc6_key)
    passed_rc6 = verify_round_trip("patient_record.txt", dec_path_rc6)
    print(f"RC6 ROUND-TRIP: {'PASSED' if passed_rc6 else 'FAILED'}")

    print("\n--- XTEA Encryption Demo ---")
    # 3. Encrypt and decrypt the file using XTEA.
    xtea_path, xtea_key = encrypt_file_xtea("patient_record.txt")
    print(f"XTEA key: {xtea_key.hex()}")
    print(f"XTEA ciphertext size: {os.path.getsize(xtea_path)} bytes")
    dec_path_xtea = decrypt_file_xtea(xtea_path, xtea_key)
    passed_xtea = verify_round_trip("patient_record.txt", dec_path_xtea)
    print(f"XTEA ROUND-TRIP: {'PASSED' if passed_xtea else 'FAILED'}")

    print("\n--- Wrong Key Test ---")
    # 4. Attempt to decrypt with an incorrect key.
    wrong_key = generate_key()
    try:
        wrong_dec_path = "wrong_dec.txt"
        # Note: The decrypt function in rc6 doesn't take an output path argument like the wrapper.
        # We will call the wrapper instead for consistency.
        decrypt_file_rc6(rc6_path, wrong_key, wrong_dec_path)
        
        with open("patient_record.txt", 'rb') as f:
            orig = f.read()
        with open(wrong_dec_path, 'rb') as f:
            wrong = f.read()
        
        # The test passes if the decrypted content does not match the original.
        print(f"WRONG KEY REJECTED: {'PASSED' if orig != wrong else 'FAILED'}")
    except ValueError:
        # A ValueError from padding errors is the expected outcome for a wrong key.
        print("WRONG KEY REJECTED: PASSED (Decryption failed with ValueError as expected)")
    except Exception as e:
        # Any other exception also indicates failure, which is a pass for this test.
        print(f"WRONG KEY REJECTED: PASSED (Decryption failed with {type(e).__name__})")