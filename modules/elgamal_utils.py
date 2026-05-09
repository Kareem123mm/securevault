import elgamal
import time
import json

# CANONICAL KDF
def derive_session_key(pre_master_secret, client_nonce, server_nonce):
   """
   Derives a 16-byte session key from three 16-byte inputs using a custom KDF.
   This is a simple, non-standard key derivation function for demonstration.
   It combines the inputs with XOR and then mixes them using rotations and additions.
   """
   # Combine the three inputs using XOR
   combined = bytearray(pre_master_secret)
   for i in range(16):
       combined[i] ^= client_nonce[i]
       combined[i] ^= server_nonce[i]
   
   # Mix the combined bytes over 3 rounds
   for _ in range(3):
       for i in range(16):
           left  = combined[(i - 1) % 16]
           right = combined[(i + 1) % 16]
           # Mixing operation: add neighbors, XOR with a rotated version of the left neighbor
           combined[i] = ((combined[i] + left + right) ^ ((left << 1) | (left >> 7))) & 0xFF
           
   return bytes(combined)

# --- String and Session Key Wrappers ---

def encrypt_string(text, p, g, y):
    """Encrypts a UTF-8 string using the ElGamal byte encryption method."""
    data = text.encode('utf-8')
    return elgamal.encrypt_bytes(data, p, g, y)

def decrypt_string(pairs, x, p):
    """Decrypts ElGamal byte-encrypted data back into a UTF-8 string."""
    data = elgamal.decrypt_bytes(pairs, x, p)
    return data.decode('utf-8')

def sign_string(text, x, p, g):
    """Signs a UTF-8 string using the ElGamal signature scheme."""
    return elgamal.sign(text.encode('utf-8'), x, p, g)

def verify_string(text, r, s, y, p, g):
    """Verifies an ElGamal signature for a UTF-8 string."""
    return elgamal.verify(text.encode('utf-8'), r, s, y, p, g)

def encrypt_session_key(session_key_bytes, p, g, y):
    """Encrypts a 16-byte session key by converting it to an integer."""
    m = int.from_bytes(session_key_bytes, 'big')
    return elgamal.encrypt(m, p, g, y)

def decrypt_session_key(c1, c2, x, p):
    """Decrypts an ElGamal-encrypted integer back into a 16-byte session key."""
    m = elgamal.decrypt(c1, c2, x, p)
    # Ensure the key is exactly 16 bytes, padding with leading zeros if necessary.
    return m.to_bytes(16, 'big')

# --- Performance Measurement ---

def measure_performance(p, g, y, x):
    """
    Measures the execution time of core ElGamal operations.
    """
    os.makedirs("performance_results", exist_ok=True)
    results = {}
    
    # 1. Key Generation
    t0 = time.perf_counter()
    elgamal.generate_keypair()
    results["keygen_ms"] = round((time.perf_counter() - t0) * 1000, 4)
    
    # Prepare a random message for encryption/signing
    msg = os.urandom(16)
    m_int = int.from_bytes(msg, 'big') % (p - 1)
    if m_int == 0: m_int = 1 # Message must not be 0
    
    # 2. Encryption
    t0 = time.perf_counter()
    c1, c2 = elgamal.encrypt(m_int, p, g, y)
    results["encrypt_ms"] = round((time.perf_counter() - t0) * 1000, 4)
    
    # 3. Decryption
    t0 = time.perf_counter()
    elgamal.decrypt(c1, c2, x, p)
    results["decrypt_ms"] = round((time.perf_counter() - t0) * 1000, 4)
    
    # 4. Signing
    t0 = time.perf_counter()
    r, s = elgamal.sign(msg, x, p, g)
    results["sign_ms"] = round((time.perf_counter() - t0) * 1000, 4)
    
    # 5. Verification
    t0 = time.perf_counter()
    elgamal.verify(msg, r, s, y, p, g)
    results["verify_ms"] = round((time.perf_counter() - t0) * 1000, 4)
    
    # Record key and ciphertext sizes
    results["pubkey_bits"] = p.bit_length()
    results["ciphertext_bits"] = c1.bit_length() + c2.bit_length()
    
    return results

if __name__ == "__main__":
    # --- DEMO ---
    print("Generating ElGamal keypair...")
    p, g, x, y = elgamal.generate_keypair()
    
    # Test string encryption/decryption
    msg = "DOCTOR ACCESS: GRANTED"
    print(f"Original message: '{msg}'")
    pairs = encrypt_string(msg, p, g, y)
    recovered = decrypt_string(pairs, x, p)
    print(f"ENCRYPT/DECRYPT: {'PASSED' if recovered == msg else 'FAILED'}")
    
    # Test string signing/verification
    r, s = sign_string(msg, x, p, g)
    print(f"SIGN/VERIFY: {'PASSED' if verify_string(msg, r, s, y, p, g) else 'FAILED'}")
    
    # Test tampered message rejection
    print(f"TAMPER REJECTED: {'PASSED' if not verify_string(msg + 'X', r, s, y, p, g) else 'FAILED'}")
    
    # Run and print performance metrics
    perf = measure_performance(p, g, y, x)
    print(f"\nPerformance (using {p.bit_length()}-bit prime):")
    for k, v in perf.items():
       print(f"  {k}: {v}")
    
    # Save performance results to a file
    with open("performance_results/elgamal_perf.json", "w") as f:
        json.dump(perf, f, indent=2)
    print("\nPerformance results saved to performance_results/elgamal_perf.json")