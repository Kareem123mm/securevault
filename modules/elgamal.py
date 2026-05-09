import random

# CONSTANTS
# P is a 2048-bit safe prime (from RFC 3526, 2048-bit MODP Group)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
# G is a generator for the multiplicative group of integers modulo P
G = 2

def manual_hash(data_bytes, mod):
    # Merkle-Damgard construction — no libraries, only XOR + shifts + addition
    # Padding: append 0x80, zero bytes until len % 64 == 56, then 8-byte little-endian length
    length = len(data_bytes)
    data = bytearray(data_bytes)
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0x00)
    data += length.to_bytes(8, 'little')
    # Initial state (derived from first 32 bits of fractional parts of sqrt of first 4 primes)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    MASK = 0xFFFFFFFF
    # Process 64-byte blocks
    for i in range(0, len(data), 64):
        block = data[i:i+64]
        w = [int.from_bytes(block[j*4:(j+1)*4], 'little') for j in range(16)]
        a, b, c, d = h0, h1, h2, h3
        for j in range(16):
            f = ((b & c) | (~b & d)) & MASK
            temp = (a + f + w[j] + 0xD76AA478) & MASK
            a, d, c, b = d, c, b, (b + ((temp << 7) | (temp >> 25))) & MASK
        h0 = (h0 + a) & MASK
        h1 = (h1 + b) & MASK
        h2 = (h2 + c) & MASK
        h3 = (h3 + d) & MASK
    result = (h0 | (h1 << 32) | (h2 << 64) | (h3 << 96)) % mod
    return result

def gcd(a, b):
    # Euclidean algorithm for finding the greatest common divisor of two numbers.
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    # ITERATIVE — safe for 1536-bit ElGamal integers (recursive version hits Python's limit)
    # Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def mod_inverse(a, m):
    # Returns x such that a*x ≡ 1 (mod m)
    a = a % m
    if a == 0:
        raise ValueError("No inverse exists for 0")
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse exists: gcd={g}")
    return x % m

def generate_keypair():
    # ElGamal key generation.
    # Private key x is a random integer.
    # Public key y = G^x mod P.
    x = random.randint(2, P - 2)
    y = pow(G, x, P)
    return (P, G, x, y)

def encrypt(message_int, p, g, y):
    # ElGamal encryption for an integer message.
    # c1 = g^k mod p
    # c2 = m * y^k mod p
    # k is an ephemeral random key.
    if not (0 < message_int < p):
        raise ValueError("Message must be in range (0, p)")
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (message_int * pow(y, k, p)) % p
    return (c1, c2)

def decrypt(c1, c2, x, p):
    # ElGamal decryption.
    # s = c1^x mod p (shared secret)
    # s_inv = s^(p-2) mod p (by Fermat's Little Theorem, since p is prime)
    # m = c2 * s_inv mod p
    s = pow(c1, x, p)
    s_inv = pow(s, p - 2, p)
    return (c2 * s_inv) % p

def int_to_bytes(n, length):
    # Converts an integer to a byte string of a specified length.
    return n.to_bytes(length, 'big')

def bytes_to_int(b):
    # Converts a byte string to an integer.
    return int.from_bytes(b, 'big')

def encrypt_bytes(data_bytes, p, g, y):
    # Encrypts a byte string by splitting it into chunks.
    # Each chunk is converted to an integer and encrypted.
    chunk_size = (p.bit_length() // 8) - 1
    chunks = []
    for i in range(0, len(data_bytes), chunk_size):
        chunk = data_bytes[i:i + chunk_size]
        # Pad the last chunk if it's smaller than the chunk size.
        if len(chunk) < chunk_size:
            pad_len = chunk_size - len(chunk)
            chunk = chunk + bytes([0] * pad_len) + bytes([pad_len])
        else:
            # Add a padding block if the last chunk is full.
            chunk = chunk + bytes([0])
        m = bytes_to_int(chunk)
        if m >= p:
            m = m % (p - 1)
        chunks.append(encrypt(m, p, g, y))
    return chunks

def decrypt_bytes(pairs, x, p):
    # Decrypts a list of encrypted (c1, c2) pairs back into a byte string.
    chunk_size = (p.bit_length() // 8) - 1
    result = bytearray()
    for idx, (c1, c2) in enumerate(pairs):
        m = decrypt(c1, c2, x, p)
        raw = int_to_bytes(m, chunk_size + 1)
        # Handle unpadding for the last chunk.
        if idx == len(pairs) - 1:
            pad_len = raw[-1]
            raw = raw[:chunk_size - pad_len]
        else:
            raw = raw[:chunk_size]
        result += raw
    return bytes(result)

def sign(message_bytes, x, p, g):
    # ElGamal signature generation.
    # h = hash(message) mod (p-1)
    # k is a random number coprime to p-1.
    # r = g^k mod p
    # s = k_inv * (h - x*r) mod (p-1)
    h = manual_hash(message_bytes, p - 1)
    if h == 0:
        h = 1
    p_minus_1 = p - 1
    for _ in range(10000):
        k = random.randint(2, p_minus_1 - 1)
        if gcd(k, p_minus_1) != 1:
            continue
        r = pow(g, k, p)
        if r == 0:
            continue
        k_inv = mod_inverse(k, p_minus_1)
        s = (k_inv * (h - x * r)) % p_minus_1
        if s == 0:
            continue
        return (r, s)
    raise Exception("Could not generate valid signature after 10000 attempts")

def verify(message_bytes, r, s, y, p, g):
    # ElGamal signature verification.
    # Checks if y^r * r^s mod p == g^h mod p
    # v1 = g^h mod p
    # v2 = y^r * r^s mod p
    # The signature is valid if v1 == v2.
    if not (0 < r < p) or not (0 < s < p - 1):
        return False
    h = manual_hash(message_bytes, p - 1)
    if h == 0:
        h = 1
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2

if __name__ == "__main__":
    # Test 1: Textbook example with small values
    print("--- TEXTBOOK EXAMPLE ---")
    p_small = 23
    g_small = 5
    x_small = 6
    y_small = pow(g_small, x_small, p_small)
    print(f"Textbook: y = {g_small}^{x_small} mod {p_small} = {y_small}  (expected 8)")
    
    m_plain = 10
    k_ephemeral = 3
    c1 = pow(g_small, k_ephemeral, p_small)
    c2 = (m_plain * pow(y_small, k_ephemeral, p_small)) % p_small
    print(f"Encrypt m={m_plain}, k={k_ephemeral}: c1={c1}, c2={c2}  (expected c1=10, c2=14)")
    
    s = pow(c1, x_small, p_small)
    s_inv = pow(s, p_small - 2, p_small)
    m_rec = (c2 * s_inv) % p_small
    print(f"Decrypt: m={m_rec}  (expected 10)")
    print("TEXTBOOK EXAMPLE:", "PASSED" if m_rec == 10 else "FAILED")

    # Test 2: Full keypair encrypt/decrypt
    print("\n--- FULL KEYPAIR ENCRYPT/DECRYPT ---")
    P_full, G_full, x_full, y_full = generate_keypair()
    print(f"Full keypair generated. Public key y starts with: {str(y_full)[:20]}...")
    test_msg = b"PATIENT RECORD: BP=120/80"
    print(f"Original message: {test_msg}")
    pairs = encrypt_bytes(test_msg, P_full, G_full, y_full)
    recovered = decrypt_bytes(pairs, x_full, P_full)
    print(f"Recovered message: {recovered}")
    print("ENCRYPT/DECRYPT ROUND-TRIP:", "PASSED" if recovered == test_msg else "FAILED")

    # Test 3: Sign and verify
    print("\n--- SIGNATURE AND VERIFICATION ---")
    r, s = sign(test_msg, x_full, P_full, G_full)
    print(f"Signature generated: r={str(r)[:20]}..., s={str(s)[:20]}...")
    valid = verify(test_msg, r, s, y_full, P_full, G_full)
    print("SIGNATURE VALID:", "PASSED" if valid else "FAILED")
    
    tampered = test_msg + b" TAMPERED"
    print(f"Verifying tampered message: {tampered}")
    invalid = verify(tampered, r, s, y_full, P_full, G_full)
    print("TAMPERED REJECTED:", "PASSED" if not invalid else "FAILED")