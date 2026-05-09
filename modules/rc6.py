# RC6-32/20/16 block cipher implementation from scratch in Python.
# No external libraries or imports are used.

# CONSTANTS
W    = 32          # Word size in bits
R    = 20          # Number of rounds
MASK = 0xFFFFFFFF  # Mask for 32-bit operations
P32  = 0xB7E15163  # Magic constant P for key schedule
Q32  = 0x9E3779B9  # Magic constant Q for key schedule
LG_W = 5           # log2(W), used for rotations


def rotate_left(x, n):
    """Circular left rotation (rol) of a 32-bit word."""
    n = n % W
    return ((x << n) | (x >> (W - n))) & MASK


def rotate_right(x, n):
    """Circular right rotation (ror) of a 32-bit word."""
    n = n % W
    return ((x >> n) | (x << (W - n))) & MASK


def key_schedule(key_bytes):
    """
    RC6 key schedule algorithm.
    Expands a 16-byte (128-bit) key into 2*R+4 = 44 subkeys.
    """
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\x00')
    elif len(key_bytes) > 16:
        key_bytes = key_bytes[:16]

    u = W // 8
    c = 16 // u
    L = []
    for i in range(c):
        word = int.from_bytes(key_bytes[i*u:(i+1)*u], 'little')
        L.append(word)

    t = 2 * R + 4
    S = [0] * t
    S[0] = P32
    for i in range(1, t):
        S[i] = (S[i-1] + Q32) & MASK

    A = B = 0
    i = j = 0
    for _ in range(3 * max(t, c)):
        A = S[i] = rotate_left((S[i] + A + B) & MASK, 3)
        B = L[j] = rotate_left((L[j] + A + B) & MASK, (A + B) % W)
        i = (i + 1) % t
        j = (j + 1) % c
    return S


def encrypt_block(plaintext_bytes, S):
    """RC6 encryption of a single 128-bit block."""
    assert len(plaintext_bytes) == 16

    A = int.from_bytes(plaintext_bytes[0:4],   'little')
    B = int.from_bytes(plaintext_bytes[4:8],   'little')
    C = int.from_bytes(plaintext_bytes[8:12],  'little')
    D = int.from_bytes(plaintext_bytes[12:16], 'little')

    # Pre-whitening
    B = (B + S[0]) & MASK
    D = (D + S[1]) & MASK

    for i in range(1, R + 1):
        t_val = rotate_left((B * (2 * B + 1)) & MASK, LG_W)
        u_val = rotate_left((D * (2 * D + 1)) & MASK, LG_W)
        A = (rotate_left(A ^ t_val, u_val % W) + S[2 * i]) & MASK
        C = (rotate_left(C ^ u_val, t_val % W) + S[2 * i + 1]) & MASK
        # Cyclic register rotation: (A,B,C,D) -> (B,C,D,A)
        A, B, C, D = B, C, D, A

    # Post-whitening
    A = (A + S[2 * R + 2]) & MASK
    C = (C + S[2 * R + 3]) & MASK

    result = bytearray()
    result += A.to_bytes(4, 'little')
    result += B.to_bytes(4, 'little')
    result += C.to_bytes(4, 'little')
    result += D.to_bytes(4, 'little')
    return bytes(result)


def decrypt_block(ciphertext_bytes, S):
    """
    RC6 decryption of a single 128-bit block.
    Exact inverse of encrypt_block.

    Key fix: post-whitening undoes A and C (not C then A), and the
    decrypt loop first undoes the rotation, THEN recomputes t/u from
    the restored B and D before undoing A and C modifications.
    """
    assert len(ciphertext_bytes) == 16

    A = int.from_bytes(ciphertext_bytes[0:4],   'little')
    B = int.from_bytes(ciphertext_bytes[4:8],   'little')
    C = int.from_bytes(ciphertext_bytes[8:12],  'little')
    D = int.from_bytes(ciphertext_bytes[12:16], 'little')

    # Undo post-whitening (A was last, C was last+1 in subkey order)
    A = (A - S[2 * R + 2]) & MASK
    C = (C - S[2 * R + 3]) & MASK

    for i in range(R, 0, -1):
        # Undo cyclic rotation (B,C,D,A) -> (A,B,C,D) by reversing: (D,A,B,C)
        A, B, C, D = D, A, B, C
        # Recompute t and u from the now-restored B and D (unchanged registers)
        t_val = rotate_left((B * (2 * B + 1)) & MASK, LG_W)
        u_val = rotate_left((D * (2 * D + 1)) & MASK, LG_W)
        # Undo A = rotate_left(A_orig ^ t_val, u_val) + S[2i]
        A = (rotate_right((A - S[2 * i]) & MASK, u_val % W) ^ t_val) & MASK
        # Undo C = rotate_left(C_orig ^ u_val, t_val) + S[2i+1]
        C = (rotate_right((C - S[2 * i + 1]) & MASK, t_val % W) ^ u_val) & MASK

    # Undo pre-whitening
    B = (B - S[0]) & MASK
    D = (D - S[1]) & MASK

    result = bytearray()
    result += A.to_bytes(4, 'little')
    result += B.to_bytes(4, 'little')
    result += C.to_bytes(4, 'little')
    result += D.to_bytes(4, 'little')
    return bytes(result)


def pkcs7_pad(data_bytes, block_size=16):
    """PKCS7 padding — pad value equals number of padding bytes."""
    pad_len = block_size - (len(data_bytes) % block_size)
    return data_bytes + bytes([pad_len] * pad_len)


def pkcs7_unpad(data_bytes):
    """Remove and verify PKCS7 padding."""
    pad_len = data_bytes[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("Invalid padding length")
    for byte in data_bytes[-pad_len:]:
        if byte != pad_len:
            raise ValueError("Invalid padding bytes")
    return data_bytes[:-pad_len]


def encrypt_data(data_bytes, key_bytes):
    """Encrypts arbitrary-length data using RC6 in ECB mode."""
    S = key_schedule(key_bytes)
    padded = pkcs7_pad(data_bytes)
    result = bytearray()
    for i in range(0, len(padded), 16):
        result += encrypt_block(padded[i:i+16], S)
    return bytes(result)


def decrypt_data(ciphertext_bytes, key_bytes):
    """Decrypts data encrypted with encrypt_data (ECB mode)."""
    S = key_schedule(key_bytes)
    result = bytearray()
    for i in range(0, len(ciphertext_bytes), 16):
        result += decrypt_block(ciphertext_bytes[i:i+16], S)
    return pkcs7_unpad(bytes(result))


def encrypt_file(input_path, output_path, key_bytes):
    """Reads a file, encrypts its content, and writes to an output file."""
    with open(input_path, 'rb') as f:
        data = f.read()
    with open(output_path, 'wb') as f:
        f.write(encrypt_data(data, key_bytes))


def decrypt_file(input_path, output_path, key_bytes):
    """Reads an encrypted file, decrypts its content, and writes to an output file."""
    with open(input_path, 'rb') as f:
        data = f.read()
    with open(output_path, 'wb') as f:
        f.write(decrypt_data(data, key_bytes))


if __name__ == "__main__":
    key = b"SECUREVAULT12345"
    S = key_schedule(key)
    print(f"First 5 subkeys: {[hex(s) for s in S[:5]]}")

    # Test 1: single block
    pt = b"PATIENT RECORD!!"
    ct = encrypt_block(pt, S)
    rt = decrypt_block(ct, S)
    print("SINGLE BLOCK:", "PASSED" if rt == pt else "FAILED")

    # Test 2: multi-block
    pt2 = b"A" * 100
    ct2 = encrypt_data(pt2, key)
    rt2 = decrypt_data(ct2, key)
    print("MULTI BLOCK:", "PASSED" if rt2 == pt2 else "FAILED")

    # Test 3: ciphertext != plaintext
    print("CIPHER != PLAIN:", "PASSED" if ct != pt else "FAILED")

    # Test 4: wrong key
    wrong_key = b"WRONGKEY12345678"
    try:
        rt3 = decrypt_data(ct2, wrong_key)
        print("WRONG KEY REJECTED:", "PASSED" if rt3 != pt2 else "FAILED")
    except (ValueError, Exception):
        print("WRONG KEY REJECTED: PASSED")

    # Test 5: file round-trip
    try:
        import os
        with open("test_record.txt", "w") as f:
            f.write("Patient: John Smith\nDiagnosis: Hypertension")
        encrypt_file("test_record.txt", "test_record.rc6", key)
        decrypt_file("test_record.rc6", "test_record_dec.txt", key)
        with open("test_record.txt") as f:
            orig = f.read()
        with open("test_record_dec.txt") as f:
            dec = f.read()
        print("FILE ROUND-TRIP:", "PASSED" if orig == dec else "FAILED")
        for fn in ["test_record.txt","test_record.rc6","test_record_dec.txt"]:
            if os.path.exists(fn): os.remove(fn)
    except Exception as e:
        print(f"FILE ROUND-TRIP: FAILED ({e})")
