# XTEA (eXtended Tiny Encryption Algorithm) implementation from scratch in Python.
# No external libraries or imports are used in the core algorithm.

# CONSTANTS
DELTA = 0x9E3779B9  # Magic constant, derived from the Golden Ratio: (sqrt(5)-1)/2 * 2^32
MASK = 0xFFFFFFFF   # Mask for 32-bit unsigned integer arithmetic.
NUM_ROUNDS = 64     # Number of rounds for the cipher. Recommended is 32, but 64 is used here.

def encrypt_block(v0, v1, key):
    # Encrypts a 64-bit block (two 32-bit words, v0 and v1) using a 128-bit key.
    # The key is provided as a list of four 32-bit integers.
    # The algorithm uses a Feistel network structure over 64 rounds.
    sum_val = 0
    for _ in range(NUM_ROUNDS):
        # First half of the round: update v0
        # v0' = v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3]))
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3]))) & MASK
        # Update sum for the next half-round
        sum_val = (sum_val + DELTA) & MASK
        # Second half of the round: update v1
        # v1' = v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[(sum >> 11) & 3]))
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & MASK
    return v0, v1

def decrypt_block(v0, v1, key):
    # Decrypts a 64-bit block by reversing the encryption process.
    # The initial sum is set to DELTA * NUM_ROUNDS.
    sum_val = (DELTA * NUM_ROUNDS) & MASK
    for _ in range(NUM_ROUNDS):
        # Second half of the round (in reverse): update v1
        # v1' = v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[(sum >> 11) & 3]))
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & MASK
        # Update sum for the next half-round (in reverse)
        sum_val = (sum_val - DELTA) & MASK
        # First half of the round (in reverse): update v0
        # v0' = v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3]))
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3]))) & MASK
    return v0, v1

def bytes_to_key(key_bytes):
    # Converts a 16-byte key into a list of four 32-bit integers.
    # The key is padded if it's shorter than 16 bytes.
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\x00')
    # Each 4-byte chunk is converted to a big-endian integer.
    return [int.from_bytes(key_bytes[i*4:(i+1)*4], 'big') for i in range(4)]

def pkcs7_pad(data, block_size=8):
    # Applies PKCS7 padding to data to make its length a multiple of the block size.
    # The value of each padding byte is the number of padding bytes.
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    # Removes PKCS7 padding from data.
    # It validates the padding before removing it.
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 8:
        raise ValueError("Invalid padding length")
    for byte in data[-pad_len:]:
        if byte != pad_len:
            raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def encrypt_data(data_bytes, key_bytes):
    # Encrypts arbitrary-length byte data using XTEA in ECB mode.
    key = bytes_to_key(key_bytes)
    padded = pkcs7_pad(data_bytes, 8)
    result = bytearray()
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        v0 = int.from_bytes(block[0:4], 'big')
        v1 = int.from_bytes(block[4:8], 'big')
        e0, e1 = encrypt_block(v0, v1, key)
        result += e0.to_bytes(4, 'big')
        result += e1.to_bytes(4, 'big')
    return bytes(result)

def decrypt_data(ciphertext_bytes, key_bytes):
    # Decrypts data that was encrypted with encrypt_data.
    key = bytes_to_key(key_bytes)
    result = bytearray()
    for i in range(0, len(ciphertext_bytes), 8):
        block = ciphertext_bytes[i:i+8]
        v0 = int.from_bytes(block[0:4], 'big')
        v1 = int.from_bytes(block[4:8], 'big')
        d0, d1 = decrypt_block(v0, v1, key)
        result += d0.to_bytes(4, 'big')
        result += d1.to_bytes(4, 'big')
    return pkcs7_unpad(bytes(result))

def encrypt_file(input_path, output_path, key_bytes):
    # Encrypts the content of a file and saves it to another file.
    with open(input_path, 'rb') as f:
        data = f.read()
    with open(output_path, 'wb') as f:
        f.write(encrypt_data(data, key_bytes))

def decrypt_file(input_path, output_path, key_bytes):
    # Decrypts the content of a file and saves it to another file.
    with open(input_path, 'rb') as f:
        data = f.read()
    with open(output_path, 'wb') as f:
        f.write(decrypt_data(data, key_bytes))

if __name__ == "__main__":
    # Test 1: Textbook trace — print first 3 rounds
    key_trace = [0, 0, 0, 0]
    v0, v1 = 1, 2
    sum_val = 0
    print("XTEA 3-round trace (v0=1, v1=2, key=[0,0,0,0]):")
    for rnd in range(3):
       v0_temp = v0
       v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key_trace[sum_val & 3]))) & MASK
       sum_val = (sum_val + DELTA) & MASK
       v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key_trace[(sum_val >> 11) & 3]))) & MASK
       print(f"  Round {rnd+1}: sum={hex(sum_val)}, v0={hex(v0)}, v1={hex(v1)}")

    # Test 2: round-trip verify
    e0, e1 = encrypt_block(1, 2, [0,0,0,0])
    d0, d1 = decrypt_block(e0, e1, [0,0,0,0])
    print("\nBLOCK ROUND-TRIP:", "PASSED" if d0==1 and d1==2 else "FAILED")

    # Test 3: bytes round-trip
    key_b = b"SECUREVAULT12345"
    pt = b"HELLO WORLD 1234"
    ct = encrypt_data(pt, key_b)
    rt = decrypt_data(ct, key_b)
    print("BYTES ROUND-TRIP:", "PASSED" if rt == pt else "FAILED")

    # Test 4: large data
    import os
    pt_large = os.urandom(1000)
    ct_large = encrypt_data(pt_large, key_b)
    rt_large = decrypt_data(ct_large, key_b)
    print("LARGE DATA:", "PASSED" if rt_large == pt_large else "FAILED")

    # Test 5: RC6 and XTEA differ
    try:
        import rc6
        ct_rc6 = rc6.encrypt_data(pt, key_b)
        print("RC6 != XTEA:", "PASSED" if ct_rc6 != ct else "FAILED")
    except ImportError:
        print("RC6 != XTEA: SKIPPED (rc6.py not found)")
    except Exception as e:
        print(f"RC6 != XTEA: FAILED ({e})")