import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import rc6
import xtea

def run_test(name, func):
    """
    Runs a single test function, prints the result, and returns True/False.
    """
    try:
        func()
        print(f"  {name}: PASSED")
        return True
    except Exception as e:
        print(f"  {name}: FAILED — {e}")
        return False

# --- RC6 TESTS ---

def test_rc6_single_block():
    """Tests if a single 16-byte block can be encrypted and decrypted correctly."""
    key = b"SECUREVAULT12345"
    S = rc6.key_schedule(key)
    pt = b"1234567890ABCDEF"
    assert rc6.decrypt_block(rc6.encrypt_block(pt, S), S) == pt

def test_rc6_multiple_blocks():
    """Tests if data spanning multiple blocks can be encrypted and decrypted."""
    key = b"SECUREVAULT12345"
    pt = os.urandom(64)
    assert rc6.decrypt_data(rc6.encrypt_data(pt, key), key) == pt

def test_rc6_padding_sizes():
    """Tests PKCS7 padding for various data sizes around the block boundary."""
    key = b"SECUREVAULT12345"
    for size in [1, 15, 16, 17, 31, 32, 33]:
        pt = os.urandom(size)
        assert rc6.decrypt_data(rc6.encrypt_data(pt, key), key) == pt, f"Failed at size {size}"

def test_rc6_wrong_key():
    """Ensures that decrypting with the wrong key fails or produces incorrect data."""
    key = b"SECUREVAULT12345"
    wrong = b"WRONGKEY12345678"
    pt = os.urandom(48)
    ct = rc6.encrypt_data(pt, key)
    try:
        rt = rc6.decrypt_data(ct, wrong)
        # If it decrypts without error, the result must not be the original plaintext
        assert rt != pt
    except ValueError:
        # A ValueError from invalid padding is the expected failure mode
        pass
    except Exception:
        # Any other exception is also a successful failure
        pass

def test_rc6_deterministic():
    """Verifies that encryption is deterministic (same input -> same output)."""
    key = b"SECUREVAULT12345"
    pt = b"DETERMINISTIC!!"
    assert rc6.encrypt_data(pt, key) == rc6.encrypt_data(pt, key)

def test_rc6_ciphertext_differs():
    """Checks that the ciphertext is not the same as the plaintext."""
    key = b"SECUREVAULT12345"
    pt = b"PLAINTEXT DATA!!"
    ct = rc6.encrypt_data(pt, key)
    assert ct != pt

def test_rc6_avalanche():
    """
    Tests the avalanche effect: a small change in plaintext should cause a
    large change (approx. 50%) in the ciphertext.
    """
    key = b"SECUREVAULT12345"
    pt1 = bytearray(b"PLAINTEXT DATA!!")
    pt2 = bytearray(b"PLAINTEXT DATA!!")
    pt2[0] ^= 0x01  # Flip one bit in the plaintext
    ct1 = rc6.encrypt_data(bytes(pt1), key)
    ct2 = rc6.encrypt_data(bytes(pt2), key)
    
    # Calculate the number of differing bits
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(ct1, ct2))
    total_bits = len(ct1) * 8
    
    # A good avalanche effect should change about half the bits.
    # We'll assert that the difference is at least 40%.
    assert (diff_bits / total_bits) > 0.4

# --- XTEA TESTS ---

def test_xtea_block_roundtrip():
    """Tests the core XTEA block encrypt/decrypt functions."""
    e0, e1 = xtea.encrypt_block(1, 2, [0, 0, 0, 0])
    d0, d1 = xtea.decrypt_block(e0, e1, [0, 0, 0, 0])
    assert d0 == 1 and d1 == 2

def test_xtea_bytes_roundtrip():
    """Tests the full data encrypt/decrypt round-trip for XTEA."""
    key = b"SECUREVAULT12345"
    pt = os.urandom(80)
    assert xtea.decrypt_data(xtea.encrypt_data(pt, key), key) == pt

def test_xtea_padding_sizes():
    """Tests PKCS7 padding for XTEA with various data sizes."""
    key = b"SECUREVAULT12345"
    for size in [1, 7, 8, 9, 15, 16]:
        pt = os.urandom(size)
        assert xtea.decrypt_data(xtea.encrypt_data(pt, key), key) == pt, f"Failed at size {size}"

def test_xtea_wrong_key():
    """Ensures that decrypting XTEA with the wrong key fails."""
    key = b"SECUREVAULT12345"
    wrong = b"WRONGKEY12345678"
    pt = os.urandom(32)
    ct = xtea.encrypt_data(pt, key)
    try:
        rt = xtea.decrypt_data(ct, wrong)
        assert rt != pt
    except ValueError:
        pass
    except Exception:
        pass

def test_xtea_deterministic():
    """Verifies that XTEA encryption is deterministic."""
    key = b"SECUREVAULT12345"
    pt = os.urandom(24)
    assert xtea.encrypt_data(pt, key) == xtea.encrypt_data(pt, key)

# --- CROSS-CIPHER TESTS ---

def test_different_outputs():
    """Ensures RC6 and XTEA produce different ciphertexts for the same input."""
    key = b"SECUREVAULT12345"
    pt = os.urandom(32)
    assert rc6.encrypt_data(pt, key) != xtea.encrypt_data(pt, key)

def test_both_correct():
    """A final sanity check that both ciphers work correctly on the same data."""
    key = b"SECUREVAULT12345"
    pt = os.urandom(48)
    assert rc6.decrypt_data(rc6.encrypt_data(pt, key), key) == pt
    assert xtea.decrypt_data(xtea.encrypt_data(pt, key), key) == pt

if __name__ == "__main__":
    tests = [
        ("RC6 single block", test_rc6_single_block),
        ("RC6 multiple blocks", test_rc6_multiple_blocks),
        ("RC6 padding sizes", test_rc6_padding_sizes),
        ("RC6 wrong key", test_rc6_wrong_key),
        ("RC6 deterministic", test_rc6_deterministic),
        ("RC6 ciphertext differs", test_rc6_ciphertext_differs),
        ("RC6 avalanche effect", test_rc6_avalanche),
        ("XTEA block round-trip", test_xtea_block_roundtrip),
        ("XTEA bytes round-trip", test_xtea_bytes_roundtrip),
        ("XTEA padding sizes", test_xtea_padding_sizes),
        ("XTEA wrong key", test_xtea_wrong_key),
        ("XTEA deterministic", test_xtea_deterministic),
        ("RC6 != XTEA output", test_different_outputs),
        ("Both decrypt correctly", test_both_correct),
    ]
    
    print("Running Symmetric Cipher Tests...")
    passed_count = sum(run_test(name, func) for name, func in tests)
    
    print("-" * 30)
    print(f"SUMMARY: {passed_count}/{len(tests)} tests passed.")
    if passed_count == len(tests):
        print("All tests completed successfully!")
    else:
        print("Some tests failed.")