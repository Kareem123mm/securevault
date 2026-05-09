import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import rc6
import xtea
import time
import tracemalloc
import json


def generate_test_data(size_bytes):
    """Generates a block of random data of a specified size."""
    return os.urandom(size_bytes)


def measure_encrypt(cipher_module, data_bytes, key_bytes, runs=3):
    """
    Measures the performance of a cipher module's encryption function.

    Args:
        cipher_module: The Python module for the cipher (e.g., rc6, xtea).
        data_bytes: The plaintext data to encrypt.
        key_bytes: The encryption key.
        runs: The number of times to run the encryption for averaging.

    Returns:
        A dictionary containing performance metrics.
    """
    times = []
    peak_mem = 0
    ct = None
    for _ in range(runs):
        tracemalloc.start()
        t0 = time.perf_counter()
        ct = cipher_module.encrypt_data(data_bytes, key_bytes)
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append((t1 - t0) * 1000)
        peak_mem = max(peak_mem, peak)

    return {
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "avg_ms": round(sum(times) / len(times), 4),
        "peak_memory_kb": round(peak_mem / 1024, 2),
        "plaintext_size": len(data_bytes),
        "ciphertext_size": len(ct),
        "expansion_ratio": round(len(ct) / len(data_bytes), 4)
    }


def measure_decrypt(cipher_module, ciphertext_bytes, key_bytes, runs=3):
    """
    Measures the performance of a cipher module's decryption function.

    Args:
        cipher_module: The Python module for the cipher.
        ciphertext_bytes: The data to decrypt.
        key_bytes: The decryption key.
        runs: The number of times to run the decryption for averaging.

    Returns:
        A dictionary containing performance metrics.
    """
    times = []
    peak_mem = 0
    for _ in range(runs):
        tracemalloc.start()
        t0 = time.perf_counter()
        cipher_module.decrypt_data(ciphertext_bytes, key_bytes)
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append((t1 - t0) * 1000)
        peak_mem = max(peak_mem, peak)

    return {
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "avg_ms": round(sum(times) / len(times), 4),
        "peak_memory_kb": round(peak_mem / 1024, 2)
    }


def run_full_benchmark():
    """
    Runs a comprehensive performance benchmark for RC6 and XTEA ciphers
    across various data sizes, saving the results and printing a summary.
    """
    sizes = [1024, 10240, 102400]
    size_labels = ["1KB", "10KB", "100KB"]
    results = {"rc6": {}, "xtea": {}}

    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'performance_results')
    os.makedirs(results_dir, exist_ok=True)

    print("Running benchmarks... (this may take a moment for larger files)")

    for size, label in zip(sizes, size_labels):
        print(f"Benchmarking with {label} of data...")
        data = generate_test_data(size)
        key = os.urandom(16)

        ct_rc6 = rc6.encrypt_data(data, key)
        results["rc6"][label] = {
            "encrypt": measure_encrypt(rc6, data, key),
            "decrypt": measure_decrypt(rc6, ct_rc6, key)
        }

        ct_xtea = xtea.encrypt_data(data, key)
        results["xtea"][label] = {
            "encrypt": measure_encrypt(xtea, data, key),
            "decrypt": measure_decrypt(xtea, ct_xtea, key)
        }

    output_filename = os.path.join(results_dir, "module_a_bench.json")
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'Cipher':<8} {'Size':<8} {'Enc(ms)':<10} {'Dec(ms)':<10} {'Mem(KB)':<10} {'Ratio':<8}")
    print("-" * 60)
    for cipher in ["rc6", "xtea"]:
        for label in size_labels:
            e = results[cipher][label]["encrypt"]
            d = results[cipher][label]["decrypt"]
            print(f"{cipher.upper():<8} {label:<8} {e['avg_ms']:<10.4f} {d['avg_ms']:<10.4f} {e['peak_memory_kb']:<10.2f} {e['expansion_ratio']:<8.4f}")

    print(f"\nResults saved to {output_filename}")


if __name__ == "__main__":
    run_full_benchmark()
