import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import elgamal
import time
import tracemalloc
import json


def measure_operation(func, *args, runs=3):
    """
    Measures the performance of a given function over several runs.

    Args:
        func: The function to benchmark.
        *args: Arguments to pass to the function.
        runs: The number of times to run the operation for averaging.

    Returns:
        A tuple containing:
        - A dictionary with performance metrics (min, max, avg time, peak memory).
        - The result from the last execution of the function.
    """
    times = []
    peak = 0
    result = None
    for _ in range(runs):
        tracemalloc.start()
        t0 = time.perf_counter()
        result = func(*args)
        t1 = time.perf_counter()
        _, p = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append((t1 - t0) * 1000)
        peak = max(peak, p)

    return {
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "avg_ms": round(sum(times) / len(times), 4),
        "peak_memory_kb": round(peak / 1024, 2)
    }, result


def run_full_benchmark():
    """
    Runs a comprehensive performance benchmark for the ElGamal implementation,
    covering key generation, encryption, decryption, signing, and verification.
    """
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'performance_results')
    os.makedirs(results_dir, exist_ok=True)

    print("Generating ElGamal keypair (one-time)...")
    keygen_result, (p, g, x, y) = measure_operation(elgamal.generate_keypair)
    print(f"Keygen took: {keygen_result['avg_ms']:.4f} ms")

    sizes = [16, 64, 256, 1024]
    size_labels = ["16B", "64B", "256B", "1024B"]
    results = {
        "keygen": keygen_result,
        "pubkey_bits": p.bit_length(),
        "operations": {}
    }

    print("Benchmarking operations for various data sizes...")

    for size, label in zip(sizes, size_labels):
        print(f"  - Size: {label}")
        data = os.urandom(size)
        m_int = int.from_bytes(data[:15], 'big')

        enc_result, (c1, c2) = measure_operation(elgamal.encrypt, m_int, p, g, y)
        dec_result, _ = measure_operation(elgamal.decrypt, c1, c2, x, p)
        sign_result, (r, s) = measure_operation(elgamal.sign, data, x, p, g)
        verify_result, _ = measure_operation(elgamal.verify, data, r, s, y, p, g)

        results["operations"][label] = {
            "encrypt": enc_result,
            "decrypt": dec_result,
            "sign": sign_result,
            "verify": verify_result,
            "ciphertext_bits": c1.bit_length() + c2.bit_length()
        }

    output_filename = os.path.join(results_dir, "module_b_bench.json")
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'Operation':<12}", end="")
    for label in size_labels:
        print(f"{label:<10}", end="")
    print()
    print("-" * 52)

    for op in ["encrypt", "decrypt", "sign", "verify"]:
        print(f"{op.capitalize() + '(ms)':<12}", end="")
        for label in size_labels:
            avg_time = results['operations'][label][op]['avg_ms']
            print(f"{avg_time:<10.4f}", end="")
        print()

    print(f"\nPublic key size: {p.bit_length()} bits")
    print(f"Results saved to {output_filename}")


if __name__ == "__main__":
    run_full_benchmark()
