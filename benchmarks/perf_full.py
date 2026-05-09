import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import rc6
import xtea
import elgamal
import time
import tracemalloc
import json

# Import the high-level components of the SecureVault system
from ca import CertificateAuthority
from server import HospitalServer
from client import DoctorClient, PatientClient
from handshake import perform_handshake

def timed(func, *args):
    """
    A simple wrapper to measure the execution time of a function.

    Returns:
        A tuple containing (execution_time_in_ms, function_result).
    """
    t0 = time.perf_counter()
    result = func(*args)
    t1 = time.perf_counter()
    return round((t1 - t0) * 1000, 4), result

def run_and_print():
    """
    Runs a series of benchmarks on the entire crypto system, from low-level
    operations to high-level end-to-end transactions, and prints a summary.
    """
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'performance_results')
    os.makedirs(results_dir, exist_ok=True)
    results = {}
    
    print("\n--- ElGamal Key Generation ---")
    # Average the time for ElGamal keypair generation over 3 runs.
    times = [timed(elgamal.generate_keypair)[0] for _ in range(3)]
    results["keygen_ms"] = round(sum(times) / 3, 4)
    print(f"ElGamal keygen (avg 3 runs): {results['keygen_ms']:.4f} ms")
    
    print("\n--- Symmetric Throughput (1MB) ---")
    data_1mb = os.urandom(1048576)
    key = os.urandom(16)
    
    # Measure RC6 throughput
    t_rc6, _ = timed(rc6.encrypt_data, data_1mb, key)
    results["rc6_throughput_mbs"] = round(1.0 / (t_rc6 / 1000), 2) if t_rc6 > 0 else float('inf')
    print(f"RC6 throughput: {results['rc6_throughput_mbs']} MB/s")
    
    # Measure XTEA throughput
    t_xtea, _ = timed(xtea.encrypt_data, data_1mb, key)
    results["xtea_throughput_mbs"] = round(1.0 / (t_xtea / 1000), 2) if t_xtea > 0 else float('inf')
    print(f"XTEA throughput: {results['xtea_throughput_mbs']} MB/s")
    
    print("\n--- Ciphertext Overhead (1000 bytes) ---")
    data_1k = os.urandom(1000)
    ct_rc6 = rc6.encrypt_data(data_1k, key)
    ct_xtea = xtea.encrypt_data(data_1k, key)
    p_full, g_full, x_full, y_full = elgamal.generate_keypair()
    m_int = int.from_bytes(data_1k[:15], 'big') % (p_full - 1) or 1
    c1, c2 = elgamal.encrypt(m_int, p_full, g_full, y_full)
    results["overhead"] = {
        "rc6_ratio": round(len(ct_rc6) / 1000, 4),
        "xtea_ratio": round(len(ct_xtea) / 1000, 4),
        "elgamal_bits_per_block": c1.bit_length() + c2.bit_length()
    }
    print(f"RC6 ciphertext size ratio: {results['overhead']['rc6_ratio']}")
    print(f"XTEA ciphertext size ratio: {results['overhead']['xtea_ratio']}")
    print(f"ElGamal ciphertext bits per block: {results['overhead']['elgamal_bits_per_block']}")
    
    print("\n--- Full TLS Handshake ---")
    # Set up the necessary components for a handshake
    ca_inst = CertificateAuthority()
    hospital = HospitalServer(ca_inst)
    p1, g1, x1, y1 = elgamal.generate_keypair()
    cert_doc = ca_inst.issue_certificate("bench_doctor", "doctor", p1, g1, y1)
    
    # Time the handshake itself
    t_handshake, _ = timed(perform_handshake, "bench_doctor", cert_doc, x1,
                           hospital.cert, hospital.x, ca_inst)
    results["handshake_ms"] = t_handshake
    print(f"Full TLS handshake: {t_handshake:.4f} ms")
    
    print("\n--- End-to-End Transaction ---")
    # Time a full transaction: connect, upload, retrieve
    dr = DoctorClient("bench_dr", ca_inst)
    
    t0 = time.perf_counter()
    dr.connect_to_server(hospital)
    record = "PATIENT: Benchmark\nDIAGNOSIS: Test\nMEDICATION: None" * 10
    pid = f"patient_bench"
    encrypted = rc6.encrypt_data(record.encode(), dr.session_key)
    hospital.store_record(pid, encrypted, dr.session_key)
    hospital.retrieve_record(pid, dr.session_key)
    t1 = time.perf_counter()
    
    results["full_transaction_ms"] = round((t1 - t0) * 1000, 4)
    print(f"Full transaction (connect, upload, retrieve): {results['full_transaction_ms']:.4f} ms")
    
    # Save all results to a JSON file
    output_filename = os.path.join(results_dir, "full_bench.json")
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nBenchmark results saved to {output_filename}")
    
    # Print final summary table
    print(f"\n{'Operation':<30} {'Time (ms)':<15} {'Notes'}")
    print("-" * 65)
    print(f"{'ElGamal keygen':<30} {results['keygen_ms']:<15.4f} one-time cost")
    print(f"{'TLS handshake':<30} {results['handshake_ms']:<15.4f} per connection")
    rc6_time = round(1000 / results['rc6_throughput_mbs'], 2) if results['rc6_throughput_mbs'] > 0 else 'N/A'
    xtea_time = round(1000 / results['xtea_throughput_mbs'], 2) if results['xtea_throughput_mbs'] > 0 else 'N/A'
    print(f"{'RC6 1MB encrypt':<30} {rc6_time:<15} symmetric bulk encryption")
    print(f"{'XTEA 1MB encrypt':<30} {xtea_time:<15} symmetric bulk encryption")
    print(f"{'Full transaction':<30} {results['full_transaction_ms']:<15.4f} end-to-end (incl. handshake)")

if __name__ == "__main__":
   run_and_print()