import subprocess
import sys
import time
import os

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def section(title):
    print(f"\n{BLUE}{BOLD}{'='*55}{RESET}")
    print(f"{BLUE}{BOLD}  {title}{RESET}")
    print(f"{BLUE}{BOLD}{'='*55}{RESET}")

def run_step(name, cmd):
    section(name)
    t0 = time.perf_counter()
    result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    if result.returncode == 0:
        print(f"\n{GREEN}{BOLD}  PASSED{RESET} — {name} ({elapsed}ms)")
        return True
    else:
        print(f"\n{RED}{BOLD}  FAILED{RESET} — {name}")
        return False

if __name__ == "__main__":
    print(f"\n{BOLD}SECUREVAULT — Full Project Runner{RESET}")
    print(f"Python {sys.version.split()[0]}")
    
    steps = [
        ("Symmetric unit tests",     ["python", "tests/test_symmetric.py"]),
        ("Integration tests",        ["python", "tests/test_integration.py"]),
        ("Symmetric benchmarks",     ["python", "benchmarks/perf_symmetric.py"]),
        ("Asymmetric benchmarks",    ["python", "benchmarks/perf_asymmetric.py"]),
        ("Full system benchmark",    ["python", "benchmarks/perf_full.py"]),
        ("Performance charts",       ["python", "charts.py"]),
        ("NTRU post-quantum bonus",  ["python", "extras/ntru.py"]),
        ("Full end-to-end demo",     ["python", "demo.py"]),
    ]
    
    results = []
    for name, cmd in steps:
        ok = run_step(name, cmd)
        results.append((name, ok))
        if not ok:
            print(f"{RED}Stopping — fix {name} before continuing{RESET}")
            sys.exit(1)

    try:
        run_step("Socket network demo", ["python", "network/socket_client.py"])
    except Exception as e:
        print(f"{YELLOW}Could not run socket demo: {e}{RESET}")
        print(f"{YELLOW}This is optional. Ensure server is running in another terminal.{RESET}")

    print("\n[OPTIONAL] Socket demo requires two terminals.")
    print("  Terminal 1: python network/socket_server.py")
    print("  Terminal 2: python network/socket_client.py")
    print("  Or use: start_network_demo.bat / start_network_demo.sh")
    
    print(f"\n{BOLD}{'='*55}")
    print("  RESULTS SUMMARY")
    print(f"{'='*55}{RESET}")
    for name, ok in results:
        status = f"{GREEN}PASSED{RESET}" if ok else f"{RED}FAILED{RESET}"
        print(f"  {status}  {name}")
    
    passed = sum(1 for _, ok in results if ok)
    print(f"\n{BOLD}{GREEN}{passed}/{len(results)} steps passed{RESET}")
    if passed == len(results):
        print(f"{GREEN}{BOLD}SecureVault fully operational.{RESET}\n")
