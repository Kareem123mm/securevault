import subprocess
import sys
import time
import os

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

ROOT = os.path.dirname(os.path.abspath(__file__))

def section(title):
    print(f"\n{BLUE}{BOLD}{'='*60}{RESET}")
    print(f"{BLUE}{BOLD}  {title}{RESET}")
    print(f"{BLUE}{BOLD}{'='*60}{RESET}")

def run_step(name, cmd, timeout=60):
    section(name)
    t0 = time.perf_counter()
    try:
        result = subprocess.run(cmd, cwd=ROOT, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"\n{YELLOW}{BOLD}  TIMEOUT{RESET} — {name} exceeded {timeout}s")
        return False
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    if result.returncode == 0:
        print(f"\n{GREEN}{BOLD}  PASSED{RESET} — {name} ({elapsed}ms)")
        return True
    else:
        print(f"\n{RED}{BOLD}  FAILED{RESET} — {name}")
        return False

def launch_network_tools():
    section("Network Tools — Live Demo (optional)")

    print(f"  {DIM}Launching SecureVault network components...{RESET}\n")

    # Launch socket server in new CMD window
    server_cmd = (
        f'start "SecureVault — Socket Server" cmd /k '
        f'"cd /d {ROOT} && echo. && '
        f'echo  SECUREVAULT SOCKET SERVER && '
        f'echo  ========================= && '
        f'echo. && '
        f'python network/socket_server.py"'
    )

    # Launch monitor in new CMD window after 2 second delay
    monitor_cmd = (
        f'start "SecureVault — Server Monitor" cmd /k '
        f'"cd /d {ROOT} && echo. && '
        f'echo  SECUREVAULT SERVER MONITOR && '
        f'echo  ========================== && '
        f'echo. && '
        f'timeout /t 2 /nobreak >nul && '
        f'python network/monitor.py"'
    )

    # Launch interactive client in new CMD window after 3 second delay
    client_cmd = (
        f'start "SecureVault — Interactive Client" cmd /k '
        f'"cd /d {ROOT} && echo. && '
        f'echo  SECUREVAULT INTERACTIVE CLIENT && '
        f'echo  ============================== && '
        f'echo. && '
        f'timeout /t 3 /nobreak >nul && '
        f'python network/interactive_client.py"'
    )

    # Launch crypto visualiser in new CMD window after 4 second delay
    visualiser_cmd = (
        f'start "SecureVault — Crypto Visualiser" cmd /k '
        f'"cd /d {ROOT} && echo. && '
        f'echo  SECUREVAULT CRYPTO VISUALISER && '
        f'echo  ============================== && '
        f'echo. && '
        f'timeout /t 4 /nobreak >nul && '
        f'python network/crypto_visualiser.py"'
    )

    try:
        os.system(server_cmd)
        print(f"  {GREEN}✓{RESET} Socket server launched in new window")
        time.sleep(0.5)

        os.system(monitor_cmd)
        print(f"  {GREEN}✓{RESET} Server monitor launched in new window")
        time.sleep(0.5)

        os.system(client_cmd)
        print(f"  {GREEN}✓{RESET} Interactive client launched in new window")
        time.sleep(0.5)

        os.system(visualiser_cmd)
        print(f"  {GREEN}✓{RESET} Crypto visualiser launched in new window")

        print(f"""
      {BOLD}Four windows are now open:{RESET}

  {CYAN}Window 1{RESET} — Socket Server
    {DIM}  Clean operational log
    {DIM}  Shows: connection, handshake, store, retrieve, list, delete

  {CYAN}Window 2{RESET} — Server Monitor
    {DIM}  Live dashboard with real-time stats
    {DIM}  NEW: Cryptographic Events panel showing every RC6/XTEA/ElGamal op
    {DIM}  NEW: System Flow Summary with bar charts per operation type

  {CYAN}Window 3{RESET} — Interactive Client Shell
    {DIM}  Type commands live
    {DIM}  NEW: After each command, prints the full mathematical chain
    {DIM}  Shows exactly what crypto happened step by step

    {CYAN}Window 4{RESET} — Crypto Visualiser
    {DIM}  Dedicated crypto event viewer
    {DIM}  Shows every operation with the math explanation
    {DIM}  Full algorithm reference panel always visible
    {DIM}  Run with --report flag for a static printed report

  {BOLD}Quick start in the client window:{RESET}
  {DIM}  > connect
  {DIM}  > store patient_001
  {DIM}  > retrieve patient_001
  {DIM}  > sign
  {DIM}  > benchmark
  {DIM}  > exit
""")

    except Exception as e:
        print(f"\n  {YELLOW}Could not auto-launch windows: {e}{RESET}")
        print(f"  Run these manually in separate terminals:\n")
        print(f"  {BOLD}Terminal 1:{RESET}  python network/socket_server.py")
        print(f"  {BOLD}Terminal 2:{RESET}  python network/monitor.py")
        print(f"  {BOLD}Terminal 3:{RESET}  python network/interactive_client.py\n")

def print_summary(results):
    print(f"\n{BLUE}{BOLD}{'='*60}{RESET}")
    print(f"{BLUE}{BOLD}  RESULTS SUMMARY{RESET}")
    print(f"{BLUE}{BOLD}{'='*60}{RESET}\n")

    max_name = max(len(name) for name, _ in results)

    for name, ok in results:
        status = f"{GREEN}PASSED{RESET}" if ok else f"{RED}FAILED{RESET}"
        dots = "." * (max_name - len(name) + 3)
        print(f"  {status}  {name} {DIM}{dots}{RESET}")

    print()
    passed = sum(1 for _, ok in results if ok)
    total  = len(results)

    if passed == total:
        print(f"  {GREEN}{BOLD}{passed}/{total} steps passed{RESET}")
        print(f"  {GREEN}{BOLD}SecureVault fully operational.{RESET}")
    else:
        failed = total - passed
        print(f"  {RED}{BOLD}{passed}/{total} steps passed — {failed} failed{RESET}")

    print()

def print_header():
    print(f"""
{BLUE}{BOLD}
╔══════════════════════════════════════════════════════════╗
║            SECUREVAULT — Full Project Runner             ║
║         Secure Medical Records System v1.0               ║
╚══════════════════════════════════════════════════════════╝
{RESET}""")
    print(f"  Python {sys.version.split()[0]}")
    print(f"  Root:   {ROOT}")
    print(f"  Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

if __name__ == "__main__":
    print_header()

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
        timeout = 30 if "ntru" in cmd[-1].lower() else 300
        ok = run_step(name, cmd, timeout=timeout)
        results.append((name, ok))
        if not ok:
            print(f"\n  {RED}Stopping — fix '{name}' before continuing.{RESET}\n")
            print_summary(results)
            sys.exit(1)

    print_summary(results)

    # Ask user if they want to launch network tools
    print(f"{BLUE}{BOLD}{'='*60}{RESET}")
    print(f"{BLUE}{BOLD}  NETWORK DEMO (optional){RESET}")
    print(f"{BLUE}{BOLD}{'='*60}{RESET}\n")
    print(f"  Launch live network demonstration?")
    print(f"  {DIM}Opens 3 windows: socket server, monitor dashboard, interactive client{RESET}\n")

    try:
        answer = input(f"  {BOLD}Launch network tools? (y/n): {RESET}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        answer = "n"

    if answer == "y":
        launch_network_tools()
    else:
        print(f"\n  {DIM}Skipped. Run manually when ready:{RESET}")
        print(f"  {BOLD}Terminal 1:{RESET}  python network/socket_server.py")
        print(f"  {BOLD}Terminal 2:{RESET}  python network/monitor.py")
        print(f"  {BOLD}Terminal 3:{RESET}  python network/interactive_client.py\n")

    print(f"{BLUE}{BOLD}{'='*60}{RESET}")
    print(f"{BLUE}{BOLD}  Run complete. SecureVault is ready for demonstration.{RESET}")
    print(f"{BLUE}{BOLD}{'='*60}{RESET}\n")