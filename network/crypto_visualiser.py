import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

import json
import time

# ─── ANSI CODES ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"
CLEAR  = "\033[2J\033[H"


def load_status():
    path = os.path.join(
        os.path.dirname(__file__), '..',
        'performance_results', 'server_status.json'
    )
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None


def format_event(entry, index):
    # Returns a formatted multi-line string for one crypto event
    event_type = entry.get('type', 'UNKNOWN')
    time_s = entry.get('time', '??:??:??')
    details = entry.get('details', '')

    type_colours = {
        "HANDSHAKE_START":    BLUE,
        "CERT_VALIDATED":     GREEN,
        "KEY_EXCHANGE":       CYAN,
        "SESSION_KEY_DERIVED": GREEN,
        "RC6_ENCRYPT":        YELLOW,
        "RC6_DECRYPT":        YELLOW,
        "XTEA_ENCRYPT":       CYAN,
        "XTEA_DECRYPT":       CYAN,
        "ELGAMAL_ENCRYPT":    BLUE,
        "ELGAMAL_DECRYPT":    BLUE,
        "SIGNATURE_CREATED":  GREEN,
        "SIGNATURE_VERIFIED": GREEN,
        "RECORD_STORED":      GREEN,
        "RECORD_RETRIEVED":   CYAN,
        "RECORD_DELETED":     RED,
        "LIST_REQUEST":       DIM,
        "SESSION_CLOSED":     DIM,
        "KEY_GENERATED":      BLUE,
    }

    explanations = {
        "HANDSHAKE_START":    "TCP connection received. Beginning 8-step TLS-style handshake.",
        "CERT_VALIDATED":     "ElGamal signature on certificate verified using CA public key (y_ca).",
        "KEY_EXCHANGE":       "Client sent (c1,c2). Server computes: s=c1^x mod P, m=c2*s^-1 mod P.",
        "SESSION_KEY_DERIVED":"128-bit RC6 key derived. Used for all transit encryption this session.",
        "RC6_ENCRYPT":        "RC6-32/20/16: 128-bit key -> 44 subkeys. 20 rounds of f(x)=x(2x+1).",
        "RC6_DECRYPT":        "RC6 decryption: 20 rounds reversed. Subkeys applied in reverse order.",
        "XTEA_ENCRYPT":       "XTEA: 64 rounds of XOR + shifts. New 128-bit key per patient record.",
        "XTEA_DECRYPT":       "XTEA decryption: 64 rounds reversed using same 128-bit storage key.",
        "ELGAMAL_ENCRYPT":    "ElGamal: c1=G^k mod P, c2=m*y^k mod P. Ephemeral k used once only.",
        "ELGAMAL_DECRYPT":    "ElGamal: s=c1^x mod P, s_inv=s^(P-2) mod P, m=c2*s_inv mod P.",
        "SIGNATURE_CREATED":  "ElGamal sig: h=hash(msg), r=G^k mod P, s=k_inv*(h-xr) mod (P-1).",
        "SIGNATURE_VERIFIED": "Verify: v1=G^h mod P, v2=y^r*r^s mod P. Valid if v1==v2.",
        "RECORD_STORED":      "Record flow: plaintext -> RC6 decrypt -> XTEA encrypt -> stored.",
        "RECORD_RETRIEVED":   "Record flow: XTEA decrypt -> plaintext -> RC6 encrypt -> sent.",
        "RECORD_DELETED":     "Record removed. XTEA storage key discarded permanently.",
        "LIST_REQUEST":       "Patient ID list retrieved and RC6-encrypted for transit.",
        "SESSION_CLOSED":     "Session ended. Session key discarded from memory. Cannot be recovered.",
        "KEY_GENERATED":      "New ElGamal keypair. Private key x never transmitted.",
    }

    colour = type_colours.get(event_type, RESET)
    explanation = explanations.get(event_type, "")

    lines = []
    lines.append(
        f"  {DIM}[{index:02d}] {time_s}{RESET}  "
        f"{colour}{BOLD}{event_type}{RESET}"
    )
    lines.append(f"       {DIM}Detail:{RESET}  {details}")
    lines.append(f"       {DIM}Math:  {explanation}{RESET}")
    lines.append("")
    return "\n".join(lines)


def draw_crypto_screen(status):
    output = [CLEAR]
    width = 64

    output.append(f"{BLUE}{BOLD}{'='*width}{RESET}")
    output.append(f"{BLUE}{BOLD}   SECUREVAULT CRYPTOGRAPHIC EVENT VIEWER{RESET}")
    output.append(f"{BLUE}{BOLD}{'='*width}{RESET}")
    output.append(
        f"  {DIM}Last updated: {time.strftime('%H:%M:%S')}   "
        f"Press Ctrl+C to exit{RESET}"
    )
    output.append("")

    if not status:
        output.append(f"  {RED}No data. Start socket_server.py first.{RESET}")
        print("\n".join(output), flush=True)
        return

    # Server info header
    output.append(
        f"  {BOLD}Server:{RESET}  "
        f"Cert #{status.get('cert_serial','?')}  |  "
        f"Patients: {status.get('patients_stored',0)}  |  "
        f"Connections: {status.get('total_connections',0)}"
    )
    output.append(
        f"  {BOLD}Session key:{RESET}  "
        f"{status.get('session_key','N/A')[:16]}...  "
        f"{DIM}(128-bit RC6 key){RESET}"
    )
    output.append("")

    # Crypto events
    events = status.get('crypto_events', [])
    if not events:
        output.append(f"  {DIM}No cryptographic events yet.{RESET}")
        output.append(f"  {DIM}Connect interactive_client.py and run:{RESET}")
        output.append(f"  {DIM}  connect -> store -> retrieve -> sign{RESET}")
    else:
        output.append(
            f"{BOLD}  CRYPTOGRAPHIC OPERATIONS "
            f"({len(events)} total, showing last 15):{RESET}"
        )
        output.append(f"  {'-'*60}")
        for i, entry in enumerate(reversed(events[-15:])):
            output.append(format_event(entry, len(events) - i))

    # Algorithm summary
    output.append(f"{BLUE}{BOLD}{'-'*width}{RESET}")
    output.append(f"{BOLD}  ALGORITHM REFERENCE{RESET}")
    output.append(f"  {'-'*60}")

    algos = [
        ("RC6-32/20/16", "Symmetric", "Transit",
         "128-bit key -> 44 subkeys -> 20 rounds -> f(x)=x(2x+1) rotation"),
        ("XTEA",         "Symmetric", "At rest",
         "128-bit key -> 64 rounds -> XOR + <<4 + >>5 Feistel"),
        ("ElGamal",      "Asymmetric","Key exchange",
         "2048-bit prime P, G=2, private x, public y=G^x mod P"),
        ("Merkle-Damgard","Hash",     "Signatures",
         "MD4-style, 16 rounds per 64-byte block, 4x32-bit state"),
    ]

    for name, category, usage, math in algos:
        output.append(
            f"  {CYAN}{name:<18}{RESET} "
            f"{YELLOW}{category:<12}{RESET} "
            f"{GREEN}{usage:<14}{RESET}"
        )
        output.append(f"  {DIM}  {math}{RESET}")
        output.append("")

    output.append(f"{BLUE}{BOLD}{'='*width}{RESET}")
    print("\n".join(output), flush=True)


def print_report(status):
    # Non-clearing version for --report mode
    if not status:
        print(
            f"{RED}No status file found. "
            f"Run socket_server.py first.{RESET}"
        )
        return

    print(f"\n{BLUE}{BOLD}SECUREVAULT CRYPTOGRAPHIC REPORT{RESET}")
    print(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    events = status.get('crypto_events', [])
    print(f"Total crypto operations logged: {len(events)}\n")

    for i, entry in enumerate(events):
        print(format_event(entry, i + 1))

    # Stats
    counts = {}
    for e in events:
        t = e.get('type','')
        counts[t] = counts.get(t, 0) + 1

    print(f"{BOLD}Operation counts:{RESET}")
    for op, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {op:<28} {count}")


if __name__ == "__main__":
    report_mode = "--report" in sys.argv

    if report_mode:
        status = load_status()
        print_report(status)
    else:
        print(f"{BLUE}SecureVault Crypto Visualiser - live mode{RESET}")
        print("Starting in 1 second... (Ctrl+C to exit)\n")
        time.sleep(1)
        try:
            while True:
                status = load_status()
                draw_crypto_screen(status)
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Visualiser stopped.{RESET}\n")
