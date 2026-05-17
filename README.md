# SecureVault — Secure Medical Records System

## Team members
Kareem Mohamed Elghetany | Student ID: 320230080
Omar Sameh Dorgham | Student ID: 320230044
Youssef Ahmed Said | Student ID: 320230137

## Overview
SecureVault is a from-scratch cryptographic system simulating a secure hospital 
portal. It implements symmetric encryption, asymmetric encryption, certificate-based 
authentication, key management, and real TCP socket communication — all without any 
cryptographic libraries. Every algorithm is implemented using only basic Python 
arithmetic operators.

## Algorithms implemented

| Algorithm | Type | Module | Key size | Why chosen |
|-----------|------|--------|----------|------------|
| RC6-32/20/16 | Symmetric block cipher | A | 128-bit | AES finalist; uses only +, *, >>, << operators |
| XTEA | Symmetric Feistel cipher | A | 128-bit | 64-round pure math Feistel structure |
| ElGamal | Asymmetric DLP-based | B + C | 2048-bit | Supports both encryption and digital signatures |
| Merkle-Damgård | Hash function | B | 128-bit output | Manual MD4-style hash for ElGamal signatures — no hashlib used |
| NTRU (toy) | Post-quantum lattice | Bonus | N=11 polynomial | Lattice-based, no crypto library possible |

## Performance results (measured on this machine)

| Operation | Result | Notes |
|-----------|--------|-------|
| RC6 throughput | 0.33 MB/s | Symmetric bulk encryption |
| XTEA throughput | 0.12 MB/s | RC6 is 2.75x faster |
| RC6 ciphertext ratio | 1.008 | Minimal overhead |
| XTEA ciphertext ratio | 1.008 | Minimal overhead |
| ElGamal keygen | 23ms | One-time cost per party |
| ElGamal encrypt | ~65ms | Per operation |
| Digital signature (ElGamal sign) | ~42ms | Per document signing operation |
| Digital signature (ElGamal verify) | ~78ms | Per signature verification |
| TLS handshake | ~175ms | Per connection |
| Full session (connect+store+retrieve) | ~232ms | End-to-end including handshake |

## File structure

| File | Folder | Module | Purpose |
|------|--------|--------|---------|
| elgamal.py | modules/ | B | ElGamal keygen, encrypt, decrypt, sign, verify, Merkle-Damgard hash |
| rc6.py | modules/ | A | RC6-32/20/16 block cipher from scratch |
| xtea.py | modules/ | A | XTEA Feistel cipher from scratch |
| ca.py | modules/ | C | Certificate Authority — issue, validate, revoke certificates |
| server.py | modules/ | C | Hospital server — XTEA at rest, RC6 for transit |
| client.py | modules/ | C | Doctor and patient client classes |
| handshake.py | modules/ | C | 8-step TLS-style handshake simulation |
| key_manager.py | modules/ | C | Key generation, rotation, expiry, usage logging |
| elgamal_utils.py | modules/ | B | ElGamal wrappers and canonical KDF |
| perf_symmetric.py | benchmarks/ | A | Benchmark RC6 and XTEA across file sizes |
| perf_asymmetric.py | benchmarks/ | B | Benchmark ElGamal operations |
| perf_full.py | benchmarks/ | C | Full system benchmark including handshake |
| test_symmetric.py | tests/ | A | 14 unit tests for RC6 and XTEA |
| test_integration.py | tests/ | C | 8 integration tests for full system |
| ntru.py | extras/ | Bonus | NTRU post-quantum encryption from scratch |
| file_encryptor.py | extras/ | A | File encryption wrapper for RC6 and XTEA |
| socket_server.py | network/ | C | Real TCP socket server on port 5000 with crypto event logging |
| socket_client.py | network/ | C | Real TCP socket client with handshake |
| interactive_client.py | network/ | C | Interactive command-line shell with crypto step display |
| monitor.py | network/ | C | Live server dashboard with cryptographic events panel |
| crypto_visualiser.py | network/ | C | Dedicated crypto event viewer with math explanations |
| start_network_demo.bat | network/ | C | Windows launcher for all network tools |
| start_network_demo.sh | network/ | C | Mac/Linux launcher |
| demo.py | root | C | Full end-to-end demonstration entry point |
| charts.py | root | C | Generate 4 performance charts |
| run_all.py | root | All | Run entire project in one command |
| requirements.txt | root | — | Dependencies (matplotlib only) |
| README.md | root | — | This file |

## Project structure

```
CRYPTO/
├── modules/               Core cryptographic implementations
│   ├── __init__.py
│   ├── elgamal.py
│   ├── rc6.py
│   ├── xtea.py
│   ├── ca.py
│   ├── server.py
│   ├── client.py
│   ├── handshake.py
│   ├── key_manager.py
│   └── elgamal_utils.py
├── benchmarks/            Performance measurement
│   ├── __init__.py
│   ├── perf_symmetric.py
│   ├── perf_asymmetric.py
│   └── perf_full.py
├── tests/                 Correctness verification
│   ├── __init__.py
│   ├── test_symmetric.py
│   └── test_integration.py
├── extras/                Bonus and utility modules
│   ├── __init__.py
│   ├── ntru.py
│   └── file_encryptor.py
├── network/               Real TCP socket layer
│   ├── socket_server.py
│   ├── socket_client.py
│   ├── start_network_demo.bat
│   └── start_network_demo.sh
├── performance_results/   Auto-generated benchmark outputs
│   ├── module_a_bench.json
│   ├── module_b_bench.json
│   ├── full_bench.json
│   ├── chart_runtime.png
│   ├── chart_memory.png
│   ├── chart_ciphertext.png
│   └── chart_operations.png
├── report/                Handwritten verification examples
│   ├── handwritten_A.jpg  (XTEA trace)
│   └── handwritten_B.jpg  (ElGamal trace)
├── .vscode/               VS Code configuration
│   ├── settings.json
│   └── launch.json
├── demo.py
├── charts.py
├── run_all.py
├── requirements.txt
└── README.md
```

## Setup

```
pip install matplotlib
```

No other dependencies. Python 3.10+ required.
No cryptographic libraries used anywhere in this project.

## How to run

### Option 1 — Run everything at once (recommended)
```
python run_all.py
```
Runs all 8 automated steps in order. Prints PASSED or FAILED for each.
Expected result: 8/8 steps passed.

### Option 2 — Run individual steps
```
python demo.py                         Full end-to-end demonstration
python tests/test_symmetric.py         RC6 + XTEA unit tests (14 tests)
python tests/test_integration.py       Full integration tests (8 tests)
python benchmarks/perf_symmetric.py    Symmetric cipher benchmarks
python benchmarks/perf_asymmetric.py   ElGamal operation benchmarks
python benchmarks/perf_full.py         Full system benchmark
python charts.py                       Generate 4 performance charts
python extras/ntru.py                  NTRU post-quantum bonus demo
python extras/file_encryptor.py        File encryption demo
```

### Network demo (4 windows)

Run after `python run_all.py` and type `y` when prompted.
Or manually:

```
Terminal 1:   python network/socket_server.py
Terminal 2:   python network/monitor.py
Terminal 3:   python network/interactive_client.py
Terminal 4:   python network/crypto_visualiser.py
```

Windows shortcut:   `network\start_network_demo.bat`

Interactive client commands:
```
connect                    — establish encrypted session (8-step handshake)
store <patient_id>         — upload a patient record (RC6 transit, XTEA at rest)
retrieve <patient_id>      — download and decrypt a record
list                       — list all stored patient IDs
delete <patient_id>        — delete a record
sign                       — demonstrate ElGamal digital signature
encrypt <text>             — show RC6 encryption with hex output
benchmark                  — run quick RC6 vs XTEA vs ElGamal speed test
help                       — show all commands
exit                       — disconnect
```

### Option 3 — Real TCP socket demo (requires two terminals)
```
Terminal 1:   python network/socket_server.py
Terminal 2:   python network/socket_client.py
```
Windows shortcut:   `network\start_network_demo.bat`
Mac/Linux:          `bash network/start_network_demo.sh`

This demonstrates real encrypted packets traveling over TCP port 5000.
RC6 encrypts data in transit. XTEA encrypts data at rest on the server.

### Option 4 — VS Code
Open Run and Debug panel (Ctrl+Shift+D).
Select any configuration from the dropdown and press F5.

## Network layer architecture

The system has two layers of client/server communication:

Layer 1 — Simulated (demo.py):
     Python objects communicate directly in memory.
     Demonstrates: full CA, handshake, key management, revocation.
     Run with: python demo.py

Layer 2 — Real TCP sockets (network/ folder):
     Real network packets over TCP port 5000.
     Encrypted bytes visible in Wireshark on the loopback interface.
     Run with: python network/socket_server.py + socket_client.py

Both layers use the same RC6, XTEA, and ElGamal implementations
from the modules/ folder.

## Cryptographic event logging

The server writes a live status file to:
     performance_results/server_status.json

This file is read by:
     network/monitor.py       — dashboard view
     network/crypto_visualiser.py  — detailed math view

Every operation is logged:
     HANDSHAKE_START → CERT_VALIDATED → KEY_EXCHANGE →
     SESSION_KEY_DERIVED → RC6_ENCRYPT → RC6_DECRYPT →
     XTEA_ENCRYPT → XTEA_DECRYPT → RECORD_STORED → RECORD_RETRIEVED

## System architecture

```
Certificate Authority (CA)
        |
        | issues ElGamal-signed certificates
        |
   Hospital Server  <-------- Doctor Client
        |                     (TLS handshake,
        |                      ElGamal key exchange,
        | stores records       RC6 encrypted transit)
        | XTEA encrypted
        |
   Patient Records (at rest)
```

### Encryption layers
- In transit: RC6 block cipher (128-bit key, 20 rounds)
- At rest: XTEA cipher (128-bit key, 64 rounds)
- Key exchange: ElGamal asymmetric encryption
- Authentication: ElGamal digital signatures
- Trust: CA-issued certificates signed with ElGamal

### TLS handshake steps
```
Step 1  Client Hello          client nonce + supported ciphers
Step 2  Server Hello          server nonce + chosen cipher + server certificate
Step 3  Certificate check     client validates server cert with CA
Step 4  Key exchange          client encrypts pre-master secret with server public key
Step 5  Server decrypt        server decrypts pre-master secret with private key
Step 6  Key derivation        both sides derive identical session key via KDF
Step 7  Client Finished       client sends RC6-encrypted handshake summary
Step 8  Server Finished       server verifies and confirms secure channel
```

## Handwritten verification examples

Located in `report/` folder:

**handwritten_A.jpg** — XTEA encryption trace
- Parameters: v0=1, v1=2, key=[0,0,0,0], DELTA=0x9E3779B9
- Shows 3 complete rounds step by step
- Shows decryption recovering original v0=1, v1=2

**handwritten_B.jpg** — ElGamal encryption trace
- Parameters: p=23, g=5, x=6 (private key)
- Key generation: y = 5^6 mod 23 = 8
- Encryption of m=10 with k=3: c1=10, c2=14
- Decryption: s=9, s_inv=18, m=10 recovered

## Academic integrity and AI usage declaration

AI tools (Claude, Anthropic) assisted with the following
specific tasks during development:

- Code structure and implementation scaffolding for rc6.py,
  xtea.py, and elgamal.py
- Debugging modular arithmetic in elgamal.py sign() function
- Certificate format design in ca.py
- Socket protocol design in network/socket_server.py and
  network/socket_client.py
- Interactive client shell structure in network/interactive_client.py
- Monitor dashboard layout in network/monitor.py
- Crypto visualiser event formatting in network/crypto_visualiser.py
- Folder structure organisation and sys.path configuration

All mathematical implementations were manually verified against
published academic specifications:
- RC6: Rivest, Sidney, Yin (1998) AES submission paper
- XTEA: Wheeler and Needham (1997) technical report
- ElGamal: ElGamal (1985) IEEE Transactions on Information Theory
- NTRU: Hoffstein, Pipher, Silverman (1998) original NTRU paper

The final report, literature review, and handwritten verification
examples were produced independently without AI assistance.

All AI usage is declared in accordance with the academic integrity
policy. Code choices can be explained and demonstrated in class.

## Team contributions

| Member | Module | Files responsible for |
|--------|--------|-----------------------|
| Member 1 | A | rc6.py, xtea.py, file_encryptor.py, perf_symmetric.py, test_symmetric.py |
| Member 2 | B | elgamal.py, elgamal_utils.py, perf_asymmetric.py |
| Member 3 | C | ca.py, key_manager.py, handshake.py, server.py, client.py, demo.py, perf_full.py, charts.py, socket_server.py, socket_client.py, interactive_client.py, monitor.py, crypto_visualiser.py, test_integration.py |

## Live demo output (verified working)

The following was captured from a real session:

Session key established:   10edfb48f772f2020943f1075ac7e83f  (128-bit RC6)
Patient record stored:     25 bytes plaintext → 32 bytes RC6 ciphertext
                           then XTEA-encrypted at rest (storage key: 83dafc7ff9cfc6af...)
Record retrieved:          XTEA decrypted → RC6 encrypted for transit → RC6 decrypted by client
Data integrity:            VERIFIED — original plaintext recovered exactly
Digital signature:         VALID — v1 == v2 mathematically confirmed
Tampered document:         CORRECTLY REJECTED — v1 ≠ v2
Total crypto operations:   11 per store+retrieve session
Network traffic:           400B sent + 256B received = 656B total (all RC6 encrypted)

## References

1. Rivest R., Sidney S., Yin L. (1998) RC6 Block Cipher. AES Submission.
2. Wheeler D., Needham R. (1997) TEA extensions. Cambridge technical report.
3. ElGamal T. (1985) A public key cryptosystem. IEEE Trans. Information Theory.
4. Hoffstein J., Pipher J., Silverman J. (1998) NTRU: A ring-based public key system.
5. NIST (2001) Advanced Encryption Standard. FIPS 197.
6. Diffie W., Hellman M. (1976) New directions in cryptography. IEEE Trans.
7. Stallings W. (2017) Cryptography and Network Security. 7th ed. Pearson.
8. Katz J., Lindell Y. (2014) Introduction to Modern Cryptography. 2nd ed. CRC Press.
9. NIST (2022) Post-Quantum Cryptography Standardisation. NIST IR 8413.
10. Menezes A., van Oorschot P., Vanstone S. (1996) Handbook of Applied Cryptography.
    Available free at: cacr.uwaterloo.ca/hac
11. Wheeler D., Needham R. (1994) Correction to XTEA. Cambridge technical note.
12. Rivest R. (1994) The RC5 Encryption Algorithm. Proceedings of Fast Software Encryption.
13. NIST (2023) Post-Quantum Cryptography Selected Algorithms. NIST IR 8413-B.
```
