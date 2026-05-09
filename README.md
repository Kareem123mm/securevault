# SecureVault — Secure Medical Records System

## Overview
SecureVault is a from-scratch cryptographic system simulating a
secure hospital portal. It implements symmetric encryption,
asymmetric encryption, certificate-based authentication,
and key management — all without any cryptographic libraries.

## Algorithms implemented

| Algorithm | Type | Module | Key size | Why chosen |
|-----------|------|--------|----------|------------|
| RC6-32/20/16 | Symmetric block cipher | A | 128-bit | AES finalist; uses only +,*,>>,<< |
| XTEA | Symmetric Feistel | A | 128-bit | Pure math, 64-round Feistel |
| ElGamal | Asymmetric DLP-based | B+C | 1024-bit | Encryption + signatures from one scheme |
| NTRU (toy) | Post-quantum lattice | Bonus | N=11 polynomial | No crypto library possible |

## File structure

CRYPTO/
├── modules/          Core cryptographic implementations
│   ├── elgamal.py
│   ├── rc6.py
│   ├── xtea.py
│   ├── ca.py
│   ├── server.py
│   ├── client.py
│   ├── handshake.py
│   ├── key_manager.py
│   └── elgamal_utils.py
├── benchmarks/       Performance measurement scripts
│   ├── perf_symmetric.py
│   ├── perf_asymmetric.py
│   └── perf_full.py
├── tests/            Correctness verification
│   ├── test_symmetric.py
│   └── test_integration.py
├── extras/           Bonus and utility modules
│   ├── ntru.py
│   └── file_encryptor.py
├── performance_results/   Auto-generated benchmark outputs
├── report/           Handwritten examples go here
├── .vscode/          VS Code configuration
├── demo.py           Entry point — run this first
├── charts.py         Generate performance charts
├── run_all.py        Run everything in one command
├── requirements.txt
└── README.md

## How to run

### Option 1 — Run everything at once (recommended for demo)
python run_all.py

### Option 2 — Run individual steps
python demo.py                        # full end-to-end demo
python tests/test_symmetric.py        # RC6 + XTEA unit tests
python tests/test_integration.py      # full integration tests
python benchmarks/perf_symmetric.py   # symmetric benchmarks
python benchmarks/perf_asymmetric.py  # ElGamal benchmarks
python benchmarks/perf_full.py        # full system benchmark
python charts.py                      # generate 4 performance charts
python extras/ntru.py                 # NTRU bonus demo

### Option 3 — VS Code
Open Run and Debug panel (Ctrl+Shift+D)
Select any configuration from the dropdown and press F5

## Setup
pip install matplotlib

No other dependencies. Python 3.10+ required.
No cryptographic libraries used anywhere in the project.

## AI usage declaration
AI tools (Claude, Anthropic) assisted with:
- Code structure for rc6.py, xtea.py, elgamal.py
- Debugging modular arithmetic in elgamal.py sign()
- Certificate format design in ca.py
All mathematical implementations were manually verified against:
- RC6: Rivest et al. 1998 AES submission
- XTEA: Wheeler & Needham 1997 technical report
- ElGamal: ElGamal 1985 IEEE Transactions on Information Theory
- NTRU: Hoffstein, Pipher, Silverman 1998 NTRU paper
The report, literature review, and handwritten examples
were produced independently.
Declared per academic integrity policy.

## Team contributions
| Member | Module | Files |
|--------|--------|-------|
| Member 1 | A | rc6.py, xtea.py, file_encryptor.py, perf_symmetric.py, test_symmetric.py |
| Member 2 | B | elgamal.py, elgamal_utils.py, perf_asymmetric.py |
| Member 3 | C | ca.py, key_manager.py, handshake.py, server.py, client.py, demo.py, perf_full.py, charts.py |

## Handwritten examples
- handwritten_A.pdf: XTEA 3-round trace, v0=1 v1=2 key=[0,0,0,0]
- handwritten_B.pdf: ElGamal full cycle, p=23 g=5 x=6 k=3 m=10
