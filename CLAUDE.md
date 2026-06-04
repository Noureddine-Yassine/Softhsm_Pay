# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project summary

PayHSM — PFE project. A soft HSM for secure payments built as a fork of SoftHSMv2 with added payment security layers. Targets Ubuntu 24.04, OpenSSL 3.x, GCC. The project is a **payShield-inspired simulator** — not an officially certified Thales payShield 10K.

---

## Build commands

### C backend (primary build target)
```bash
cd src/lib/payhsm
make clean all test      # builds libpayhsm.a, payhsm-httpd, payhsmd, payhsm-cli; runs 28 unit tests
make bin/payhsm-httpd    # build only the HTTP server binary
```

### Alternative build script (no Makefile needed)
```bash
./scripts/build-payhsm-httpd.sh
```

### Full SoftHSMv2 build (PKCS#11 integration)
```bash
./autogen.sh
./configure --with-crypto-backend=openssl --with-objectstore-backend-db
make -j$(nproc)
make check   # CppUnit unit tests
```

### Run tests
```bash
# Unit tests (C, no server needed)
cd src/lib/payhsm && make test

# Wire-protocol tests (requires running payhsm-httpd + initialized HSM)
./src/lib/payhsm/bin/test-wire-compat.sh [http://host:port]
./src/lib/payhsm/bin/test-hsm-cmds.sh   [http://host:port]
./src/lib/payhsm/bin/test-keymgr.sh
```

### Start the stack
```bash
# Console only (port 8765) — quickest
./scripts/start-console.sh

# Full stack: HSM + simulator backend + frontend + OpenBao
./start.sh     # → HSM: :8765 | Sim: :5173 | Bank API: :4000 | OpenBao: :8200
./stop.sh

# Manual
cd src/lib/payhsm && ./bin/payhsm-httpd 8765 ../../../frontend
```

Always open **http://127.0.0.1:8765** — never open `frontend/index.html` via `file://`.

---

## Architecture

### Three-layer stack

```
Browser / CLI
     │ HTTP REST + HSM wire commands
     ▼
payhsm-httpd (C, port 8765)          ← primary backend
     │
     ├── payhsm_core.c               provision / startup / key ops
     ├── payhsm_switch.c             switch-specific ops (ZMK/ZPK/PIN translate)
     ├── keymanager/                 LMK store, XOR fragments, Shamir, key vault
     ├── payment/                    PIN ISO 9564, MAC ISO 9797, EMV ARQC/ARPC, key exchange
     ├── defense/                    anti-dump, anti-ptrace (VALIDATED — do not touch)
     ├── net/                        TCP server + ISO config (TLS-capable)
     └── iso8583/                    ISO 8583 parser/packer

simulation/backend/server.js (Node.js/Express, port 4000)
     │  calls payhsm-httpd REST API
     └── services: GAB, Switch, EMV, MAC, cardService, OpenBao client

simulation/frontend/ (React/Vite, port 5173)
     └── GAB/ATM UI, Switch UI, ISO 8583 scenarios

simulation/openbao/ (Docker, port 8200)
     └── HashiCorp OpenBao — Switch key vault persistence
```

### Key structural detail: include-based composition

`payhsm-httpd.c` `#include`s two companion files directly (they are **not** compiled separately):
- `bin/payhsm-cmd-table.c` — error codes, HSM modes, key-type table, `calculate_kcv()`, `hsm_ok()`/`hsm_err()` builders, command registry, wire dispatcher
- `bin/payhsm-cmds.c` — handlers for B2, N0, NO, NI, NC and other utility commands

All `static` helpers in `payhsm-httpd.c` (e.g., `audit_log`, `hex_encode`, `hex_decode`, `secure_zero`) are therefore visible to the included files.

### Key blob format (under LMK)

```
[IV: 12 bytes][TAG: 16 bytes][KEY: 16–32 bytes]  = 44–60 bytes = 88–120 hex chars
```
Encrypted with AES-256-GCM using the recomposed LMK (P1 ⊕ P2 ⊕ P3).

### Data files (`payhsm-data/`)

| File | Content |
|------|---------|
| `mk.bin` | LMK encrypted AES-256-GCM under KEK (PBKDF2 passphrase) |
| `keys.vault` | Operational keys (TMK, TPK, TAK, ZMK, ZPK…) under LMK |
| `lmk_share_N.sss` | Shamir shares (3/3) — one per admin |

---

## Wire protocol

```
Request : [HEADER:4][COMMAND:2][PARAMS...]
Response: [HEADER:4][RESP_CMD:2][ERROR_CODE:2][DATA...]
```

The 4-byte header is always echoed back. HTTP endpoint: `POST /api/hsm/cmd` body `{"cmd":"0001A0001U"}`.

### Three operating modes

| Mode | Value | Description |
|------|-------|-------------|
| `INTERNAL` | 1 | Default — pipe-extended formats |
| `PAYSHIELD_COMPAT` | 2 | payShield-inspired formats [PS-INSPIRED, not officially conformant] |
| `LAB` | 3 | INTERNAL + `A8 flag V` (expose clear key — debug only) |

Switch mode: `POST /api/hsm/mode {"mode": "PAYSHIELD_COMPAT"}`.

### Implemented commands

| Command | Role | Notes |
|---------|------|-------|
| B2/B3 | Echo | Conformant, no init required |
| N0/N1 | Generate random | RAND_bytes, 8–64 bytes |
| NO/NP | HSM status | Inspired |
| NI/NJ | Network info | Inspired |
| NC/ND | Diagnostics | Inspired |
| A0/A1 | Generate key under LMK | INTERNAL wire or pipe; PAYSHIELD_COMPAT [PS-INSPIRED] |
| A6/A7 | Import key under ZMK→LMK | Decrypt + re-encrypt + KCV |
| A8/A9 | Consult/export key | flag H=KCV only, V=clear (LAB only) |
| KA/KB | Generate KCV | Wire or pipe by key ID |
| BU/BV | Generate/verify KCV | INTERNAL accepts clear key ⚠; PAYSHIELD mode refuses it |
| BW/BX | Re-wrap vault | |
| BS | Clear temp storage | |
| CA/CB | PIN block translate TPK→ZPK | |

Centralized error codes are in `payhsm-cmd-table.c` (`HSM_ERR_*` defines, e.g., `"00"` OK, `"10"` LMK absent, `"31"` LAB only).

---

## Invariant rules — critical

1. **NEVER modify** `defense.c`, `xor_fragment.c`, `demo_fragmentation.c` — VALIDATED
2. **NEVER** use AES-ECB for LMK storage — only AES-256-GCM
3. **NEVER** hardcode keys or passphrases
4. **Always** call `secure_zero()` after any secret buffer
5. **Always** use `RAND_bytes()` — never `fake_random()`
6. Defense setup (`anti_dump_setup`, `anti_ptrace_setup`) **must run before** any secret is loaded
7. Compile with `gcc -Wall -Wextra -lssl -lcrypto`
8. Include path: `-I src/lib/payhsm`
9. **Never log a clear key** — log only KCV and status

---

## PKCS#11 integration (pending)

The steps below are planned but not yet done:

- **`src/lib/SecureDataManager.cpp`** — replace `unmask()`/`remask()` to call `recompose_for_op()` (xor_fragment) and `mutate_fragments()` instead of the simple XOR mask
- **`src/lib/SoftHSM.cpp`** — call `anti_dump_setup()`, `anti_ptrace_setup()`, `fragment_lmk()` at the top of `SoftHSM::init()`
- **`src/lib/Makefile.am`** — add all payhsm C files and `-I$(srcdir)/payhsm`
- **`src/lib/payhsm/payment/pkcs11_payment.cpp`** — new file exposing `CKM_VENDOR_PIN_TRANSLATE`, `CKM_VENDOR_ARQC_VERIFY`, `CKM_VENDOR_MAC_CALCULATE`
