# PayHSM — Claude Desktop Briefing

## Project Summary
PFE project : Soft HSM for secure payments.
Fork of SoftHSMv2 + 3 security layers added.
Repo : https://github.com/Schaib03/payhsm
Local path : ~/payhsm/payhsm
OS : Ubuntu 24.04, OpenSSL 3.x, GCC

---

## What has been done — DO NOT MODIFY these files

### defense/
- defense.h + defense.c        ✅ VALIDATED — do not touch
- seccomp_policy.h + seccomp_policy.c  ✅ VALIDATED — do not touch

### keymanager/
- xor_fragment.h + xor_fragment.c  ✅ VALIDATED — do not touch
- demo_fragmentation.c             ✅ VALIDATED — do not touch
- test_complet.c                   ✅ VALIDATED — do not touch

### payment/
- pin.h + pin.c           ✅ done
- mac.h + mac.c           ✅ done
- emv.h + emv.c           ✅ done
- key_exchange.h + key_exchange.c  ✅ done

---

## What needs to be done — PKCS#11 integration

### Goal
Integrate our security modules into SoftHSMv2 so that
the final binary exposes a standard PKCS#11 interface.

### Step 1 — Modify SecureDataManager.cpp
File : src/lib/SecureDataManager.cpp

Replace the unmask() and remask() functions to use
our xor_fragment.c instead of the simple XOR mask.

CURRENT CODE :
void SecureDataManager::unmask(ByteString& key) {
    key = maskedKey;
    key ^= *mask;
}

void SecureDataManager::remask(ByteString& key) {
    rng->generateRandom(*mask, 32);
    key ^= *mask;
    maskedKey = key;
}

TARGET CODE :
void SecureDataManager::unmask(ByteString& key) {
    uint8_t lmk[32];
    recompose_for_op(lmk);           /* from xor_fragment.c */
    key = ByteString(lmk, 32);
    secure_zero(lmk, 32);            /* from defense.c */
}

void SecureDataManager::remask(ByteString& key) {
    mutate_fragments();              /* from xor_fragment.c */
    secure_zero((uint8_t*)key.byte_str(), key.size());
}

### Step 2 — Modify SoftHSM.cpp
File : src/lib/SoftHSM.cpp

Add at the very beginning of SoftHSM::init() :
- Call anti_dump_setup()     from defense.c
- Call anti_ptrace_setup()   from defense.c
- Call fragment_lmk()        from xor_fragment.c
BEFORE any key is loaded into memory.

### Step 3 — Modify the build system
File : src/lib/Makefile.am

Add our C files to the build :
payhsm/defense/defense.c
payhsm/defense/seccomp_policy.c
payhsm/keymanager/xor_fragment.c
payhsm/payment/pin.c
payhsm/payment/mac.c
payhsm/payment/emv.c
payhsm/payment/key_exchange.c

Also add the include path : -I$(srcdir)/payhsm

### Step 4 — Add PKCS#11 payment commands
File : src/lib/payhsm/payment/pkcs11_payment.cpp (NEW FILE)

Create a wrapper that exposes our payment functions
through PKCS#11 vendor-defined mechanisms :
- CKM_VENDOR_PIN_TRANSLATE   → calls translate_pin_block()
- CKM_VENDOR_ARQC_VERIFY     → calls verify_arqc()
- CKM_VENDOR_MAC_CALCULATE   → calls calculate_mac_tak()

---

## Rules — VERY IMPORTANT

1. NEVER modify defense.c, xor_fragment.c, demo_fragmentation.c
2. NEVER use fake_random() — always use RAND_bytes()
3. NEVER use AES-ECB for LMK storage — only AES-256-GCM
4. NEVER hardcode keys or passphrases
5. Always call secure_zero() after using any secret buffer
6. The defense setup MUST happen BEFORE any secret is loaded
7. Compile with : gcc -Wall -Wextra -lssl -lcrypto
8. Include path : -I src/lib/payhsm

---

## How to compile and test

### Full build
./autogen.sh
./configure --with-crypto-backend=openssl --with-objectstore-backend-db
make -j$(nproc)

### Test PKCS#11
softhsm2-util --init-token --slot 0 --label "payhsm" \
               --so-pin 1234 --pin 5678
pkcs11-tool --module ./src/lib/.libs/libsofthsm2.so \
            --login --pin 5678 --test

### Test our modules
./demo_frag --init
./demo_frag
./test_complet

---

## Architecture overview

Application (banking app)
      |
      | PKCS#11 standard calls
      v
libsofthsm2.so  (SoftHSMv2 + our modifications)
      |
      |-- SecureDataManager  (modified to use xor_fragment)
      |-- SoftHSM.cpp        (modified to call defense setup)
      |
      v
our modules
      |-- defense.c          (anti-dump, anti-ptrace)
      |-- xor_fragment.c     (LMK fragmentation P1/P2/P3)
      |-- pin.c              (PIN Block ISO 9564)
      |-- mac.c              (MAC ISO 9797-1)
      |-- emv.c              (ARQC/ARPC EMV)
      |-- key_exchange.c     (TMK/TPK/ZMK/ZPK)

---

## Current file structure

src/lib/payhsm/
├── defense/
│   ├── defense.h
│   ├── defense.c
│   ├── seccomp_policy.h
│   └── seccomp_policy.c
├── keymanager/
│   ├── xor_fragment.h
│   ├── xor_fragment.c
│   ├── demo_fragmentation.c
│   └── test_complet.c
└── payment/
    ├── pin.h + pin.c
    ├── mac.h + mac.c
    ├── emv.h + emv.c
    └── key_exchange.h + key_exchange.c