# PayHSM — SoftHSMv2 integration report

This document is the short companion to the integration pass. It lists
every file that was touched, what was added, why, and how to
build / test / demo the result.

## TL;DR

| Layer | Before | After |
| --- | --- | --- |
| Per-token master key protection | Single XOR mask | LMK recomposed from 3 mutating fragments (P1/P2/P3) |
| Defense setup | Not wired in the .so | Armed at `C_Initialize` (anti-dump, anti-ptrace, LMK fragment) |
| Payment primitives | Static C modules, no entry point in the .so | Exported through a stable C ABI from `libsofthsm2.so` |
| PFE demo path | None | Flask UI calling the .so via ctypes |

Nothing under `src/lib/payhsm/defense/` or `src/lib/payhsm/keymanager/`
that was marked **VALIDATED — do not touch** in `CLAUDE.md` was changed.

## Files touched

### 1. `src/lib/data_mgr/SecureDataManager.cpp`

Replaced the simple `*mask ^= rand` mechanism in `unmask()` / `remask()`
with calls into `recompose_for_op()` / `mutate_fragments()` from
`xor_fragment.c`. Defensive fallback: if the fragmentation hasn't been
initialised, the original masking is used and an error is logged — the
daemon doesn't crash.

`secure_zero()` from `defense.c` wipes every stack-resident copy of the
LMK on the way out.

### 2. `src/lib/SoftHSM.cpp`

Added a once-only helper `payhsm_arm_defense_once()` that runs:

1. `anti_dump_setup()`
2. `anti_ptrace_setup()`
3. `RAND_bytes(lmk, 32)` followed by `fragment_lmk(lmk)` and a
   `secure_zero()` of the local LMK buffer.

The helper is called at the very top of `C_Initialize`, right after the
"already initialised" guard, so it runs once per `dlopen()` and *before*
any key material is loaded into memory (the third rule from `CLAUDE.md`).

### 3. `src/lib/Makefile.am`

Added the C files to `libsofthsm2_la_SOURCES`, plus the new
`pkcs11_payment.cpp` wrapper, and a `-I$(srcdir)` to the CPPFLAGS so
the `payhsm/...` includes resolve. `seccomp_policy.c` is **not** built
into the .so — it would add a `libseccomp-dev` build dependency that
the in-tree defenses don't actually require.

### 4. `src/lib/payhsm/payment/pkcs11_payment.{h,cpp}` (NEW)

Thin C ABI in front of the payment functions, with explicit
`visibility("default")` so the symbols survive SoftHSMv2's
`-fvisibility=hidden` build flag. Each call first asks
`verify_integrity_quiet()` whether the LMK fragments are still
consistent and only then forwards to the underlying C function.

Exported symbols:

```
PayHSM_is_ready
PayHSM_version
PayHSM_PIN_build
PayHSM_PIN_translate
PayHSM_ARQC_verify
PayHSM_EMV_derive_sk_ac
PayHSM_EMV_compute_arqc
PayHSM_MAC_calculate
```

### 5. `build_and_test.sh` (NEW, repo root)

End-to-end build + smoke-test:

- checks apt prerequisites (`build-essential`, `libssl-dev`,
  `libsqlite3-dev`, `opensc`, etc.)
- runs `autogen.sh` / `configure` / `make` if needed
- verifies every `PayHSM_*` symbol shows up in
  `nm -D --defined-only`
- spins up a throw-away `softhsm2.conf`, runs
  `softhsm2-util --init-token` and `pkcs11-tool --module ... --test`

### 6. `tools/payhsm_demo/` (NEW)

Flask web demo. `app.py` `ctypes.CDLL`s the freshly-built
`libsofthsm2.so`, calls `C_Initialize(NULL)` to arm the defenses, and
exposes a JSON API that the single-page `index.html` consumes.

## Why a C ABI and not vendor PKCS#11 mechanisms?

`CKM_VENDOR_PIN_TRANSLATE` & friends would have required editing
SoftHSM's mechanism table, the per-call dispatch in `C_EncryptInit` /
`C_SignInit` / `C_VerifyInit`, parameter struct definitions, and a
mechanism-info entry. That is a sizeable, error-prone change for what
is fundamentally a PFE demonstrator.

The compromise: a small stable C ABI in the same `.so`. Standard
PKCS#11 clients (`pkcs11-tool`, `pkcs11-spy`, `Java SunPKCS11`) still
see the unchanged SoftHSM surface, while the demo and any banking-side
client can reach the payment primitives through a single `dlsym()`.

## How to use

```bash
# 1. Build + smoke-test (once)
cd ~/payhsm/payhsm
./build_and_test.sh

# 2. Start the demo
cd tools/payhsm_demo
./run_demo.sh
# → http://127.0.0.1:5000
```

In the UI:

- **PIN block translate** — type a PIN and PAN, click *random* on TPK
  and ZPK, then *Build & translate*. You should see two different
  8-byte hex strings; the cleartext PIN never leaves the .so.
- **EMV ARQC round-trip** — generate an MK-AC, click *Run round-trip*.
  The browser shows the derived SK-AC, the demo transaction blob, the
  ARQC, and the verification result.
- **Retail MAC** — generate a TAK, edit the message, click *Calculate*.

## Self-checks

If anything below fails, the integration is wrong:

```bash
# All PayHSM symbols exported?
nm -D --defined-only src/lib/.libs/libsofthsm2.so | grep PayHSM_

# LMK fragmentation reachable from the .so?
python3 -c "import ctypes; l=ctypes.CDLL('src/lib/.libs/libsofthsm2.so'); \
    l.C_Initialize(None); print('ready=', l.PayHSM_is_ready())"

# Standard PKCS#11 surface still works?
SOFTHSM2_CONF=/tmp/payhsm.conf softhsm2-util --init-token --free \
    --label payhsm --so-pin 1234 --pin 5678
SOFTHSM2_CONF=/tmp/payhsm.conf pkcs11-tool \
    --module src/lib/.libs/libsofthsm2.so --login --pin 5678 --test
```

## Known limitations

- The PFE design ties every token to the *same* fragmented LMK; that is
  the explicit goal in `CLAUDE.md` but it's worth being explicit about
  the tradeoff vs. SoftHSMv2's original per-token master key.
- `anti_ptrace_setup()` calls `PTRACE_TRACEME` — running the daemon
  under gdb will fail at startup. That is the intended behaviour.
- `seccomp_policy.c` is shipped in the tree but not in the .so build to
  keep the dependency surface small. Re-add it to `libsofthsm2_la_SOURCES`
  and `-lseccomp` if you want it.

## Repo layout after the change

```
payhsm/payhsm/
├── build_and_test.sh                       NEW
├── INTEGRATION.md                          NEW (this file)
├── src/lib/
│   ├── Makefile.am                         modified
│   ├── SoftHSM.cpp                         modified
│   ├── data_mgr/SecureDataManager.cpp      modified
│   └── payhsm/
│       ├── defense/                        unchanged
│       ├── keymanager/                     unchanged
│       └── payment/
│           ├── pin.{c,h}                   unchanged
│           ├── mac.{c,h}                   unchanged
│           ├── emv.{c,h}                   unchanged
│           ├── key_exchange.{c,h}          unchanged
│           ├── pkcs11_payment.h            NEW
│           └── pkcs11_payment.cpp          NEW
└── tools/payhsm_demo/                      NEW
    ├── app.py
    ├── run_demo.sh
    ├── README.md
    └── templates/index.html
```
