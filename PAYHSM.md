# PayHSM — HSM de paiement (C / OpenSSL)

Backend réel : LMK chiffrée sur disque, fragmentation XOR P1/P2/P3, coffre de clés dérivées sous LMK, opérations PIN / translation pour GAP et switch.

## Architecture

```
LMK (32 octets, aléatoire)
  ├── lmk.bin          AES-256-GCM sous KEK (PBKDF2 passphrase)
  ├── P1 / P2 / P3     fragments XOR + HMAC intégrité
  └── key_vault        TMK, TPK, TAK, ZMK, ZPK, PVK, IMK dérivés (HMAC-SHA256 labels)

GAP  ──► payhsmd ──► generate_pin_block (TPK)
HSM  ──► verify_encrypted_pin_block (TPK + PVK + PVV)
Switch ──► translate_pin_block (TPK → ZPK)
```

Aucune clé en dur dans le code : tout est provisionné depuis la LMK au premier `provision`.

## Build

```bash
cd src/lib/payhsm
make clean all test
```

Cibles : `libpayhsm.a`, `bin/payhsm-test`, `bin/payhsmd`, `bin/payhsm-cli`.

## Utilisation

```bash
# Terminal 1 — daemon
./bin/payhsmd

# Terminal 2 — provision (une fois)
./bin/payhsm-cli provision "ma-passphrase" ./payhsm-data ATM001,ATM002

# Chaque session
./bin/payhsm-cli startup "ma-passphrase" ./payhsm-data
./bin/payhsm-cli status
./bin/payhsm-cli register 4111111111111111 1234
./bin/payhsm-cli gap ATM001 1234 4111111111111111
# → pin block hex sous TPK
./bin/payhsm-cli verify ATM001 4111111111111111 &lt;hex&gt;
./bin/payhsm-cli translate ATM001 &lt;hex&gt;
```

Variables : `PAYHSM_SOCK`, `PAYHSM_DATA`, `PAYHSM_PASS`.

## Fichiers de données (`payhsm-data/`)

| Fichier | Rôle |
|---------|------|
| `lmk.bin` | LMK chiffrée (sel + nonce + ciphertext + tag) |
| `keys.vault` | Clés opérationnelles chiffrées sous LMK |
| `cards.pvv` | PVV par PAN (issuer) |

## Modules

- `keymanager/` — LMK, KEK, fragmentation, vault
- `payment/` — PIN ISO 9564, EMV, MAC, key exchange
- `defense/` — anti-dump, ptrace
- `payhsm_core.c` — orchestration provision / GAP / verify / translate
- `bin/payhsmd.c` — socket Unix `/tmp/payhsm.sock`
- `bin/payhsm-cli.c` — client

## Frontend (console de test)

Interface web branchée sur la **lib C réelle** via `payhsm-httpd` :

```bash
# Depuis la racine du projet (recommandé)
chmod +x scripts/start-console.sh
./scripts/start-console.sh

# Ou manuellement :
cd src/lib/payhsm
make bin/payhsm-httpd
./bin/payhsm-httpd 8765 ../../../frontend
```

**Important** : ouvrir **http://127.0.0.1:8765** dans le navigateur.  
Ne pas ouvrir `frontend/index.html` en `file://` — l’API sera « hors ligne ».

Onglets : Setup (provision/startup), Dashboard (clés + LMK), GAP, HSM verify, Switch ZPK, Cartes PVV, EMV ARQC/ARPC, MAC TAK, scénario PIN complet.

Aucune crypto dans le navigateur — toutes les requêtes passent par l’API REST → `libpayhsm`.

## Tests

```bash
make test   # 28 scénarios unitaires (clés éphémères en RAM, hors vault)
```
