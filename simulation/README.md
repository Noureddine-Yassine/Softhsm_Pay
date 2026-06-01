# PayHSM — Simulation des flux ATM

Application **autonome** (backend + frontend) qui simule les deux flux de
retrait par carte bancaire et qui dialogue avec le HSM réel du projet
(`payhsm-httpd`, la lib C compilée). Aucun fichier existant du projet
n'est modifié — tout est ajouté dans `simulation/`.

## Ce que ça démontre

**Scénario 1 — INTRA-BANQUE** (carte Banque A sur GAB Banque A)
```
GAB-A → Switch-A → HSM-A (RÉEL = payhsm-httpd) → Core Banking A
```
La totalité du flux passe par le HSM réel : `/api/gap`, `/api/verify`
(PVV), `/api/corebanking/issue`.

**Scénario 2 — INTER-BANQUES** (carte Banque B sur GAB Banque A)
```
GAB-A → Switch-A → HSM-A → Réseau Central (CMI) → Switch-B → HSM-B → Core-B
                  TPK_A→ZPK_A         ZPK_A→ZPK_B           ZPK_B+PVK_B
```
Les HSM Banque A, Banque B et Réseau sont **simulés** (vraie crypto
3DES + ISO 9564-0 + PVV Visa) pour pouvoir illustrer le partage des ZPK
entre acteurs — ce que payhsm-httpd ne permet pas d'exporter
(sécurité by design).

Le HSM réel est sondé en permanence via `/api/health` pour prouver
l'intégration.

## Architecture

```
simulation/
├── backend/                    Node.js + Express (port 4000)
│   ├── server.js               API REST + flux SSE temps réel
│   ├── config.js
│   ├── crypto/
│   │   ├── des.js              3DES helpers (OpenSSL via node:crypto)
│   │   ├── pinblock.js         PIN Block ISO 9564-0
│   │   └── pvv.js              PVV Visa (PIN Verification Value)
│   ├── hsm/
│   │   ├── hsmReal.js          client HTTP vers payhsm-httpd (port 8765)
│   │   └── hsmSim.js           HSM-A sim, HSM-B, HSM-Network
│   ├── services/
│   │   ├── gab.js              logique GAB-A / GAB-B
│   │   ├── switchBank.js       logique Switch-A / Switch-B
│   │   └── networkCentral.js   routage par BIN + translation ZPK
│   ├── orchestrator/
│   │   ├── scenarioIntra.js
│   │   └── scenarioInter.js
│   ├── db/memdb.js             cartes pré-provisionnées
│   └── bus.js                  Event Bus pour SSE
└── frontend/                   React + Vite + Tailwind (port 5173)
    ├── index.html
    ├── tailwind.config.js
    ├── vite.config.js
    └── src/
        ├── App.jsx
        ├── api.js
        └── components/
            ├── Actor.jsx
            ├── FlowDiagram.jsx
            ├── HsmStatus.jsx
            ├── MessageBus.jsx
            ├── ResultBanner.jsx
            └── ScenarioControls.jsx
```

## Démarrage rapide

### 1) HSM réel (terminal 1)

Dans `src/lib/payhsm/` (le projet existant) :

```bash
cd src/lib/payhsm
./bin/payhsm-httpd 8765 ../../../frontend
```

Ouvre une fois `http://127.0.0.1:8765` (frontend existant), provisionne
(passphrase + dossier données + terminaux `ATM001,ATM002`) puis démarre
le HSM. Émets le PVV pour `4111111111111111` PIN `1234` via l'onglet
**Core Banking**.

### 2) Backend simulation (terminal 2)

```bash
cd simulation/backend
npm install
npm start
# → http://127.0.0.1:4000
```

### 3) Frontend simulation (terminal 3)

```bash
cd simulation/frontend
npm install
npm run dev
# → http://127.0.0.1:5173
```

Ouvre **http://127.0.0.1:5173** : tu verras le dashboard avec les deux
scénarios.

## Cartes pré-provisionnées

| Banque | PAN              | PIN  | Solde  |
|--------|------------------|------|--------|
| A      | 4111111111111111 | 1234 | 12500€ |
| A      | 4222222222222222 | 1234 | 8200€  |
| B      | 5500000000000004 | 1234 | 6400€  |
| B      | 5500000000000012 | 5678 | 3100€  |

(Côté Banque A le PVV doit être émis via le frontend HSM existant ; pour
l'INTRA scénario le backend tente une émission automatique.)

## API du backend simulation

| Méthode | Chemin                  | Description                                 |
|---------|-------------------------|---------------------------------------------|
| GET     | `/api/health`           | Backend + ping HSM réel                     |
| GET     | `/api/info`             | KCV des HSM simulés                         |
| GET     | `/api/cards`            | Cartes des deux banques                     |
| POST    | `/api/scenario/intra`   | Lance retrait intra-banque                  |
| POST    | `/api/scenario/inter`   | Lance retrait inter-banques                 |
| GET     | `/api/stream`           | SSE — flux temps réel des événements        |
| POST    | `/api/reset`            | Reset des soldes et du journal              |

Body POST `/api/scenario/*` :
```json
{ "pan": "5500000000000004", "pin": "1234", "amount": 300 }
```

## Crypto — pourquoi c'est "vrai"

- **PIN Block** : format ISO 9564-0 strict. Bloc1 (PIN+pad F) XOR Bloc2 (PAN 12 digits zero-prefixed) → 8 octets.
- **Chiffrement** : 3DES-EDE3 sur 8 octets (un bloc), équivalent au TDES-ECB banking standard. Clé 16 octets (3DES2) répliquée K1K2K1 pour faire 24 octets.
- **PVV Visa** : TSP = `right11(PAN) || PVKI || PIN(4)` (16 digits = 8 octets), chiffré 3DES sous PVK, puis extraction des 4 premiers digits décimaux (avec décalage hex A-F → 0-5 si nécessaire). Conforme à la spec Visa publique.
- **Translation TPK→ZPK** : déchiffrement sous TPK puis re-chiffrement sous ZPK dans la même fonction. Le PIN clair ne sort jamais.

Toute la crypto utilise `node:crypto` (OpenSSL en interne) — pas de
re-implémentation maison de DES.

## Intégration avec le HSM existant

Le client `hsm/hsmReal.js` appelle les endpoints publics de
`payhsm-httpd` :

- `GET  /api/health`
- `POST /api/gap` → PIN block sous TPK_A
- `POST /api/verify` → vérification PVV
- `POST /api/translate` → translation TPK→ZPK (le HSM-A réel a sa
  propre ZPK_A en interne, c'est utile pour démontrer le mécanisme
  côté HSM réel même si on n'utilise pas le résultat pour le scénario
  inter-banques)
- `POST /api/corebanking/issue` / `/api/corebanking/lookup`

Le statut du HSM réel est affiché en permanence dans le panneau
"État des HSM". Si le HSM est éteint, le scénario INTRA renvoie une
erreur claire ; le scénario INTER continue à fonctionner avec les HSM
simulés.

## Schémas pédagogiques

### Scénario INTRA-BANQUE

```
  Client                  GAB-A                  Switch-A                 HSM-A (réel)              BDD-A
    │                       │                       │                          │                       │
    │── PIN+PAN ──────────► │                       │                          │                       │
    │                       │── /api/gap ──────────────────────────────────►   │                       │
    │                       │   PIN block / TPK_A   │ ◄─── PIN block hex ──────│                       │
    │                       │                       │                          │                       │
    │                       │── retrait ──────────► │                          │                       │
    │                       │   PB + PAN + montant  │── lookup PAN ────────────────────────────────► │
    │                       │                       │ ◄────── PVV stocké + refs clés (chiffrées) ──── │
    │                       │                       │                          │                       │
    │                       │                       │── /api/verify ──────►    │                       │
    │                       │                       │   PB + PAN + terminal    │ déchiffre TPK,        │
    │                       │                       │                          │ déchiffre PB,         │
    │                       │                       │                          │ recompute PVV,        │
    │                       │                       │                          │ compare → APPROVED    │
    │                       │                       │ ◄── approved=true ──────│                       │
    │                       │ ◄── APPROVED ───────  │                          │                       │
    │ ◄── billets 💵        │                       │                          │                       │
```

### Scénario INTER-BANQUES

```
  Client       GAB-A       Switch-A       HSM-A       Réseau       Switch-B       HSM-B
    │            │            │             │            │             │            │
    │─ PIN+PAN─► │            │             │            │             │            │
    │            │── PB/TPK_A► │            │            │             │            │
    │            │            │── translate► │            │             │            │
    │            │            │   TPK_A→ZPK_A│            │             │            │
    │            │            │ ◄── PB/ZPK_A │            │             │            │
    │            │            │── 0200 ──────────────────► │           │            │
    │            │            │             │            │── translate ZPK_A→ZPK_B (HSM réseau)  │
    │            │            │             │            │── 0200/ZPK_B─► │        │
    │            │            │             │            │             │── verify ► │
    │            │            │             │            │             │  PB/ZPK_B  │
    │            │            │             │            │             │  +PAN+PVV  │
    │            │            │             │            │             │            │── déchiffre ZPK_B
    │            │            │             │            │             │            │── déchiffre PB
    │            │            │             │            │             │            │── recompute PVV
    │            │            │             │            │             │ ◄── OK ────│
    │            │            │             │            │ ◄── 0210 ── │            │
    │            │            │ ◄────────── relais ────  │             │            │
    │            │ ◄ APPROVED │             │            │             │            │
    │ ◄ billets  │            │             │            │             │            │
```

## Limitations / honnêteté

1. Le scénario inter-banques utilise des HSM **simulés** pour Bank A, Bank B et le Réseau car la lib C `payhsm-httpd` ne permet pas (et c'est sain) d'exporter ses ZPK pour les partager avec un autre HSM. La crypto reste réelle ; seule la "frontière HSM" est en mémoire JS au lieu d'être dans la lib C.
2. Les LMK simulées sont en mémoire process (pas chiffrées au repos). Sur un vrai HSM, la LMK serait protégée par TPM/TEE/HSM-physique — voir `defense.c` et `xor_fragment.c` côté projet principal pour les contre-mesures effectives.
3. Le Core Banking est simplifié à un solde en mémoire.
4. Pas de gestion ISO 8583 complète ; les messages "0200/0210" sont symboliques dans les logs.

Pour la soutenance : ces limitations sont les bonnes — elles montrent
les frontières du périmètre projet et où le payhsm "vrai" (lib C +
defense + fragmentation) prend le relais.
