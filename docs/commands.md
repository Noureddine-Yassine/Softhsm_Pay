# PayHSM — Documentation des Commandes Wire

> **Important** : Ce projet est un émulateur logiciel éducatif inspiré du Thales payShield 10K.  
> Les formats en mode `PAYSHIELD_COMPAT` sont **[PS-INSPIRED]** — inspirés de la documentation  
> publique payShield, **non officiellement conformes** sans documentation officielle Thales.  
> Seul le format `B2/B3 Echo` et `N0/N1 Random` sont documentés publiquement et considérés conformes.

---

## Architecture des modes

| Mode | Valeur | Description |
|------|--------|-------------|
| `INTERNAL` | 1 | **Défaut** — formats pipe-étendus du projet, rétrocompatibles |
| `PAYSHIELD_COMPAT` | 2 | Formats **[PS-INSPIRED]** proches payShield 10K |
| `LAB` | 3 | INTERNAL + `A8 flag V` autorisé (debug uniquement) |

### Changer de mode
```
GET  /api/hsm/mode          → mode actuel
POST /api/hsm/mode  {"mode": "PAYSHIELD_COMPAT"}
```

---

## Format général des trames

```
Requête  : [HEADER:4][COMMAND:2][PARAMS...]
Réponse  : [HEADER:4][RESP_CMD:2][ERROR_CODE:2][DATA...]
```

Le HEADER de la requête est **toujours conservé** dans la réponse.

### Codes erreur centralisés

| Code | Description |
|------|-------------|
| `00` | Succès |
| `02` | Format de trame invalide |
| `04` | Longueur invalide |
| `05` | Échec cryptographique (LMK/déchiffrement) |
| `10` | LMK absente |
| `15` | HSM non initialisé |
| `21` | Clé non exportable |
| `30` | Mode non autorisé |
| `31` | LAB uniquement (ex: A8 flag V) |
| `40` | Commande non supportée |

---

## Commandes — Référence

### B2/B3 — Echo ✅ CONFORME

```
Requête  : [HDR:4][B2][DATA:opt]
Réponse  : [HDR:4][B3][00][DATA:opt]
Exemple  : 0001B2HELLO  →  0001B300HELLO
```
Ne requiert pas d'initialisation HSM.

---

### N0/N1 — Generate Random ✅ CONFORME

```
Requête  : [HDR:4][N0][LEN_HEX:2]    (LEN: 08–40 hex)
Réponse  : [HDR:4][N1][00][RANDOM_HEX]
Exemple  : 0001N010  →  0001N100<32hex>
```
Générateur : `RAND_bytes` (CSPRNG OpenSSL).

---

### NO/NP — HSM Status ⚠ INSPIRÉ

```
Requête  : [HDR:4][NO]
Réponse  : [HDR:4][NP][00][STATE|LMK_LOADED=x|KEYS=n|...]
```

### NI/NJ — Network Information ⚠ INSPIRÉ

```
Requête  : [HDR:4][NI]
Réponse  : [HDR:4][NJ][00][HOST=x|PORT=y|PROTO=z|...]
```

### NC/ND — Diagnostics ⚠ INSPIRÉ

```
Requête  : [HDR:4][NC]
Réponse  : [HDR:4][ND][00][MEMORY=x|VAULT=x|RNG=x|LMK=x|UPTIME=n|...]
```

---

### A0/A1 — Generate Key

**Mode INTERNAL (défaut)**
```
Requête wire  : [HDR:4][A0][KEYLEN_HEX:2][KEYTYPE_HEX:2][SCHEME:1]   = 11 chars
  Exemple     : 0001A01001U  (len=16, type=01=TMK, scheme=U)
Requête pipe  : [HDR:4][A0|TYPE|LEN|SCHEME|EXPORT]
  Exemple     : 0001A0|ZPK|16|U|1
Réponse A1    : [HDR:4][A1][00][SCHEME:1][KEY_UNDER_LMK:88][KCV:6]
```

**Mode PAYSHIELD_COMPAT [PS-INSPIRED]**
```
Requête  : [HDR:4][A0][KEY_TYPE:3][KEY_SCHEME:1]   = 10 chars min
  Exemple  : 0001A0001U  (type=001=ZPK, scheme=U)
Réponse  : [HDR:4][A1][00][SCHEME:1][KEY_UNDER_LMK:88][KCV:6]
```

Table des types [PS-INSPIRED — codes internes, non officiels Thales] :

| Code | Nom | Description |
|------|-----|-------------|
| 000 | ZMK | Zone Master Key |
| 001 | ZPK | Zone PIN Key |
| 002 | PVK | PIN Verification Key |
| 003 | CVK | Card Verification Key |
| 006 | TPK | Terminal PIN Key |
| 007 | TMK | Terminal Master Key |
| 008 | TAK | Terminal Auth Key |
| 009 | ZAK | Zone Auth Key |
| 00A | ZEK | Zone Encryption Key |
| 00B | IMK | Issuer Master Key |
| 00C | KEK | Key Encryption Key |
| 00D | BDK | Base Derivation Key |

---

### A8/A9 — Consult/Export Key (mode INTERNAL)

```
Requête wire  : [HDR:4][A8][KEYLEN:2][FLAG:1][KEY_UNDER_LMK:88]   = 97 chars
  FLAG=H      : retourne KCV seulement (défaut sécurisé)
  FLAG=V      : retourne clé claire + KCV — INTERDIT hors mode LAB (err 31)
Réponse H     : [HDR:4][A9][00][KEYLEN:2][KCV:6]
Réponse V LAB : [HDR:4][A9][00][KEYLEN:2][KEY_CLEAR:32][KCV:6]

Requête pipe  : [HDR:4][A8|KEY_ID|TTYPE|TID|SCHEME]
```

---

### KA/KB — Generate KCV

**Mode INTERNAL — wire**
```
Requête  : [HDR:4][KA][KEYLEN:2][SCHEME:1][KEY_UNDER_LMK:88]   = 97 chars
Réponse  : [HDR:4][KB][00][KEYLEN:2][SCHEME:1][KCV:6]
Exemple  : 0001KA10U<88hex>
```

**Mode INTERNAL — pipe**
```
Par ID   : 0001KA|KEY_ID
RAW      : 0001KA|RAW|AES|<32hex>
```

**Mode PAYSHIELD_COMPAT [PS-INSPIRED]**
```
Requête  : [HDR:4][KA][KEY_TYPE:3][KEY_SCHEME:1][KEY_UNDER_LMK:88]   = 98 chars
Réponse  : [HDR:4][KB][00][KCV:6]
Exemple  : 0001KA001U<88hex>
```

---

### BU/BV — Generate/Verify KCV

**Mode INTERNAL (accepte clé en clair — usage développement)**
```
Générer  : [HDR][BU][G][KEY_HEX:32/48/64]
Vérifier : [HDR][BU][V][KEY_HEX][KCV:6]
```

**Mode PAYSHIELD_COMPAT (clé en clair REFUSÉE — sécurisé)**
```
Générer  : [HDR][BU][G][KEY_TYPE:3][KEY_SCHEME:1][KEY_UNDER_LMK:88]   = 99 chars
Vérifier : [HDR][BU][V][KEY_TYPE:3][KEY_SCHEME:1][KEY_UNDER_LMK:88][KCV:6]   = 105 chars
Réponse  : [HDR][BV][00][KCV:6]       (génération)
           [HDR][BV][00]              (vérification OK)
           [HDR][BV][07]EXPECTED=XX|COMPUTED=YY  (KCV mismatch)
```

---

### KCV — Calcul unifié

Toutes les commandes utilisent la même fonction `calculate_kcv()` :
- **AES-128** : `AES-ECB(key, 16_zeros)[0..2]`
- **AES-192/256** : idem avec AES-192/256
- **DES (8 octets)** : `DES-ECB(key, 8_zeros)[0..2]`

Les KCV retournés par A0, KA, BU pour la même clé sont **identiques**.

---

## Exemples de trames prêtes à tester

```bash
# Mode INTERNAL (défaut)
0001B2HELLO                           # Echo
0001N010                              # 16 octets aléatoires
0001NO                                # Statut HSM
0001A01001U                           # Générer TMK AES-128
0001A0|ZPK|16|U|1                     # Générer ZPK (pipe)
0001KA10U<CRYPT_88HEX>                # KCV d'une clé sous LMK
0001A810H<CRYPT_88HEX>                # KCV sans exposer la clé
0001BS                                # Effacer stockage temporaire
0001BW                                # Re-envelopper vault

# Mode PAYSHIELD_COMPAT [PS-INSPIRED]
0001A0001U                            # Générer ZPK
0001A0000U                            # Générer ZMK
0001KA001U<CRYPT_88HEX>               # KCV (KEY_TYPE:3)
0001BUG001U<CRYPT_88HEX>              # BU sécurisé (KEY_UNDER_LMK)
```

---

## Différences INTERNAL vs PAYSHIELD_COMPAT

| Commande | INTERNAL | PAYSHIELD_COMPAT |
|----------|----------|-----------------|
| A0 | `[KEYLEN:2][KEYTYPE_HEX:2][SCHEME:1]` OU pipe | `[KEY_TYPE:3][KEY_SCHEME:1]` |
| KA | `[KEYLEN:2][SCHEME:1][KEY:88]` OU pipe | `[KEY_TYPE:3][KEY_SCHEME:1][KEY:88]` |
| BU | Accepte clé en CLAIR ⚠ | Refuse clé en clair, KEY_UNDER_LMK obligatoire ✅ |
| A8 flag V | Disponible en LAB seulement | N/A |

---

## Limites du prototype

1. **Sans documentation officielle Thales** : les codes KEY_TYPE 3-chars sont internes au projet et peuvent différer des vrais codes payShield.
2. **Pas de TLS** : le protocole est HTTP (pour LAB). En production, utiliser un proxy TLS.
3. **Pas de framing TCP** : chaque commande est dans un POST HTTP séparé. Un vrai HSM payShield utilise des sessions TCP avec framing de longueur.
4. **LMK unique** : le projet supporte une seule LMK en mémoire. Un vrai payShield gère des ensembles LMK multiples.
5. **AES uniquement** : le projet cible AES-128 principalement (clés 16 octets). Le payShield supporte aussi DES/3DES avec des modes différents.
