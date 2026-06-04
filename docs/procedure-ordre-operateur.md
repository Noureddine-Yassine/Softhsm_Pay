# Repartir à zéro + garder le coffre Switch au redémarrage

## Règle de persistance (même LMK)

| Où | Fichier | Quand c’est rechargé |
|----|---------|----------------------|
| **PayHSM** | `<dataDir>/ext_keys.vault` + `keys.vault` | `startup` / Shamir + **même répertoire données** |
| **Switch** | `simulation/backend/data/switch-vault.json` | `SWITCH INIT` ou démarrage backend si HSM déjà up |

Le coffre Switch est lié à **`hmacRefPrefix`** de la LMK (empreinte).  
**Même LMK + même dataDir PayHSM** → les clés Switch reviennent après redémarrage.  
**Nouvelle LMK** → le Switch efface automatiquement l’ancien coffre.

Chaque `SWITCH STORE` / `SWITCH PULL` **sauvegarde sur disque** immédiatement.

---

## A. Tout régénérer (ZMK incluse)

### 1. Effacer l’ancien (une fois)

**Terminal PayHSM (:8765)**

```text
vault clear
```

*(ou supprimer à la main dans votre `dataDir` : `ext_keys.vault`, `keys.vault`)*

**Terminal / simulateur Switch (:4000)**

```text
SWITCH RESET
```

### 2. Session HSM (garder votre LMK actuelle)

```text
startup
MODE PAYSHIELD
SWITCH INIT
VARS
```

`SWITCH INIT` restaure le coffre Switch s’il existe déjà pour cette LMK (après reset : vide, c’est normal).

---

## B. Ordre des clés (tout neuf)

### B0 — ZMK (A2 + A4, comme avant)

```text
0001NE|ZMK|16|3|Y
0001A4|ZMK|U|3|$comp1|$comp2|$comp3
SWITCH STORE ZMK ZMK $zmk $kcv
```

Vérifier : `vault` (onglet Coffre) ou `VARS` → `$zmk` = 88 hex.

---

### B1 — TMK (même cérémonie)

```text
0001NE|TMK|16|3|Y
0001A4|TMK|U|3|$comp1|$comp2|$comp3
SWITCH STORE TMK TMK $tmk $kcv
```

---

### B2 — ZPK

```text
0001A00001U00
0001A8L001U$zpk_88
SWITCH PULL ZPK ZPK $enc $kcv
```

---

### B3 — TPK

```text
0001A00002U00
0001A8L002U$tpk_88
SWITCH PULL TPK TPK $enc $kcv
```

---

### B4 — TAK

```text
0001A00003U00
0001A8L003U$tak_88
SWITCH PULL TAK TAK $enc $kcv
```

---

### B5 — PVK

```text
0001A00008U00
0001A8L008U$pvk_88
SWITCH PULL PVK PVK $enc $kcv
```

---

### B6 — IMK

```text
0001A00109U00
0001A8L109U$imk_88
SWITCH PULL IMK IMK $enc $kcv
```

---

## C. Après redémarrage (même LMK)

1. Reconstruire LMK (Shamir) ou `startup` — **ne pas** faire **Provision** (nouvelle LMK) si vous voulez garder les clés.
2. **Même répertoire données** PayHSM que lors de la génération.
3. Terminal :

```text
startup
MODE PAYSHIELD
SWITCH INIT
```

4. Vérifier :

```text
SWITCH STATUS
vault
```

Vous devez revoir ZMK, TMK, ZPK, TPK, etc. côté Switch.

---

## À ne pas faire si vous voulez conserver les clés

- **Provision** PayHSM (nouvelle LMK) sans sauvegarde
- Changer de **répertoire données** entre sessions
- **`SWITCH RESET`** sauf vraie regénération complète
- Nouvelle LMK (TRNG) → efface le coffre Switch lié à l’ancienne empreinte

---

## Aide

```text
KEYEX ZPK
SWITCH LOGS-A6
```
