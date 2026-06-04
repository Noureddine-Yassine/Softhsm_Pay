# Manuel opérateur — échange clés PayHSM → Switch

**Prérequis :** `MODE PAYSHIELD` · `startup` · `SWITCH INIT`

**Clés de transport** (une fois, cérémonie A2/A4) :
- **ZMK** → pour ZPK, PVK, IMK
- **TMK** → pour TPK, TAK

Pour chaque clé métier : **A0** → **A8/L** (KEK lue dans le coffre) → **SWITCH PULL**.

Raccourcis console : `KEYEX TPK` · `A8 TPK` · variables `$zpk_88`, `$tpk_88`, …

---

## Préambule — ZMK et TMK (pas d’A8/PULL)

### ZMK

```text
0001NE|ZMK|16|3|Y
0001A4|ZMK|U|3|$comp1|$comp2|$comp3
SWITCH STORE ZMK ZMK $zmk $kcv
```

### TMK

```text
0001NE|TMK|16|3|Y
0001A4|TMK|U|3|$comp1|$comp2|$comp3
SWITCH STORE TMK TMK $tmk $kcv
```

---

## ZPK (sous ZMK)

| Étape | Commande |
|-------|----------|
| 1 | `0001A00001U00` |
| 2 | `0001A8L001U$zpk_88` ou `A8 ZPK` ou `0001A8\|ZPK_00029` |
| 3 | `SWITCH PULL ZPK ZPK $enc $kcv` |

---

## TPK (sous TMK)

| Étape | Commande |
|-------|----------|
| 1 | `0001A00002U00` |
| 2 | `0001A8L002U$tpk_88` ou `A8 TPK` ou `0001A8\|TPK_xxxxx` |
| 3 | `SWITCH PULL TPK TPK $enc $kcv` |

---

## TAK (sous TMK)

| Étape | Commande |
|-------|----------|
| 1 | `0001A00003U00` |
| 2 | `0001A8L003U$tak_88` ou `A8 TAK` ou `0001A8\|TAK_xxxxx` |
| 3 | `SWITCH PULL TAK TAK $enc $kcv` |

---

## PVK (sous ZMK)

| Étape | Commande |
|-------|----------|
| 1 | `0001A00008U00` |
| 2 | `0001A8L008U$pvk_88` ou `A8 PVK` ou `0001A8\|PVK_xxxxx` |
| 3 | `SWITCH PULL PVK PVK $enc $kcv` |

---

## IMK (sous ZMK)

| Étape | Commande |
|-------|----------|
| 1 | `0001A00109U00` |
| 2 | `0001A8L109U$imk_88` ou `A8 IMK` ou `0001A8\|IMK_xxxxx` |
| 3 | `SWITCH PULL IMK IMK $enc $kcv` |

---

## Format A8/L (99 car.)

```text
0001 + A8 + L + [TYPE 3 ch.] + U + [cryptogramme clé 88 hex]
```

| Clé | TYPE | KEK coffre |
|-----|------|------------|
| ZPK | `001` | ZMK |
| TPK | `002` | TMK |
| TAK | `003` | TMK |
| PVK | `008` | ZMK |
| IMK | `109` | ZMK |

**Ne pas** utiliser le bloc LMK 33 car. (`UA3D30…`) dans A8 — utiliser le **cryptogramme** 88 hex affiché après A0 (`$zpk_88`, etc.).

---

## Variables console

| Après | Variable |
|-------|----------|
| A0 | `$zpk_88`, `$tpk_88`, `$tak_88`, `$pvk_88`, `$imk_88`, `$kcv` |
| A8 | `$enc` (bloc 33 sous ZMK/TMK), `$kcv` |
| A4 ZMK/TMK | `$zmk`, `$tmk` (88 hex) |

---

## Ordre recommandé (session complète)

```text
MODE PAYSHIELD
startup
SWITCH INIT
(cérémonie ZMK + TMK si besoin)
0001A00001U00  →  0001A8L001U$zpk_88  →  SWITCH PULL ZPK ZPK $enc $kcv
0001A00002U00  →  0001A8L002U$tpk_88  →  SWITCH PULL TPK TPK $enc $kcv
0001A00003U00  →  0001A8L003U$tak_88  →  SWITCH PULL TAK TAK $enc $kcv
0001A00008U00  →  0001A8L008U$pvk_88  →  SWITCH PULL PVK PVK $enc $kcv
0001A00109U00  →  0001A8L109U$imk_88  →  SWITCH PULL IMK IMK $enc $kcv
```

---

## Dépannage KCV (TPK)

Si `SWITCH PULL TPK` échoue avec `attendu=… calcule=…` :

1. **A8/L TPK** doit être `0001A8L002U$tpk_88` (TYPE `002`, KEK **TMK**), jamais `L001` (ZMK).
2. Le KCV après A8 doit être **identique** au KCV affiché après A0 (ex. `83779A`). Sinon refaire A0 puis A8.
3. TMK doit être dans `ext_keys` (cérémonie `0001A4` TMK + `SWITCH STORE TMK`).
4. Recharger la console (F5) après mise à jour — une ancienne version réécrivait `L002` en `L001` à cause de `001` dans l'en-tête `0001`.

## Simulation GAB

Le GAB utilise directement **`TPK`** et **`TAK`** du coffre Switch (ids `TPK` / `TAK` après `SWITCH PULL`).

Les anciens alias `TPK-ATM001` / `TAK-ATM001` sont supprimés automatiquement au chargement du coffre.

## Persistance du coffre Switch

Chaque `SWITCH PULL` / `STORE` sauvegarde automatiquement sur **disque** (`simulation/backend/data/switch-vault.json`) et **OpenBao** (si actif), lié à l’empreinte LMK.

- **Actualiser** (UI Banque) : recharge depuis mémoire ; restaure depuis disque/OpenBao si le backend a redémarré.
- **Restaurer (SWITCH INIT)** : recharge explicitement depuis disque/OpenBao (même LMK).
- Si le coffre semble vide après F5 : cliquez **Actualiser** ou tapez `SWITCH INIT` dans le terminal HSM.
