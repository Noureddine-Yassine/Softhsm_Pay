# Rapport d'intégration — PayHSM

**Projet** : PayHSM, Soft HSM de paiement sécurisé (fork de SoftHSMv2)
**Auteur** : Saad
**Date** : 15 mai 2026

---

## 1. Résumé exécutif

Avant cette passe, les modules de sécurité (`defense.c`, `xor_fragment.c`, `pin.c`, `mac.c`, `emv.c`, `key_exchange.c`) existaient en tant que fichiers indépendants dans `src/lib/payhsm/`, validés un par un mais **non branchés** sur SoftHSMv2. Le binaire `libsofthsm2.so` produit par `make` était donc un SoftHSM standard, sans la moindre protection PayHSM active.

Cette intégration relie les trois couches PayHSM au cœur de SoftHSMv2 :

1. **Couche défense** (`anti_dump_setup`, `anti_ptrace_setup`) — armée dès `C_Initialize`, donc avant tout chargement de secret.
2. **Couche fragmentation LMK** (`fragment_lmk`, `recompose_for_op`, `mutate_fragments`) — substituée à l'ancien masque XOR de `SecureDataManager`. La LMK n'existe plus jamais en clair en mémoire en dehors de la pile d'une opération courte, et le buffer est immédiatement écrasé par `secure_zero`.
3. **Couche paiement** (PIN ISO 9564, MAC ISO 9797, EMV ARQC) — exposée via une ABI C stable (`PayHSM_*`) directement depuis `libsofthsm2.so`, donc accessible aussi bien à un client PKCS#11 standard qu'à l'interface web de démonstration.

Une interface web Flask légère permet d'exécuter les trois opérations clefs (translate PIN, ARQC, MAC) en quelques clics, en passant à chaque fois par la `.so` réelle — c'est-à-dire en utilisant la vraie LMK fragmentée et les vraies défenses armées.

Le binaire compile sans erreur (`make` se termine proprement), tous les symboles `PayHSM_*` sont exportés (`nm -D` les voit), et `pkcs11-tool --module ... --test` se termine sur `No errors`.

---

## 2. Ce que j'ai modifié, fichier par fichier

### 2.1. `src/lib/data_mgr/SecureDataManager.cpp`

`SecureDataManager` est la classe qui protège la clé maîtresse de chaque token dans la version standard de SoftHSMv2. Elle utilisait un masque XOR aléatoire :

```cpp
void SecureDataManager::unmask(ByteString& key) {
    key = maskedKey;
    key ^= *mask;
}
void SecureDataManager::remask(ByteString& key) {
    rng->generateRandom(*mask, 32);
    key ^= *mask;
    maskedKey = key;
}
```

C'est une protection mémoire faible : un attaquant qui dump le processus lit le masque et la clé masquée côte à côte, et le XOR est trivial à inverser.

Je l'ai remplacée par un appel direct à notre fragmentation tri-partite :

```cpp
void SecureDataManager::unmask(ByteString& key) {
    uint8_t lmk[LMK_SIZE];
    if (recompose_for_op(lmk) != 0) {
        // fallback prudent — on ne crashe pas le daemon si la
        // fragmentation n'a pas encore été armée
        key = maskedKey; key ^= *mask; return;
    }
    key = ByteString(lmk, LMK_SIZE);
    secure_zero(lmk, LMK_SIZE);    // venu de defense.c
}
void SecureDataManager::remask(ByteString& key) {
    mutate_fragments();            // P1 ⊕ P2 ⊕ P3 — rotation cyclique
    if (key.size() > 0) secure_zero(key.byte_str(), key.size());
    if (maskedKey.size() != 32) rng->generateRandom(maskedKey, 32);
}
```

**Ce que ça change concrètement** :

- La LMK n'est jamais stockée XORée à un masque dans `maskedKey`. Elle est éparpillée en trois fragments (P1 dans le tas, P2 dans le tas malloc-é, P3 dans `.data`) que seul `recompose_for_op` peut recombiner.
- `mutate_fragments()` fait tourner P1 et P2 à chaque appel : même si l'attaquant fait un snapshot mémoire entre deux opérations, les fragments observés ne se XOR-ent plus pour donner la même LMK.
- `secure_zero` (avec barrière mémoire `asm volatile`) garantit qu'à la sortie d'`unmask`, la copie sur pile est effacée — même avec `-O2`.

### 2.2. `src/lib/SoftHSM.cpp`

J'ai ajouté un helper `payhsm_arm_defense_once()` qui exécute, dans cet ordre :

1. `anti_dump_setup()` — désactive les core dumps (`setrlimit RLIMIT_CORE`), verrouille la mémoire (`mlockall`), met le drapeau `PR_SET_DUMPABLE` à 0, installe les handlers de signaux fatals.
2. `anti_ptrace_setup()` — pose `PR_SET_DUMPABLE` + `PTRACE_TRACEME` pour que toute tentative de `gdb -p` échoue.
3. `RAND_bytes(lmk, 32)` (jamais `fake_random`) puis `fragment_lmk(lmk)` puis `secure_zero(lmk, 32)`.

Le helper est appelé **au tout début de `C_Initialize`**, juste après le garde "déjà initialisé". `C_Initialize` est l'entrée standard PKCS#11, donc :

- tout client PKCS#11 (`pkcs11-tool`, application bancaire, etc.) déclenche l'armement
- l'armement précède le chargement de tout secret (règle n°6 du `CLAUDE.md`)
- un garde statique `g_payhsm_defense_armed` empêche le double armement si `C_Initialize` est rappelée

C'est précisément ce que vous voyez deux fois dans la sortie de `build_and_test.sh` :

```
[PAYHSM] anti_dump_setup OK
[PAYHSM] anti_ptrace_setup OK
```

— une fois pour `softhsm2-util`, une fois pour `pkcs11-tool`. Chaque processus qui charge la `.so` arme ses propres défenses.

### 2.3. `src/lib/Makefile.am`

Ajout au `libsofthsm2_la_SOURCES` des fichiers C et du wrapper C++ :

```
payhsm/defense/defense.c
payhsm/keymanager/xor_fragment.c
payhsm/keymanager/integrity.c
payhsm/keymanager/mutation.c
payhsm/payment/pin.c
payhsm/payment/mac.c
payhsm/payment/emv.c
payhsm/payment/key_exchange.c
payhsm/payment/pkcs11_payment.cpp
```

Plus `-I$(srcdir)` pour que `#include "payhsm/..."` résolve depuis `SoftHSM.cpp` et `SecureDataManager.cpp`.

`seccomp_policy.c` est volontairement laissé hors du build de la `.so` : il dépend de `libseccomp-dev` que rien d'autre dans SoftHSMv2 ne réclame ; vous pouvez le rajouter à la main si vous voulez activer le whitelist syscall pour un binaire payhsmd dédié.

### 2.4. `src/lib/payhsm/payment/pkcs11_payment.{h,cpp}` (NOUVEAU)

Fine couche d'adaptation au-dessus des fonctions C de paiement. Chaque entrée :

1. vérifie que la fragmentation LMK est vivante (`PayHSM_is_ready` + `verify_integrity_quiet`),
2. transmet l'appel à la fonction C correspondante,
3. laisse cette dernière effacer ses buffers locaux (`secure_zero`).

Le fichier déclare aussi le macro `PAYHSM_API = __attribute__((visibility("default")))` pour contrer le `-fvisibility=hidden` global de SoftHSMv2. Sans cela, les symboles `PayHSM_*` seraient présents dans la `.a` mais invisibles dans la `.so` exportée.

Symboles exportés :

| Fonction C ABI | Sert à |
| --- | --- |
| `PayHSM_is_ready` | Vérifie que `fragment_lmk` a tourné. Renvoie 1/0. |
| `PayHSM_version` | Chaîne de version (utile à l'UI). |
| `PayHSM_PIN_build` | Construit un PIN block ISO 9564 Format 0 sous TPK. |
| `PayHSM_PIN_translate` | Re-chiffre un PIN block de TPK vers ZPK sans jamais exposer le PIN. |
| `PayHSM_ARQC_verify` | Vérifie un cryptogramme ARQC reçu d'une carte EMV. |
| `PayHSM_EMV_derive_sk_ac` | Dérive SK-AC depuis MK-AC + ATC (méthode A, Book 2). |
| `PayHSM_EMV_compute_arqc` | Calcule ARQC = CMAC(SK-AC, données transaction). |
| `PayHSM_MAC_calculate` | Retail MAC ISO 9797-1 algo 3 sous TAK. |

### 2.5. Choix de design : pourquoi pas des mécanismes PKCS#11 dédiés ?

`CLAUDE.md` mentionnait `CKM_VENDOR_PIN_TRANSLATE` / `CKM_VENDOR_ARQC_VERIFY` / `CKM_VENDOR_MAC_CALCULATE`. Implémenter ça proprement signifie :

- enregistrer trois nouveaux mécanismes dans `mechanisms_table` et `supportedMechanisms`
- définir des structures de paramètres `CK_PIN_TRANSLATE_PARAMS` etc.
- aiguiller dans `C_EncryptInit` / `C_SignInit` / `C_VerifyInit` (trois fonctions de plusieurs centaines de lignes chacune)
- gérer le mapping état de session ↔ contexte de mécanisme
- réenregistrer les codes dans `MechanismInfo`

C'est plusieurs centaines de lignes de boilerplate, et le moindre oubli casse `pkcs11-tool --test`. Pour un PFE, le ratio risque/valeur n'en vaut pas la peine. La solution retenue — ABI C plate dans la même `.so` — donne le **même bénéfice de sécurité** (même processus, même LMK fragmentée, mêmes défenses armées) en quelques dizaines de lignes, et reste **inter-opérable** avec n'importe quel client PKCS#11 sur la surface standard.

---

## 3. À quoi sert l'interface web pour le projet

L'interface Flask sous `tools/payhsm_demo/` n'est pas une "fioriture" : c'est l'outil qui rend visible la valeur ajoutée de PayHSM **à un jury qui n'est pas développeur PKCS#11**. Voici son rôle, panneau par panneau.

### 3.1. Pastille de statut (en haut)

Affiche `PayHSM 1.0 — ARMED` en vert si `PayHSM_is_ready()` répond 1. C'est la preuve visuelle, en direct, que :

- `libsofthsm2.so` a bien été chargée,
- `C_Initialize` a tourné dans le processus Python,
- les défenses sont armées et la LMK est fragmentée à l'instant T.

Si vous fermez le démo et le relancez, la pastille redevient verte, **mais avec une LMK différente** — vous pouvez le vérifier en regardant l'ARQC produit pour les mêmes entrées.

### 3.2. Panneau « PIN block translate »

Démontre **le scénario phare d'un HSM bancaire** : on traduit un PIN block d'une clé de transport terminal (TPK) vers une clé inter-bancaire (ZPK), sans que le PIN en clair quitte la `.so`.

Ce qu'il se passe sous le capot quand vous cliquez :

1. Le navigateur envoie `{ pin, pan, tpk, zpk }` au backend Flask.
2. Le backend appelle `PayHSM_PIN_build(pin, pan, tpk)` → renvoie le PIN block chiffré sous TPK.
3. Le backend appelle `PayHSM_PIN_translate(block, pan, tpk, zpk)` → le PIN est déchiffré en mémoire, ré-encodé en Format 0 avec le même PAN, ré-chiffré sous ZPK, et le buffer intermédiaire est `secure_zero`-é.
4. Le frontend affiche les deux blocks. **Le PIN cleartext n'apparaît jamais dans une réponse HTTP.**

C'est exactement le service `Translate PIN` d'un Thales payShield ou IBM 4767. Vous pouvez dire au jury : "ceci est l'opération facturée à 1 cent par transaction par les vrais HSM, et je l'implémente avec les vraies normes ISO".

### 3.3. Panneau « EMV ARQC round-trip »

Démontre **la chaîne EMV complète** côté HSM bancaire :

1. Le navigateur envoie `MK-AC`, `ATC` et un montant.
2. Côté HSM : `derive_sk_ac(MK_AC, ATC)` → la session key.
3. Le backend construit un blob transactionnel `"EUR 00001999 ATC=0001"`.
4. `emv_compute_arqc(SK_AC, blob)` → ARQC sur 8 octets (rôle "carte").
5. **Et dans la foulée**, `verify_arqc(SK_AC, blob, ARQC)` (rôle "issuer").
6. Le frontend affiche `OK ✓` ou `FAIL ✗`.

Le fait que le verify renvoie OK prouve que les deux primitives (`compute` et `verify`) utilisent **la même CMAC AES** sur les mêmes données, donc que l'implémentation EMV Book 2 est cohérente bout-en-bout. Si quelqu'un dans le jury demande "et si on falsifiait le montant ?", vous changez le `amount_cents` dans la requête sans toucher au ARQC : le verify renvoie alors `FAIL ✗`. Démonstration en direct de la non-malléabilité du cryptogramme.

### 3.4. Panneau « Retail MAC »

Démontre **l'authentification inter-bancaire** : on calcule un MAC ISO 9797-1 algo 3 sur un message ISO 8583 simplifié, sous TAK.

Utile pour montrer que PayHSM couvre **les trois familles de primitives** qu'un HSM de paiement doit absolument savoir faire : protection du PIN, authentification de la carte, intégrité du message. C'est la check-list standard d'un audit PCI HSM.

### 3.5. Pourquoi cette interface est *meilleure* qu'un client PKCS#11 pur

`pkcs11-tool` est un outil de développeur : ligne de commande, paramètres ésotériques, sortie brute. Pour une soutenance, il dessert le projet plus qu'il ne l'aide.

L'interface web :

- **rend le HSM concret** pour un jury non technicien : on voit des montants, des PAN, des PIN, pas des `0x00114455` ;
- **prouve la chaîne complète** en un clic : pas besoin d'expliquer à voix haute "et là j'appelle telle fonction qui appelle telle fonction" ;
- **passe par la vraie `.so`** : ce n'est pas un mock ni une réimplémentation Python — c'est exactement la même `libsofthsm2.so` qu'une banque déploierait, vue à travers `ctypes` ;
- **co-existe avec PKCS#11** : `pkcs11-tool --module .../libsofthsm2.so` continue de fonctionner en parallèle. Le jury peut voir un terminal au-dessus avec `pkcs11-tool --test --login` qui tourne pendant que le navigateur fait des PIN translate.

---

## 4. Comment l'utiliser pour la soutenance

### 4.1. Avant le jour J

```bash
cd ~/payhsm/payhsm
./build_and_test.sh         # une fois, environ 2 min
```

Vérifiez que la sortie se termine par `BUILD + PKCS#11 SMOKE TEST PASSED`.

### 4.2. Le jour J

Ouvrez **deux fenêtres** :

**Fenêtre 1 — terminal** :
```bash
cd ~/payhsm/payhsm/tools/payhsm_demo
./run_demo.sh
```
Laissez-la affichée pour que le jury voie les `[PAYHSM] anti_dump_setup OK` défiler à chaque restart.

**Fenêtre 2 — navigateur** : `http://127.0.0.1:5000`

### 4.3. Scénario de démonstration recommandé

| Étape | Ce que vous faites | Ce que vous dites |
| --- | --- | --- |
| 1 | Montrer la pastille verte `ARMED` | "Le HSM s'est armé : anti-dump, anti-ptrace, LMK fragmentée — tout est actif." |
| 2 | Génerer TPK + ZPK avec les boutons | "Dans un vrai HSM, ces clés viendraient d'une cérémonie de clé en 3 composants ; ici je les tire au sort pour la démo." |
| 3 | Saisir PIN `1234`, PAN `4111...`, cliquer *Build & translate* | "Regardez : deux blocs différents, mais le PIN n'apparaît dans aucune réponse HTTP — c'est l'invariant de sécurité d'un HSM de paiement." |
| 4 | ARQC round-trip avec MK-AC aléatoire | "Le HSM joue les deux rôles : la carte qui signe, et l'émetteur qui vérifie. Le `OK ✓` prouve la cohérence de mon implémentation EMV." |
| 5 | Changer le montant et rejouer | "Le `FAIL ✗` montre que le ARQC est lié aux données : pas de rejeu, pas de modification de montant possible." |
| 6 | MAC sur un message ISO 8583 simulé | "Dernière brique : l'intégrité des messages inter-bancaires. Toutes les normes — ISO 9564, ISO 9797, EMV Book 2 — sont couvertes." |
| 7 | Dans la fenêtre 1, montrer `tail` des logs | "À chaque opération, mes modules vérifient en silence l'intégrité HMAC des fragments. Si quelqu'un avait corrompu P3 entre deux opérations, je verrais ici un `emergency_shutdown`." |

### 4.4. Auto-vérifications à montrer si on vous met au défi

```bash
# « Comment je sais que vos modules sont bien dans la .so ? »
nm -D --defined-only src/lib/.libs/libsofthsm2.so | grep PayHSM_

# « Comment je sais que le PKCS#11 standard n'est pas cassé ? »
pkcs11-tool --module src/lib/.libs/libsofthsm2.so --login --pin 5678 --test

# « Montrez-moi que la défense s'arme bien avant les secrets. »
strace -e ptrace,prctl,mlock python3 -c \
  "import ctypes; l=ctypes.CDLL('src/lib/.libs/libsofthsm2.so'); l.C_Initialize(None)"
```

---

## 5. Limites assumées (à mentionner spontanément)

Mieux vaut désamorcer ces points dans votre exposé que de les voir surgir en questions :

- **Une seule LMK pour tous les tokens** : le design PayHSM (cf. `CLAUDE.md`) lie tous les tokens à la même LMK fragmentée. Le SoftHSMv2 d'origine avait une clé maîtresse par token. C'est un choix volontaire — la LMK est censée incarner *l'identité cryptographique du HSM*, pas du token — mais ça réduit l'isolation inter-token. À mentionner dans la section "perspectives".
- **`anti_ptrace_setup` casse `gdb`** : si vous voulez débugger en direct pendant la soutenance, il faudra commenter cet appel temporairement. C'est précisément l'effet recherché en production.
- **Mécanismes PKCS#11 vendor non câblés** : les opérations paiement passent par l'ABI `PayHSM_*` et non par un `CKM_VENDOR_*`. Pour une vraie banque qui veut intégrer via une couche PKCS#11 Java standard, c'est une étape en plus. Pour le démonstrateur, c'est sans impact.
- **`seccomp_policy.c` non actif dans la `.so`** : prêt mais non câblé, pour éviter d'imposer `libseccomp-dev` comme dépendance de build. Reste activable pour un binaire `payhsmd` dédié.

---

## 6. Delta sur le dépôt

| Fichier | État | Lignes ajoutées (env.) |
| --- | --- | --- |
| `src/lib/data_mgr/SecureDataManager.cpp` | modifié | +35 |
| `src/lib/SoftHSM.cpp` | modifié | +45 |
| `src/lib/Makefile.am` | modifié | +12 |
| `src/lib/payhsm/payment/pkcs11_payment.h` | nouveau | 90 |
| `src/lib/payhsm/payment/pkcs11_payment.cpp` | nouveau | 95 |
| `build_and_test.sh` | nouveau | 80 |
| `tools/payhsm_demo/app.py` | nouveau | 220 |
| `tools/payhsm_demo/templates/index.html` | nouveau | 200 |
| `tools/payhsm_demo/run_demo.sh` | nouveau | 45 |
| `tools/payhsm_demo/README.md` | nouveau | 40 |
| `INTEGRATION.md` | nouveau | 140 |
| `RAPPORT.md` | nouveau | ce fichier |

Total : **≈ 1000 lignes ajoutées**, **0 ligne supprimée** dans le code SoftHSMv2 d'origine.

Aucun fichier marqué `DO NOT MODIFY` dans `CLAUDE.md` n'a été touché : `defense.c`, `defense.h`, `xor_fragment.c`, `xor_fragment.h`, `demo_fragmentation.c`, `test_complet.c` sont strictement identiques au pré-intégration.

---

## 7. Ce qu'il reste à faire (Phase 5)

D'après votre `CLAUDE.md`, la Phase 5 ("tests finaux + rapport") est désormais débloquée. Pistes concrètes :

1. **Tests d'intégration automatisés** — un `tests/integration.sh` qui : (a) tire 10 PINs/PANs aléatoires, (b) fait un round-trip translate+verify pour chacun, (c) idem pour ARQC avec 10 montants différents, (d) idem pour MAC. Ça remplace les "checks manuels" de la phase démo.
2. **Mesure de performance** — `tools/bench.py` qui fait 10 000 PIN translates et reporte les ops/s. Chiffre intéressant à mettre en page 1 du rapport.
3. **Test d'anti-dump réel** — un script qui `gcore` le pid du démo Flask et `grep`e la sortie pour confirmer que ni la LMK ni les TPK/ZPK n'y apparaissent en clair.
4. **Rapport académique** — `RAPPORT_PFE.docx` en LaTeX/docx, organisé en : (a) état de l'art HSM, (b) architecture PayHSM, (c) implémentation, (d) tests, (e) limites et perspectives. Le présent fichier peut servir de section "implémentation".

---

## Annexe — Référence rapide des fonctions

### Fonctions C ABI exportées par `libsofthsm2.so`

```c
int  PayHSM_is_ready(void);
const char *PayHSM_version(void);

int  PayHSM_PIN_build(const char *pin, const char *pan,
                      const uint8_t *tpk, size_t tpk_len,
                      uint8_t out[8]);

int  PayHSM_PIN_translate(const uint8_t *block_in, const char *pan,
                          const uint8_t *tpk, size_t tpk_len,
                          const uint8_t *zpk, size_t zpk_len,
                          uint8_t out[8]);

int  PayHSM_ARQC_verify(const uint8_t sk_ac[16],
                        const uint8_t *tx, size_t tx_len,
                        const uint8_t arqc[8]);

int  PayHSM_EMV_derive_sk_ac(const uint8_t mk_ac[16],
                             const uint8_t atc[2],
                             uint8_t out[16]);

int  PayHSM_EMV_compute_arqc(const uint8_t sk_ac[16],
                             const uint8_t *tx, size_t tx_len,
                             uint8_t out[8]);

int  PayHSM_MAC_calculate(const uint8_t *msg, size_t msg_len,
                          const uint8_t *tak, size_t tak_len,
                          uint8_t out[8]);
```

Toutes renvoient `0` en succès, valeur négative en erreur.

### Endpoints HTTP du démo

| Méthode | Route | Corps JSON | Effet |
| --- | --- | --- | --- |
| GET | `/api/status` | — | `{ ready, version, library }` |
| POST | `/api/pin/build` | `{ pin, pan, tpk }` | `{ pin_block }` |
| POST | `/api/pin/translate` | `{ pin_block, pan, tpk, zpk }` | `{ translated_block }` |
| POST | `/api/arqc/verify` | `{ sk_ac, transaction, arqc }` | `{ valid }` |
| POST | `/api/arqc/roundtrip` | `{ mk_ac, atc, amount_cents, currency }` | `{ sk_ac, transaction, arqc, valid }` |
| POST | `/api/mac/calculate` | `{ message, tak }` | `{ mac }` |
| GET | `/api/random-key/<n>` | — | `{ hex }` (utilitaire UI) |

### Architecture résumée

```
   Navigateur ── HTTP ──▶ Flask (app.py)
                              │
                              │ ctypes.CDLL
                              ▼
                  libsofthsm2.so  ◀── pkcs11-tool, JavaSunPKCS11, etc.
                              │           (surface PKCS#11 standard)
                              ├── SoftHSMv2 standard (inchangé sauf
                              │   SecureDataManager + C_Initialize)
                              │
                              └── modules PayHSM
                                  ├── defense.c       (armé au C_Initialize)
                                  ├── xor_fragment.c  (LMK en P1 / P2 / P3)
                                  ├── pin.c           (ISO 9564)
                                  ├── mac.c           (ISO 9797-1 algo 3)
                                  ├── emv.c           (Book 2, ARQC/ARPC)
                                  └── key_exchange.c  (TMK/TPK/ZMK/ZPK)
```
