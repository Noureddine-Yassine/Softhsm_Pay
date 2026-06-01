// ============================================================
//  PayHSM — Generateur DOCX d'analyse de conception
//  Usage : npm install -g docx && node gen_payhsm_docx.js
//  Output : PayHSM_Analyse_Conception.docx (dans le meme dossier)
// ============================================================
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, HeadingLevel, BorderStyle, WidthType, ShadingType,
  Header, Footer, PageNumber, PageBreak, LevelFormat
} = require('docx');
const fs = require('fs');
const path = require('path');

const DARK_BLUE  = "154360";
const ACCENT     = "2980B9";
const LIGHT_BLUE = "D6EAF8";
const LIGHT_GREY = "F2F3F4";
const WHITE      = "FFFFFF";

const cellBorder = { style: BorderStyle.SINGLE, size: 1, color: "AAAAAA" };
const borders    = { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder };

// ── Helpers ──────────────────────────────────────────────────
function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text, bold: true, font: "Arial", size: 32, color: DARK_BLUE })],
    spacing: { before: 400, after: 200 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: ACCENT, space: 1 } },
  });
}
function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    children: [new TextRun({ text, bold: true, font: "Arial", size: 26, color: DARK_BLUE })],
    spacing: { before: 280, after: 140 },
  });
}
function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    children: [new TextRun({ text, bold: true, font: "Arial", size: 22, color: ACCENT })],
    spacing: { before: 200, after: 100 },
  });
}
function p(text) {
  return new Paragraph({
    children: [new TextRun({ text, font: "Arial", size: 22 })],
    spacing: { before: 80, after: 80 },
  });
}
function bp(text) {                       // bullet
  return new Paragraph({
    numbering: { reference: "bul", level: 0 },
    children: [new TextRun({ text, font: "Arial", size: 22 })],
    spacing: { before: 60, after: 60 },
  });
}
function note(text) {
  return new Paragraph({
    children: [new TextRun({ text: "Note : " + text, font: "Arial", size: 20, italics: true, color: "555555" })],
    indent: { left: 360 },
    spacing: { before: 60, after: 60 },
  });
}
function br() { return new Paragraph({ children: [new PageBreak()] }); }

function row(cells, isHdr = false) {
  return new TableRow({
    tableHeader: isHdr,
    children: cells.map(c => new TableCell({
      borders,
      width: { size: c.w || 2000, type: WidthType.DXA },
      shading: c.bg ? { fill: c.bg, type: ShadingType.CLEAR } : undefined,
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      children: [new Paragraph({
        children: [new TextRun({
          text: c.t || "",
          font: "Arial",
          size: 20,
          bold: c.bold || isHdr,
          color: isHdr ? WHITE : undefined,
        })],
      })],
    })),
  });
}
function tbl(colWidths, rows) {
  const total = colWidths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: colWidths,
    rows,
  });
}

// ── Section helpers ──────────────────────────────────────────
const A4_W = 11906, A4_H = 16838, MARGIN = 1440;
const CONTENT_W = A4_W - 2 * MARGIN;  // 9026

const PAGE_PROPS = {
  page: { size: { width: A4_W, height: A4_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } },
};

const HEADER = new Header({
  children: [new Paragraph({
    children: [new TextRun({ text: "PayHSM — Analyse de Conception | PFE 2026", font: "Arial", size: 18, color: "888888" })],
    border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 1 } },
  })],
});
const FOOTER = new Footer({
  children: [new Paragraph({
    children: [
      new TextRun({ text: "PayHSM PFE 2026 | Page ", font: "Arial", size: 18, color: "888888" }),
      new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 18, color: "888888" }),
    ],
    alignment: AlignmentType.CENTER,
    border: { top: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 1 } },
  })],
});

// ════════════════════════════════════════════════════════════
//  CONSTRUCTION DU DOCUMENT
// ════════════════════════════════════════════════════════════
const doc = new Document({
  numbering: {
    config: [{
      reference: "bul",
      levels: [{
        level: 0, format: LevelFormat.BULLET, text: "•",
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    }],
  },
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: DARK_BLUE },
        paragraph: { spacing: { before: 400, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: DARK_BLUE },
        paragraph: { spacing: { before: 280, after: 140 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, font: "Arial", color: ACCENT },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
    ],
  },
  sections: [
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PAGE DE TITRE
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
      properties: { page: PAGE_PROPS.page },
      children: [
        new Paragraph({ spacing: { before: 2800, after: 0 }, children: [] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 200 },
          children: [new TextRun({ text: "PAYHSM", font: "Arial", size: 80, bold: true, color: DARK_BLUE })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 500 },
          children: [new TextRun({ text: "Soft HSM pour Paiements Securises", font: "Arial", size: 36, color: ACCENT, italics: true })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 160 },
          border: { top: { style: BorderStyle.SINGLE, size: 4, color: ACCENT, space: 1 } },
          children: [] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 160, after: 100 },
          children: [new TextRun({ text: "Analyse de Conception et Diagrammes UML", font: "Arial", size: 28, bold: true })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 800 },
          children: [new TextRun({ text: "Projet de Fin d'Etudes (PFE) — Architecture Securisee", font: "Arial", size: 22, italics: true, color: "666666" })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 },
          children: [new TextRun({ text: "Auteur : Yassine Nourdine", font: "Arial", size: 24, bold: true })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 },
          children: [new TextRun({ text: "nourddineyassine2002@gmail.com", font: "Arial", size: 20, color: "555555" })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 },
          children: [new TextRun({ text: "Mai 2026", font: "Arial", size: 20, color: "555555" })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 },
          children: [new TextRun({ text: "https://github.com/Schaib03/payhsm", font: "Arial", size: 20, color: ACCENT })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 0 },
          children: [new TextRun({ text: "Ubuntu 24.04 | OpenSSL 3.x | GCC | SoftHSMv2", font: "Arial", size: 18, color: "888888" })] }),
      ],
    },

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  CORPS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
      properties: { page: PAGE_PROPS.page },
      headers: { default: HEADER },
      footers: { default: FOOTER },
      children: [

        // ──────────────────────────────────────
        h1("1. Introduction et Contexte"),
        p("PayHSM est un projet PFE concevant un module de securite materiel logiciel (Soft HSM) dedie aux paiements electroniques. Il s'appuie sur SoftHSMv2 comme socle PKCS#11 et y greffe trois couches originales : defense systeme, gestionnaire de cles fragmentees, et primitives cryptographiques conformes ISO 9564, ISO 9797-1 et EMV Book 2."),
        p("Problematique : garantir la confidentialite de la LMK et des operations de paiement (PIN, MAC, EMV) sans puce HSM physique, en environnement Linux."),
        h2("1.1 Perimetre"),
        p("Analyse exclusive des modules PayHSM originaux (src/lib/payhsm/). SoftHSMv2 est utilise comme fondation PKCS#11 mais n'est pas analyse ici. L'integration se fait via SecureDataManager.cpp et SoftHSM.cpp (modifies)."),
        h2("1.2 Structure des Sources"),
        tbl([2000, 2200, 4826], [
          row([{t:"Repertoire",w:2000,bg:DARK_BLUE},{t:"Fichiers cles",w:2200,bg:DARK_BLUE},{t:"Role",w:4826,bg:DARK_BLUE}], true),
          row([{t:"defense/",w:2000},{t:"defense.c, seccomp_policy.c",w:2200},{t:"Anti-dump, anti-ptrace, secure_zero, filtre BPF syscalls",w:4826}]),
          row([{t:"keymanager/",w:2000,bg:LIGHT_GREY},{t:"xor_fragment.c, lmk_store.c, kek_provider.c, key_vault.c, integrity.c, mutation.c",w:2200,bg:LIGHT_GREY},{t:"Fragmentation LMK P1/P2/P3, stockage AES-256-GCM, coffre cles",w:4826,bg:LIGHT_GREY}]),
          row([{t:"payment/",w:2000},{t:"pin.c, mac.c, emv.c, key_exchange.c, pkcs11_payment.cpp",w:2200},{t:"PIN Block ISO 9564, MAC ISO 9797-1, EMV Book 2, ABI C PKCS#11",w:4826}]),
          row([{t:"payhsm_core.c/h",w:2000,bg:LIGHT_GREY},{t:"payhsm_core.c, payhsm.h",w:2200,bg:LIGHT_GREY},{t:"Coeur HSM : provision, startup, operations bancaires, gestion cartes",w:4826,bg:LIGHT_GREY}]),
          row([{t:"payhsm_switch.c/h",w:2000},{t:"payhsm_switch.c/h",w:2200},{t:"Interface Switch : cles fournies par le reseau (GCM 88 hex / ECB 32 hex)",w:4826}]),
          row([{t:"bin/",w:2000,bg:LIGHT_GREY},{t:"payhsm-cli.c, payhsmd.c, payhsm-httpd.c",w:2200,bg:LIGHT_GREY},{t:"CLI, daemon Unix socket, serveur HTTP REST",w:4826,bg:LIGHT_GREY}]),
          row([{t:"tests/",w:2000},{t:"test_scenarios.c, test_emv_switch.c, test_complet.c",w:2200},{t:"Tests d'integration : PIN, MAC, EMV, mutation, switch",w:4826}]),
        ]),
        br(),

        // ──────────────────────────────────────
        h1("2. Besoins Fonctionnels"),
        h2("2.1 Gestion du Cycle de Vie (FR1)"),
        tbl([1000,2200,5826], [
          row([{t:"ID",w:1000,bg:DARK_BLUE},{t:"Intitule",w:2200,bg:DARK_BLUE},{t:"Description",w:5826,bg:DARK_BLUE}], true),
          row([{t:"FR1.1",w:1000},{t:"Provisionnement HSM",w:2200},{t:"Generer LMK 256 bits (RAND_bytes), deriver TMK/TPK/TAK par terminal, initialiser le coffre chiffre. Passphrase requise.",w:5826}]),
          row([{t:"FR1.2",w:1000,bg:LIGHT_GREY},{t:"Provisionnement LMK seule",w:2200,bg:LIGHT_GREY},{t:"Genere uniquement la LMK. Les cles metier restent chez le Switch (payhsm_provision_lmk_only).",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR1.3",w:1000},{t:"Demarrage securise",w:2200},{t:"Charger LMK chiffree, KEK via PBKDF2-SHA256 (100k), AES-256-GCM, fragmenter P1/P2/P3, effacer LMK. Defenses armees en premier.",w:5826}]),
          row([{t:"FR1.4",w:1000,bg:LIGHT_GREY},{t:"Arret propre",w:2200,bg:LIGHT_GREY},{t:"zero_all_fragments() + secure_zero() sur tous les buffers secrets avant terminaison du processus.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR1.5",w:1000},{t:"Identifiant de boot",w:2200},{t:"boot_id incremental pour synchroniser l'etat HSM-Switch apres chaque redemarrage (payhsm_get_boot_id).",w:5826}]),
        ]),
        h2("2.2 Gestion des Cles (FR2)"),
        tbl([1000,2200,5826], [
          row([{t:"ID",w:1000,bg:DARK_BLUE},{t:"Intitule",w:2200,bg:DARK_BLUE},{t:"Description",w:5826,bg:DARK_BLUE}], true),
          row([{t:"FR2.1",w:1000},{t:"Fragmentation LMK",w:2200},{t:"LMK fragmentee : P1 (BSS) XOR P2 (heap) XOR P3 (DATA) = LMK. Invariant maintenu en permanence. LMK effacee apres fragmentation.",w:5826}]),
          row([{t:"FR2.2",w:1000,bg:LIGHT_GREY},{t:"Persistance LMK (AES-256-GCM)",w:2200,bg:LIGHT_GREY},{t:"Fichier lmk.bin : sel(16) | nonce(12) | tag(16) | CT(32). Tag garantit l'integrite. AES-ECB interdit pour la LMK.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR2.3",w:1000},{t:"Derivation KEK (PBKDF2)",w:2200},{t:"KEK = PBKDF2-SHA256(passphrase, sel, 100 000 iterations). Resistance aux attaques dictionnaire.",w:5826}]),
          row([{t:"FR2.4",w:1000,bg:LIGHT_GREY},{t:"Coffre (KeyVault)",w:2200,bg:LIGHT_GREY},{t:"32 entrees typees (LMK/TMK/TPK/TAK/ZMK/ZPK/PVK/IMK). Chaque cle chiffree sous LMK + KCV 3 octets.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR2.5",w:1000},{t:"Verification integrite",w:2200},{t:"HMAC-SHA256 de reference calcule a la fragmentation. Verifie avant chaque recompose_for_op(). Echec = emergency_shutdown().",w:5826}]),
          row([{t:"FR2.6",w:1000,bg:LIGHT_GREY},{t:"Mutation cyclique",w:2200,bg:LIGHT_GREY},{t:"XOR aleatoire P1/P3 + reallocation heap P2. Rend inutilisable tout snapshot memoire anterieur.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR2.7",w:1000},{t:"Calcul KCV",w:2200},{t:"KCV = AES-ECB(key, 0x00...00)[0:3]. Verification visuelle de toute cle du coffre.",w:5826}]),
        ]),
        h2("2.3 Traitement du PIN (FR3)"),
        tbl([1000,2200,5826], [
          row([{t:"ID",w:1000,bg:DARK_BLUE},{t:"Intitule",w:2200,bg:DARK_BLUE},{t:"Description",w:5826,bg:DARK_BLUE}], true),
          row([{t:"FR3.1",w:1000},{t:"Generation PIN Block",w:2200},{t:"PIN Block ISO 9564 Fmt0 chiffre sous TPK (AES-128-ECB) depuis PIN + PAN. Simulation GAP ou demo.",w:5826}]),
          row([{t:"FR3.2",w:1000,bg:LIGHT_GREY},{t:"Translation TPK -> ZPK",w:2200,bg:LIGHT_GREY},{t:"Dechiffre sous TPK, rechiffre sous ZPK. PIN jamais en clair hors buffers proteges.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR3.3",w:1000},{t:"Verification PIN (PVV VISA)",w:2200},{t:"PVV = decimalise(AES(PVK, PAN+PSN+PIN))[0:4]. Retourne 0 si valide, -1 sinon.",w:5826}]),
          row([{t:"FR3.4",w:1000,bg:LIGHT_GREY},{t:"Verification PIN Block chiffre",w:2200,bg:LIGHT_GREY},{t:"Dechiffre PIN Block (TPK ou ZPK), calcule PVV et compare. PIN ne transite jamais en clair.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR3.5",w:1000},{t:"Translation ZPK -> ZPK",w:2200},{t:"Translation inter-bancaire entre deux ZPK pour routage reseau (payhsm_translate_zpk_to_zpk).",w:5826}]),
        ]),
        h2("2.4 Operations MAC (FR4)"),
        tbl([1000,2200,5826], [
          row([{t:"ID",w:1000,bg:DARK_BLUE},{t:"Intitule",w:2200,bg:DARK_BLUE},{t:"Description",w:5826,bg:DARK_BLUE}], true),
          row([{t:"FR4.1",w:1000},{t:"MAC Retail (TAK)",w:2200},{t:"MAC ISO 9797-1 Algorithme 3 (Retail MAC) sous TAK pour l'integrite des messages terminaux.",w:5826}]),
          row([{t:"FR4.2",w:1000,bg:LIGHT_GREY},{t:"MAC inter-bancaire (ZAK)",w:2200,bg:LIGHT_GREY},{t:"MAC sous ZAK pour messages de compensation inter-bancaires.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR4.3",w:1000},{t:"Verification MAC temps constant",w:2200},{t:"Comparaison a temps constant (loop XOR, pas de court-circuit) — anti-timing attack.",w:5826}]),
        ]),
        h2("2.5 Traitement EMV (FR5)"),
        tbl([1000,2200,5826], [
          row([{t:"ID",w:1000,bg:DARK_BLUE},{t:"Intitule",w:2200,bg:DARK_BLUE},{t:"Description",w:5826,bg:DARK_BLUE}], true),
          row([{t:"FR5.1",w:1000},{t:"Derivation MK-AC",w:2200},{t:"MK-AC = HMAC-SHA1(IMK, PAN||PSN)[0:16]. Methode A EMV Book 2 — cle unique par carte.",w:5826}]),
          row([{t:"FR5.2",w:1000,bg:LIGHT_GREY},{t:"Derivation SK-AC",w:2200,bg:LIGHT_GREY},{t:"SK-AC = XOR(MK-AC, ATC||0x00...). Cle de session unique par transaction.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR5.3",w:1000},{t:"Calcul ARQC",w:2200},{t:"ARQC = CMAC-AES(SK-AC, donnees_tx). Simule le cryptogramme de la puce EMV.",w:5826}]),
          row([{t:"FR5.4",w:1000,bg:LIGHT_GREY},{t:"Verification ARQC",w:2200,bg:LIGHT_GREY},{t:"Recalcule ARQC cote HSM emetteur et compare au cryptogramme recu.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR5.5",w:1000},{t:"Generation ARPC",w:2200},{t:"ARPC = CMAC(MK-AC, ARQC XOR ARC). Reponse d'autorisation envoyee a la puce.",w:5826}]),
          row([{t:"FR5.6",w:1000,bg:LIGHT_GREY},{t:"Verification ARPC (puce)",w:2200,bg:LIGHT_GREY},{t:"Verification de l'ARPC cote puce — authentification mutuelle HSM-carte.",w:5826,bg:LIGHT_GREY}]),
          row([{t:"FR5.7",w:1000},{t:"Simulation achat EMV",w:2200},{t:"Orchestre MK-AC -> donnees_tx -> SK-AC -> ARQC -> verify -> ARPC en un appel payhsm_emv_simulate_purchase().",w:5826}]),
        ]),
        h2("2.6 Gestion des Cartes (FR6) et Interface Switch (FR7)"),
        bp("FR6.1 — Enregistrement carte : PAN + PIN -> calcul PVV -> persistance dans cards.pvv"),
        bp("FR6.2 — Emission PVV Core Banking : payhsm_corebanking_issue_pvv() calcule et retourne le PVV"),
        bp("FR6.3 — Lecture PVV : payhsm_corebanking_get_pvv() pour verifier l'enrolement"),
        bp("FR7.1 — Dechiffrement cles Switch : GCM blob 88 hex (IV+Tag+CT) ou ECB 32 hex"),
        bp("FR7.2 — Derivation terminaux Switch : TPK et TAK depuis TMK fourni par le Switch"),
        bp("FR7.3 — Toutes operations PIN/MAC/EMV disponibles sans coffre local (mode Switch)"),
        h2("2.7 Couche de Defense Active (FR8)"),
        tbl([1000,2300,5726], [
          row([{t:"ID",w:1000,bg:DARK_BLUE},{t:"Mecanisme",w:2300,bg:DARK_BLUE},{t:"Detail d'implementation",w:5726,bg:DARK_BLUE}], true),
          row([{t:"FR8.1",w:1000},{t:"Anti-dump (OS)",w:2300},{t:"setrlimit(RLIMIT_CORE,{0,0}) + mlockall(MCL_CURRENT|MCL_FUTURE) — pas de core dump, pas de swap des secrets sur disque.",w:5726}]),
          row([{t:"FR8.2",w:1000,bg:LIGHT_GREY},{t:"Anti-ptrace (debug)",w:2300,bg:LIGHT_GREY},{t:"prctl(PR_SET_DUMPABLE,0) + prctl(PR_SET_NO_NEW_PRIVS,1) — attachement debugger bloque.",w:5726,bg:LIGHT_GREY}]),
          row([{t:"FR8.3",w:1000},{t:"Detection debugger active",w:2300},{t:"Lecture periodique /proc/self/status -> TracerPid. Si != 0 : emergency_shutdown().",w:5726}]),
          row([{t:"FR8.4",w:1000,bg:LIGHT_GREY},{t:"Handlers signaux fatals",w:2300,bg:LIGHT_GREY},{t:"SIGSEGV/SIGABRT/SIGTERM/SIGINT/SIGBUS/SIGFPE/SIGILL -> zeroiser P3 + _exit(1) signal-safe.",w:5726,bg:LIGHT_GREY}]),
          row([{t:"FR8.5",w:1000},{t:"Arret d'urgence",w:2300},{t:"emergency_shutdown() : zero_all_fragments() + _exit(99) sans destructeurs C++.",w:5726}]),
          row([{t:"FR8.6",w:1000,bg:LIGHT_GREY},{t:"Filtrage syscalls (seccomp BPF)",w:2300,bg:LIGHT_GREY},{t:"Whitelist BPF : seuls les syscalls necessaires sont autorises. Tout autre = SIGKILL.",w:5726,bg:LIGHT_GREY}]),
        ]),
        h2("2.8 Interface PKCS#11 — ABI C Exporte (FR9)"),
        p("pkcs11_payment.cpp exporte depuis libsofthsm2.so (__attribute__((visibility(\"default\")))). Partage du processus : LMK fragmentee et defenses identiques pour tous les clients (Python ctypes, banking apps)."),
        tbl([3200,5826], [
          row([{t:"Fonction exportee",w:3200,bg:DARK_BLUE},{t:"Role",w:5826,bg:DARK_BLUE}], true),
          row([{t:"PayHSM_is_ready()",w:3200},{t:"Verifie que la fragmentation LMK est active (1=pret, 0=non)",w:5826}]),
          row([{t:"PayHSM_PIN_translate(pin_block_in, pan, tpk, zpk, out)",w:3200,bg:LIGHT_GREY},{t:"Translation PIN Block TPK -> ZPK",w:5826,bg:LIGHT_GREY}]),
          row([{t:"PayHSM_ARQC_verify(sk_ac, tx_data, tx_len, arqc)",w:3200},{t:"Verification ARQC sous SK-AC",w:5826}]),
          row([{t:"PayHSM_MAC_calculate(msg, msg_len, tak, mac_out)",w:3200,bg:LIGHT_GREY},{t:"Retail MAC ISO 9797-1 Algo 3 sous TAK",w:5826,bg:LIGHT_GREY}]),
          row([{t:"PayHSM_EMV_derive_sk_ac(mk_ac, atc, sk_ac_out)",w:3200},{t:"Derivation SK-AC depuis MK-AC + ATC",w:5826}]),
          row([{t:"PayHSM_EMV_compute_arqc(sk_ac, tx_data, tx_len, arqc_out)",w:3200,bg:LIGHT_GREY},{t:"Calcul ARQC (simulation cote puce pour demo)",w:5826,bg:LIGHT_GREY}]),
          row([{t:"PayHSM_version()",w:3200},{t:"Chaine de version de l'extension PayHSM",w:5826}]),
        ]),
        br(),

        // ──────────────────────────────────────
        h1("3. Besoins Non Fonctionnels"),
        h2("3.1 Securite"),
        tbl([1200,2600,5226], [
          row([{t:"ID",w:1200,bg:DARK_BLUE},{t:"Exigence",w:2600,bg:DARK_BLUE},{t:"Critere de satisfaction",w:5226,bg:DARK_BLUE}], true),
          row([{t:"NFR1.1",w:1200},{t:"LMK jamais en clair",w:2600},{t:"LMK fragmentee P1/P2/P3 en permanence. En clair uniquement pendant la nano-fenetre de fragmentation. secure_zero avec barriere assembleur asm volatile.",w:5226}]),
          row([{t:"NFR1.2",w:1200,bg:LIGHT_GREY},{t:"Chiffrement authentifie",w:2600,bg:LIGHT_GREY},{t:"AES-256-GCM obligatoire pour lmk.bin. AES-ECB interdit pour la LMK. Modification du fichier detectee par le tag GCM.",w:5226,bg:LIGHT_GREY}]),
          row([{t:"NFR1.3",w:1200},{t:"KDF resistante",w:2600},{t:"PBKDF2-SHA256, 100 000 iterations, sel aleatoire 128 bits. Attaques dictionnaire couteuses.",w:5226}]),
          row([{t:"NFR1.4",w:1200,bg:LIGHT_GREY},{t:"Zeroisaton systematique",w:2600,bg:LIGHT_GREY},{t:"secure_zero() apres chaque usage de buffer secret (LMK, KEK, TPK, ZPK, PIN clair, MK-AC, SK-AC, IMK).",w:5226,bg:LIGHT_GREY}]),
          row([{t:"NFR1.5",w:1200},{t:"Memoire verrouilee",w:2600},{t:"mlockall(MCL_CURRENT|MCL_FUTURE) : pages memoire non swappables sur disque.",w:5226}]),
          row([{t:"NFR1.6",w:1200,bg:LIGHT_GREY},{t:"Pas de cles codees en dur",w:2600,bg:LIGHT_GREY},{t:"Toutes les valeurs crypto viennent de RAND_bytes ou de la passphrase. Regle de codage obligatoire.",w:5226,bg:LIGHT_GREY}]),
          row([{t:"NFR1.7",w:1200},{t:"Surface d'attaque reduite",w:2600},{t:"Filtre seccomp BPF whitelist : seuls les syscalls HSM necessaires autorises.",w:5226}]),
          row([{t:"NFR1.8",w:1200,bg:LIGHT_GREY},{t:"MAC temps constant",w:2600,bg:LIGHT_GREY},{t:"verify_mac() : boucle XOR sans court-circuit — protection contre les attaques temporelles.",w:5226,bg:LIGHT_GREY}]),
        ]),
        h2("3.2 Performance"),
        bp("NFR2.1 — OpenSSL 3.x avec AES-NI (acceleration materielle) pour AES, HMAC, CMAC, PBKDF2."),
        bp("NFR2.2 — PBKDF2 execute une seule fois au demarrage. Les operations temps reel (PIN, MAC, EMV) n'incluent pas de KDF couteuse."),
        bp("NFR2.3 — Recomposition LMK (recompose_for_op) : XOR 96 octets — microsecondes."),
        bp("NFR2.4 — Mutation cyclique (mutation_apply) : XOR + malloc — microsecondes."),
        h2("3.3 Fiabilite"),
        bp("NFR3.1 — Verification HMAC avant chaque recomposition — aucune operation avec fragments corrompus."),
        bp("NFR3.2 — Codes retour explicites : PAYHSM_RC_OK=0, PAYHSM_RC_ERR=-1, PAYHSM_RC_NOT_INIT=-2, PAYHSM_RC_DECLINED=55."),
        bp("NFR3.3 — Arret d'urgence immediat sur toute detection d'intrusion (debugger, fragments corrompus)."),
        h2("3.4 Portabilite et Interoperabilite"),
        bp("NFR4.1 — Cible : Ubuntu 24.04 LTS, Linux 6.x. Mecanismes specifiques Linux (prctl, mlockall, seccomp, /proc)."),
        bp("NFR4.2 — Compilateur GCC, flags -Wall -Wextra -lssl -lcrypto -I src/lib/payhsm."),
        bp("NFR5.1 — Conformite ISO 9564 Fmt0, ISO 9797-1 Algo 3, EMV Book 2 Methode A, PKCS#11."),
        bp("NFR5.2 — ABI C extern compatible Python ctypes et pkcs11-tool."),
        h2("3.5 Maintenabilite"),
        bp("NFR6.1 — Architecture 4 couches a responsabilites exclusives (C0=defense, C1=cles, C2=paiement, C3=dispatch)."),
        bp("NFR6.2 — Conventions uniformes : prefixe payhsm_, codes retour int, structs typedefs, headers auto-contenus."),
        bp("NFR6.3 — Tests d'integration dans tests/ : scenarios PIN, EMV, mutation, switch."),
        br(),

        // ──────────────────────────────────────
        h1("4. Architecture du Systeme"),
        h2("4.1 Vue en Couches"),
        tbl([1600,2400,5026], [
          row([{t:"Couche",w:1600,bg:DARK_BLUE},{t:"Modules",w:2400,bg:DARK_BLUE},{t:"Responsabilite",w:5026,bg:DARK_BLUE}], true),
          row([{t:"C4 — Applications",w:1600},{t:"BankApp, GAP, Switch, CLI, HTTP",w:2400},{t:"Clients externes : socket Unix, API C, PKCS#11, REST",w:5026}]),
          row([{t:"C3 — Dispatch",w:1600,bg:LIGHT_BLUE},{t:"payhsm_core, payhsm_switch, payhsmd",w:2400,bg:LIGHT_BLUE},{t:"Orchestration flux, contexte HSM singleton, routage requetes",w:5026,bg:LIGHT_BLUE}]),
          row([{t:"C2 — Paiement",w:1600},{t:"pin.c, mac.c, emv.c, key_exchange.c",w:2400},{t:"Primitives crypto monetiques : PIN Block, MAC, ARQC/ARPC, derivation cles",w:5026}]),
          row([{t:"C1 — Cles",w:1600,bg:LIGHT_BLUE},{t:"xor_fragment.c, lmk_store.c, kek_provider.c, key_vault.c, integrity.c, mutation.c",w:2400,bg:LIGHT_BLUE},{t:"Protection et cycle de vie LMK, coffre cles derivees",w:5026,bg:LIGHT_BLUE}]),
          row([{t:"C0 — Defense",w:1600,bg:"FFE0E0"},{t:"defense.c, seccomp_policy.c",w:2400,bg:"FFE0E0"},{t:"Protection systeme transversale — activee EN PREMIER avant tout secret",w:5026,bg:"FFE0E0"}]),
        ]),
        h2("4.2 Ordre de Demarrage (Bootstrap)"),
        p("L'ordre d'initialisation est strictement impose. Toute deviation constitue une vulnerability de securite."),
        bp("1. anti_dump_setup()  —  desactive core dumps, mlocke memoire, installe handlers signaux"),
        bp("2. anti_ptrace_setup()  —  bloque ptrace et elevation de privileges"),
        bp("3. install_seccomp_filter()  —  filtre BPF whitelist syscalls"),
        bp("4. lmk_store_read_salt()  —  lit le sel depuis lmk.bin"),
        bp("5. kek_derive_from_passphrase()  —  PBKDF2-SHA256 (100k iterations)"),
        bp("6. lmk_store_load()  —  AES-256-GCM : dechiffre la LMK + verifie le tag"),
        bp("7. secure_zero(kek, 32)  —  KEK efface immediatement apres usage"),
        bp("8. integrity_set_reference(lmk)  —  HMAC-SHA256 de reference calcule"),
        bp("9. fragment_lmk(lmk)  —  P1 XOR P2 XOR P3 = LMK, dispersion tri-segment"),
        bp("10. secure_zero(lmk, 32)  —  LMK originale effacee de la memoire"),
        bp("11. vault_load()  —  coffre des cles chiffrees sous LMK"),
        note("A partir de l'etape 10, la LMK n'existe plus en clair. Seuls P1/P2/P3 disperses permettent de la reconstituer."),
        h2("4.3 Pattern Operationnel (Recomposition a la Demande)"),
        p("Toute operation cryptographique necessitant la LMK suit invariablement ce pattern protect-use-zero :"),
        bp("check_integrity()  —  verification HMAC-SHA256 des 3 fragments avant recomposition"),
        bp("recompose_for_op(lmk)  —  XOR temporaire P1/P2/P3 dans buffer local de pile"),
        bp("[operation crypto sur buffer secret derive de lmk]"),
        bp("secure_zero(lmk, 32)  —  effacement immediat apres usage, quelques microsecondes apres recomposition"),
        br(),

        // ──────────────────────────────────────
        h1("5. Description Detaillee des Modules"),
        h2("5.1 defense.c — Couche de Defense Systeme"),
        p("Fondation securitaire de PayHSM. Cinq mecanismes complementaires et orthogonaux, actives avant tout chargement de secret."),
        h3("anti_dump_setup()"),
        bp("setrlimit(RLIMIT_CORE,{0,0}) : empeche la creation de core dumps contenant les fragments LMK"),
        bp("mlockall(MCL_CURRENT|MCL_FUTURE) : toutes les pages memoire verrouillees en RAM (pas de swap)"),
        bp("sigaction sur 7 signaux fatals — handler zeroIse P3 + _exit(1) de maniere signal-safe"),
        h3("anti_ptrace_setup() et anti_ptrace_check()"),
        bp("prctl(PR_SET_DUMPABLE,0) + prctl(PR_SET_NO_NEW_PRIVS,1) — ptrace bloque des le demarrage"),
        bp("anti_ptrace_check() lit /proc/self/status -> TracerPid. Si != 0 : emergency_shutdown()"),
        h3("secure_zero(ptr, len)"),
        bp("Pointeur volatile : le compilateur ne peut pas optimiser les ecritures"),
        bp("Barriere assembleur asm volatile(\"\" ::: \"memory\") garantit l'ecriture effective en memoire"),
        h3("emergency_shutdown(reason) et install_seccomp_filter()"),
        bp("emergency_shutdown : zero_all_fragments() + _exit(99) — terminaison sans destructeurs"),
        bp("seccomp BPF whitelist : tout appel systeme hors liste autorisee declenche SIGKILL du noyau"),
        h2("5.2 xor_fragment.c — Fragmentation LMK"),
        p("La LMK (32 octets) est divisee en P1 (segment BSS, zero-init), P2 (heap, malloc, adresse variable), P3 (segment DATA, variable globale). L'invariant P1 XOR P2 XOR P3 = LMK est maintenu. La dispersion dans 3 segments distincts contraint un attaquant effectuant un dump a analyser l'espace memoire entier et a retrouver les 3 parties. La fragmentation seule n'est pas un chiffrement mais augmente considerablement la complexite forensique."),
        h2("5.3 integrity.c / mutation.c — Integrite et Anti-Forensique"),
        p("integrity.c calcule HMAC-SHA256(lmk) comme reference lors de la fragmentation initiale. Avant chaque recompose_for_op(), re-calcule HMAC(P1 XOR P2 XOR P3) et compare. Echec = emergency_shutdown() immediate."),
        p("mutation.c applique XOR aleatoire (RAND_bytes) sur P1 et P3, puis realloue P2 sur une nouvelle adresse heap. Le HMAC est recalcule et verifie apres mutation. Les statistiques (count, last_ts) sont exposees au dashboard."),
        h2("5.4 lmk_store.c / kek_provider.c — Persistance"),
        p("Format lmk.bin : sel(16o) | nonce_GCM(12o) | tag_GCM(16o) | ciphertext(32o). KEK = PBKDF2-SHA256(passphrase, sel, 100000). AES-256-GCM garantit confidentialite ET integrite (tag) — toute modification du fichier est detectee au dechiffrement."),
        h2("5.5 key_vault.c — Coffre des Cles"),
        p("payhsm_key_vault_t : tableau 32 entrees payhsm_key_entry_t. Chaque entree : id(48 chars), type(enum 8 valeurs), terminal_id(32 chars), enc[16] (chiffre sous LMK AES-ECB), kcv[3]. API : vault_find(type, terminal_id), vault_find_by_id(id), vault_save(), vault_load(). La LMK est recomposee brievement pour chiffrer/dechiffrer."),
        h2("5.6 pin.c — ISO 9564 Format 0"),
        p("PIN Block = (0x0N PIN_digits 0xF...) XOR (0x0000 PAN_12digits). Chiffrement AES-128-ECB sous TPK. Translation : dechiffre TPK -> extrait PIN -> reconstruit bloc clair -> chiffre ZPK. PIN jamais en clair hors buffers proteges. PVV VISA = decimalise(AES(PVK, PAN+PSN+PIN))[0:4]."),
        h2("5.7 mac.c — ISO 9797-1 Algorithme 3"),
        p("Retail MAC : CBC-MAC sur tous les blocs du message, puis AES sur le dernier bloc sous TAK. Verification a temps constant (boucle XOR, pas de memcmp() court-circuit). Le calcul ZAK fonctionne de maniere identique avec la cle ZAK."),
        h2("5.8 emv.c — EMV Book 2"),
        p("Methode A : MK-AC = HMAC-SHA1(IMK, PAN||PSN)[0:16]. SK-AC = XOR(MK-AC, ATC padde 16o). ARQC = CMAC-AES(SK-AC, donnees_tx). ARPC = CMAC-AES(MK-AC, ARQC XOR ARC). payhsm_emv_simulate_purchase() orchestre tout en un appel, zeroIse chaque secret des qu'il n'est plus utile."),
        h2("5.9 key_exchange.c — Hierarchie des Cles"),
        p("TPK = AES-CMAC(TMK, terminal_id||'TPK'). TAK = AES-CMAC(TMK, terminal_id||'TAK'). ZPK chiffre sous ZMK (AES-ECB) pour transport inter-bancaire. KCV = AES-ECB(key, 0x00...00)[0:3] pour verification visuelle."),
        h2("5.10 pkcs11_payment.cpp — ABI C PKCS#11"),
        p("Wrapper C++ avec extern \"C\" et __attribute__((visibility(\"default\"))). Deux raisons d'un ABI C : (1) ajouter des CKM_VENDOR_ dans SoftHSMv2 necessite de modifier plusieurs tables — hors scope PFE ; (2) l'ABI C est trivial a appeler depuis Python via ctypes. Partage du processus : LMK fragmentee et defenses identiques pour tous les clients."),
        br(),

        // ──────────────────────────────────────
        h1("6. Diagrammes UML de Conception"),
        p("Les codes PlantUML complets sont dans le fichier payhsm_diagrammes.puml (meme dossier). Rendez-les via https://plantuml.com, l'extension VS Code PlantUML, ou la CLI PlantUML."),
        h2("6.1 Diagramme de Cas d'Utilisation (UseCase_PayHSM)"),
        p("26 cas d'utilisation, 5 acteurs (Administrateur HSM, Application Bancaire, Terminal GAP, Switch Inter-Bancaire, Puce EMV), 6 packages fonctionnels. Relations cles : UC01-Provision inclut UC05-Fragmentation, UC24-Anti-dump, UC25-Anti-ptrace. UC02-Startup inclut UC06-Integrite. UC21-Achat EMV inclut UC16, UC18, UC19."),
        note("Section @startuml UseCase_PayHSM dans payhsm_diagrammes.puml"),
        h2("6.2 Diagramme de Classes (Classes_PayHSM)"),
        p("20 classes/modules, 5 packages (Core, KeyManager, Payment, Defense, Switch Interface). Agregation forte : payhsm_ctx_t contient payhsm_key_vault_t (1:1), qui compose 0..32 payhsm_key_entry_t. PKCS11Payment delegue a PinModule, MacModule, EmvModule. SwitchModule reutilise les memes primitives que Core. payhsm_key_type_t : 8 valeurs (LMK, TMK, TPK, TAK, ZMK, ZPK, PVK, IMK)."),
        note("Section @startuml Classes_PayHSM dans payhsm_diagrammes.puml"),
        h2("6.3 Sequence — Demarrage du HSM (Sequence_Startup)"),
        p("9 participants, 18 messages. Sequence : armement defenses (anti_dump, anti_ptrace, seccomp) -> lecture sel -> PBKDF2-SHA256 -> AES-256-GCM dechiffrement -> secure_zero(kek) -> HMAC reference -> fragmentation P1/P2/P3 -> secure_zero(lmk) -> vault_load. A la fin, la LMK n'existe plus en clair nulle part."),
        note("Section @startuml Sequence_Startup dans payhsm_diagrammes.puml"),
        h2("6.4 Sequence — Verification PIN Flux GAP (Sequence_PIN_Verify)"),
        p("Flux complet porteur -> terminal -> switch -> HSM acquéreur -> HSM emetteur. L'HSM acquéreur translate TPK -> ZPK. L'HSM emetteur verifie contre PVV. Chaque HSM commence par check_integrity() et termine par secure_zero() de tous les secrets manipules."),
        note("Section @startuml Sequence_PIN_Verify dans payhsm_diagrammes.puml"),
        h2("6.5 Sequence — Paiement EMV (Sequence_EMV_Purchase)"),
        p("Simulation complete en un appel payhsm_emv_simulate_purchase(). 10 etapes : recompose LMK -> derive MK-AC -> build donnees_tx -> derive SK-AC -> calcule ARQC -> verifie ARQC -> genere ARPC -> secure_zero(imk, mk_ac, sk_ac). Flux orchestre sans jamais exposer les cles en dehors des buffers locaux."),
        note("Section @startuml Sequence_EMV_Purchase dans payhsm_diagrammes.puml"),
        h2("6.6 Activite — Provisionnement (Activity_Provision)"),
        p("Flux lineaire de 12 etapes avec branchement conditionnel sur la presence de terminaux. Inclut : armement defenses, generation LMK aleatoire, derivation KEK PBKDF2, chiffrement AES-256-GCM, persistence lmk.bin, secure_zero(kek), HMAC reference, fragmentation, secure_zero(lmk), et si terminaux : derive TMK/TPK/TAK, KCV, vault_add_key, vault_save."),
        note("Section @startuml Activity_Provision dans payhsm_diagrammes.puml"),
        h2("6.7 Activite — Translation PIN TPK->ZPK (Activity_PIN_Translation)"),
        p("Deux gardes de securite : (1) HSM initialise ?, (2) Integrite HMAC OK ? -- echec = emergency_shutdown(). Si OK : recompose LMK -> dechiffre TPK et ZPK sous LMK -> secure_zero(lmk) -> AES-ECB decrypt sous TPK -> extraction ISO 9564 -> AES-ECB encrypt sous ZPK -> secure_zero(tpk, zpk, pin_plain)."),
        note("Section @startuml Activity_PIN_Translation dans payhsm_diagrammes.puml"),
        h2("6.8 Architecture Composants (Architecture_PayHSM)"),
        p("5 couches, 3 stores persistants (lmk.bin, keys.vault, cards.pvv), 3 interfaces clientes (PKCS#11 C ABI, Unix Socket, REST HTTP), dependance OpenSSL 3.x transversale. La couche Defense est transversale : utilisee par Core via direct calls et par XorFragment pour zero_all_fragments()."),
        note("Section @startuml Architecture_PayHSM dans payhsm_diagrammes.puml"),
        h2("6.9 Sequence — Mutation des Fragments (Sequence_Mutation)"),
        p("Flux : verify HMAC pre-mutation -> recompose verification -> secure_zero -> mutation_apply(XOR nonce + realloc heap P2 + MAJ HMAC) -> verify HMAC post-mutation -> lecture stats (count, last_ts). Ce flux garantit l'invariant d'integrite avant et apres chaque mutation."),
        note("Section @startuml Sequence_Mutation dans payhsm_diagrammes.puml"),
        br(),

        // ──────────────────────────────────────
        h1("7. Innovations, Conformite et Perspectives"),
        h2("7.1 Innovations Techniques"),
        tbl([2800,6226], [
          row([{t:"Innovation",w:2800,bg:DARK_BLUE},{t:"Detail",w:6226,bg:DARK_BLUE}], true),
          row([{t:"Fragmentation LMK tri-partite",w:2800},{t:"P1 (BSS) XOR P2 (heap, adresse variable) XOR P3 (DATA). Dispersion dans 3 segments force l'analyse de tout l'espace memoire du processus.",w:6226}]),
          row([{t:"Mutation anti-forensique",w:2800,bg:LIGHT_GREY},{t:"XOR aleatoire periodique + reallocation heap. Tout snapshot memoire anterieur est inutilisable pour reconstruire la LMK.",w:6226,bg:LIGHT_GREY}]),
          row([{t:"Defense en profondeur (4 couches)",w:2800},{t:"Anti-dump (OS) + anti-ptrace (debug) + seccomp BPF (syscalls) + HMAC fragments (crypto). Orthogonaux : un attaquant doit tous les contourner.",w:6226}]),
          row([{t:"Zeroisaton resistante compilateur",w:2800,bg:LIGHT_GREY},{t:"volatile + asm volatile barriere memoire. Contrairement a memset(), ne peut pas etre elimine par les optimisations du compilateur.",w:6226,bg:LIGHT_GREY}]),
          row([{t:"ABI C partagee PKCS#11",w:2800},{t:"Partage du processus libsofthsm2.so : LMK fragmentee et defenses identiques pour tous les clients (Python ctypes, pkcs11-tool, banking apps).",w:6226}]),
          row([{t:"Mode Switch complet",w:2800,bg:LIGHT_GREY},{t:"Toutes les operations PIN/MAC/EMV disponibles avec cles fournies par le Switch (GCM 88 hex / ECB 32 hex) sans coffre HSM local.",w:6226,bg:LIGHT_GREY}]),
        ]),
        h2("7.2 Conformite aux Standards"),
        tbl([2800,6226], [
          row([{t:"Standard",w:2800,bg:DARK_BLUE},{t:"Implementation PayHSM",w:6226,bg:DARK_BLUE}], true),
          row([{t:"ISO 9564 Format 0 (PIN Block)",w:2800},{t:"pin.c : generate_pin_block(), translate_pin_block(), verify_encrypted_pin_block()",w:6226}]),
          row([{t:"ISO 9797-1 Algo 3 (Retail MAC)",w:2800,bg:LIGHT_GREY},{t:"mac.c : calculate_mac_tak(), calculate_mac_zak(), verify_mac()",w:6226,bg:LIGHT_GREY}]),
          row([{t:"EMV Book 2 Methode A",w:2800},{t:"emv.c : derive_card_keys(), derive_sk_ac(), emv_compute_arqc(), generate_arpc(), verify_arpc()",w:6226}]),
          row([{t:"PVV VISA",w:2800,bg:LIGHT_GREY},{t:"pin.c : pin_compute_pvv() — decimalisation AES/Triple-DES",w:6226,bg:LIGHT_GREY}]),
          row([{t:"PKCS#11 (via SoftHSMv2)",w:2800},{t:"pkcs11_payment.cpp + integration SecureDataManager.cpp + SoftHSM.cpp",w:6226}]),
          row([{t:"Linux Security (LSM/prctl/seccomp)",w:2800,bg:LIGHT_GREY},{t:"defense.c : prctl, mlockall, seccomp BPF, rlimit, /proc/self/status",w:6226,bg:LIGHT_GREY}]),
        ]),
        h2("7.3 Perspectives d'Evolution"),
        bp("Authentification mutuelle TLS entre payhsm-cli et payhsmd (actuellement socket Unix local non chiffre)."),
        bp("Integration TPM : stocker le KEK dans un TPM hardware pour un stockage de confiance materielle."),
        bp("Clustering multi-HSM : replication chiffree du coffre entre plusieurs instances."),
        bp("Certification PCI HSM : audit et certification formelle de l'implementation."),
        bp("Interface REST securisee : TLS mutuel + JWT pour payhsm-httpd."),
        br(),

        // ──────────────────────────────────────
        h1("8. Glossaire"),
        tbl([1800,7226], [
          row([{t:"Terme",w:1800,bg:DARK_BLUE},{t:"Definition",w:7226,bg:DARK_BLUE}], true),
          row([{t:"ARPC",w:1800},{t:"Authorization Response Cryptogram — reponse chiffree de l'emetteur a la puce carte prouvant l'authenticite de la banque.",w:7226}]),
          row([{t:"ARQC",w:1800,bg:LIGHT_GREY},{t:"Authorization Request Cryptogram — cryptogramme genere par la puce EMV, prouvant l'authenticite de la carte.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"ATC",w:1800},{t:"Application Transaction Counter — compteur de transaction unique par puce EMV (2 octets).",w:7226}]),
          row([{t:"BPF",w:1800,bg:LIGHT_GREY},{t:"Berkeley Packet Filter — programme de filtrage noyau utilise pour seccomp (filtrage syscalls).",w:7226,bg:LIGHT_GREY}]),
          row([{t:"CMAC",w:1800},{t:"Cipher-based MAC sur AES — utilise pour ARQC/ARPC EMV.",w:7226}]),
          row([{t:"GAP",w:1800,bg:LIGHT_GREY},{t:"Guichet Automatique de Paiement — terminal equipe d'un EPP (Encrypting PIN Pad).",w:7226,bg:LIGHT_GREY}]),
          row([{t:"HSM",w:1800},{t:"Hardware Security Module — module de securite dedie aux cles crypto. PayHSM en est une implementation logicielle.",w:7226}]),
          row([{t:"IMK",w:1800,bg:LIGHT_GREY},{t:"Issuer Master Key — cle maitresse de la banque emettrice, racine des cles carte.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"KCV",w:1800},{t:"Key Check Value = AES-ECB(key, 0x00...)[0:3] — verification visuelle d'une cle.",w:7226}]),
          row([{t:"KEK",w:1800,bg:LIGHT_GREY},{t:"Key Encryption Key — derive de la passphrase (PBKDF2) pour chiffrer la LMK.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"LMK",w:1800},{t:"Local Master Key — cle maitresse du HSM. Jamais en clair en memoire (fragmentee P1/P2/P3).",w:7226}]),
          row([{t:"MK-AC",w:1800,bg:LIGHT_GREY},{t:"Master Key Application Cryptogram — cle carte derivee de l'IMK et du PAN/PSN.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"PAN",w:1800},{t:"Primary Account Number — numero de carte bancaire (16 chiffres).",w:7226}]),
          row([{t:"PBKDF2",w:1800,bg:LIGHT_GREY},{t:"Password-Based Key Derivation Function 2 — KDF robuste avec sel et iterations (ici SHA256, 100k).",w:7226,bg:LIGHT_GREY}]),
          row([{t:"PVK",w:1800},{t:"PIN Verification Key — cle pour calculer et verifier le PVV.",w:7226}]),
          row([{t:"PVV",w:1800,bg:LIGHT_GREY},{t:"PIN Verification Value — 4 chiffres stockes dans le HSM emetteur pour verifier le PIN sans le stocker.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"PSN",w:1800},{t:"PAN Sequence Number — numero de sequence carte (distingue les reemissions).",w:7226}]),
          row([{t:"SK-AC",w:1800,bg:LIGHT_GREY},{t:"Session Key Application Cryptogram = f(MK-AC, ATC) — unique par transaction EMV.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"TAK",w:1800},{t:"Terminal Authentication Key — cle de terminal pour calcul de MAC.",w:7226}]),
          row([{t:"TMK",w:1800,bg:LIGHT_GREY},{t:"Terminal Master Key — derive TPK et TAK.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"TPK",w:1800},{t:"Terminal PIN Key — chiffrement du PIN Block au terminal.",w:7226}]),
          row([{t:"ZAK",w:1800,bg:LIGHT_GREY},{t:"Zone Authentication Key — MAC inter-bancaire.",w:7226,bg:LIGHT_GREY}]),
          row([{t:"ZMK",w:1800},{t:"Zone Master Key — echange de ZPK entre banques.",w:7226}]),
          row([{t:"ZPK",w:1800,bg:LIGHT_GREY},{t:"Zone PIN Key — transport de PIN Blocks entre banques.",w:7226,bg:LIGHT_GREY}]),
        ]),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { before: 2000 },
          children: [new TextRun({ text: "--- Fin du Document ---", font: "Arial", size: 20, color: "888888", italics: true })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "PayHSM PFE 2026 | Analyse de Conception | Confidentiel", font: "Arial", size: 18, color: "AAAAAA" })],
        }),
      ],
    },
  ],
});

// ── Generation ───────────────────────────────────────────────
const outPath = path.join(__dirname, 'PayHSM_Analyse_Conception.docx');
Packer.toBuffer(doc)
  .then(buf => {
    fs.writeFileSync(outPath, buf);
    console.log('');
    console.log('  SUCCES : ' + outPath);
    console.log('  Taille : ' + (buf.length / 1024).toFixed(1) + ' KB');
    console.log('');
  })
  .catch(err => {
    console.error('ERREUR :', err.message);
    process.exit(1);
  });
