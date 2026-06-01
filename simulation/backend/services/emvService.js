/**
 * TPE EMV — flux EMV Book 2 :
 * ① Puce → ARQC (SK-AC) → Switch → ② PayHSM émetteur : vérif ARQC + ARPC
 * → Switch → ③ Puce : MK-AC, recalcul ARPC, compare → ④ débit solde
 */
import { HsmA, requireHsmReady } from '../hsm/hsmReal.js';
import { payhsmCall } from './payhsmJournal.js';
import { getCard, debitCard } from './cardService.js';
import { CONFIG } from '../config.js';
import { bus } from '../bus.js';
import { formatDateDisplay } from './emvCardProfile.js';

const ENGINE = 'payment/emv.c';

/** Consomme le compteur ATC stocké sur la carte (prochain → suivant). */
function consumeAtc(card) {
  const cur = parseInt(card.emv_atc ?? '0000', 16);
  const use = Number.isFinite(cur) ? cur : 0;
  const hex = use.toString(16).toUpperCase().padStart(4, '0');
  card.emv_atc = (use + 1).toString(16).toUpperCase().padStart(4, '0');
  return hex;
}

/** Métadonnées visibles + chaîne de dérivation clé ICC (EMV Book 2) */
function buildTxMeta({ panNorm, psnVal, atcVal, amountCents, currency, dateYymmdd, terminalId }) {
  const curLabel = currency === '978' ? 'EUR' : currency;
  return {
    date: dateYymmdd,
    dateDisplay: formatDateDisplay(dateYymmdd),
    atc: atcVal,
    terminal: terminalId,
    currency,
    amountCents,
    amountDisplay: `${(amountCents / 100).toFixed(2)} ${curLabel}`,
    iccKeyChain: [
      'IMK — clé maître émetteur (coffre Switch, commune à toutes les cartes)',
      `MK-AC = f(IMK, PAN …${panNorm.slice(-4)}, PSN ${psnVal}) → une clé par carte`,
      `SK-AC (ICC session) = f(MK-AC, ATC ${atcVal}) → une clé par transaction`,
      'ARQC = CMAC(SK-AC, montant|devise|date|ATC|terminal) — la clé ne sort jamais de la puce/HSM',
      'ARPC = AES-ECB(MK-AC, ARQC⊕ARC) — la puce recalcule et compare à l\'ARPC émetteur',
    ],
  };
}

export async function processEmvPurchase({
  pan,
  amountCents,
  psn,
  atc,
  currency = '978',
  date,
  terminal,
}) {
  const txId = 'TX-EMV-' + Date.now();
  const panNorm = String(pan || '').replace(/\s/g, '');
  const steps = [];
  const terminalId = terminal || CONFIG.TPE_TERMINAL;

  await requireHsmReady();

  const card = getCard(panNorm);
  if (!card) {
    const msg =
      'Carte inconnue — créez-la d\'abord dans Core Banking (PAN + PIN → PVV HSM)';
    steps.push({ id: 'card', ok: false, label: msg });
    return { txId, approved: false, steps, message: msg, engine: ENGINE };
  }

  const lk = await HsmA.coreBankingLookup(panNorm);
  if (lk.rc !== 0 || !lk.pvv) {
    const msg =
      'PVV absent dans le HSM — émettez la carte via Core Banking avant tout paiement EMV';
    steps.push({ id: 'card', ok: false, label: msg });
    return { txId, approved: false, steps, message: msg, engine: ENGINE };
  }

  const amountEur = amountCents / 100;
  if (card.balance < amountEur) {
    const msg = `Solde insuffisant (${card.balance}€ < ${amountEur.toFixed(2)}€)`;
    steps.push({ id: 'card', ok: false, label: msg });
    return {
      txId,
      approved: false,
      reason: msg,
      steps,
      message: msg,
      engine: ENGINE,
    };
  }

  const psnVal = psn || card.emv_psn || '01';
  const dateYymmdd = date || card.emv_date;
  if (!dateYymmdd) {
    const msg = 'Date EMV absente sur la carte — réémettez via Core Banking';
    steps.push({ id: 'card', ok: false, label: msg });
    return { txId, approved: false, steps, message: msg, engine: ENGINE };
  }
  const atcVal = atc || consumeAtc(card);
  const txMeta = buildTxMeta({
    panNorm,
    psnVal,
    atcVal,
    amountCents,
    currency,
    dateYymmdd,
    terminalId,
  });

  bus.publish({
    txId,
    stage: 1,
    from: 'PUCE',
    to: 'HSM-A',
    kind: 'request',
    label: '① Puce : données tx + ICC Key → ARQC',
    payload: {
      pan: panNorm.replace(/.(?=.{4})/g, '*'),
      amountCents,
      currency,
      atc: atcVal,
      date: dateYymmdd,
      terminal: terminalId,
    },
  });

  const arqcRes = await HsmA.emvArqc({
    pan: panNorm,
    psn: psnVal,
    atc: atcVal,
    amountCents,
    currency,
    date: dateYymmdd,
    terminal: terminalId,
  });

  if (arqcRes.rc != null && arqcRes.rc !== 0) {
    const msg =
      arqcRes.message ||
      (arqcRes.rc === -3
        ? 'Carte non enregistrée — Core Banking (PVV) requis avant EMV'
        : 'Échec calcul ARQC (emv.c)');
    steps.push({ id: 'card', ok: false, api: '/api/emv/arqc', label: msg });
    bus.publish({
      txId,
      stage: 1,
      from: 'HSM-A',
      to: 'PUCE',
      kind: 'error',
      label: 'ARQC refusé — ' + msg,
      payload: {},
    });
    return { txId, approved: false, steps, message: msg, engine: ENGINE, ...txMeta };
  }

  const { arqc, txData, txDataLen } = arqcRes;
  if (!arqc || !txData) {
    const msg = 'Réponse ARQC incomplète';
    steps.push({ id: 'card', ok: false, api: '/api/emv/arqc', label: msg });
    return { txId, approved: false, steps, message: msg, engine: ENGINE, ...txMeta };
  }

  steps.push({
    id: 'card',
    ok: true,
    api: '/api/emv/arqc',
    label: `Puce : ARQC unique (ATC ${atcVal}, ${txData})`,
    arqc,
  });

  bus.publish({
    txId,
    stage: 1,
    from: 'HSM-A',
    to: 'PUCE',
    kind: 'crypto',
    label: `ARQC ${arqc}`,
    payload: { engine: arqcRes.engine || ENGINE, txData },
  });

  bus.publish({
    txId,
    stage: 2,
    from: 'TPE',
    to: 'RESEAU',
    kind: 'request',
    label: 'Authorization Request (ARQC + txData)',
    payload: { pan: panNorm.replace(/.(?=.{4})/g, '*'), atc: atcVal },
  });

  steps.push({
    id: 'network',
    ok: true,
    label: 'Réseau — routage vers émetteur (IMK Switch)',
    txDataPreview: txData.length > 48 ? txData.slice(0, 48) + '…' : txData,
  });

  bus.publish({
    txId,
    stage: 2,
    from: 'RESEAU',
    to: 'HSM-EMETTEUR',
    kind: 'request',
    label: '② Émetteur : IMK+PAN+ATC → ICC Key, recalcul ARQC',
    payload: { arqc },
  });

  const verRes = await HsmA.emvVerify({
    pan: panNorm,
    psn: psnVal,
    atc: atcVal,
    txData,
    txDataLen: txDataLen ?? txData.length,
    arqc,
  });

  const issuerOk =
    verRes.rc === 0 &&
    (verRes.valid === true || verRes.valid === 'true');
  const cardInline =
    verRes.arpcCardValid === undefined || verRes.arpcCardValid === null
      ? true
      : verRes.arpcCardValid === true || verRes.arpcCardValid === 'true';
  const approved =
    issuerOk &&
    (verRes.approved === undefined || verRes.approved === null
      ? issuerOk
      : verRes.approved === true || verRes.approved === 'true') &&
    cardInline;

  if (!approved) {
    const msg =
      verRes.message ||
      (verRes.rc === -3
        ? 'Carte non enregistrée — Core Banking requis'
        : 'ARQC invalide — fraude ou données transaction modifiées');
    steps.push({ id: 'issuer', ok: false, api: '/api/emv/verify', label: msg });
    bus.publish({
      txId,
      stage: 3,
      from: 'HSM-EMETTEUR',
      to: 'TPE',
      kind: 'error',
      label: 'DECLINED — ' + msg,
      payload: {},
    });
    return {
      txId,
      approved: false,
      arqc,
      txData,
      atc: atcVal,
      psn: psnVal,
      steps,
      reason: msg,
      message: msg,
      engine: verRes.engine || ENGINE,
      nextAtc: card.emv_atc,
      ...txMeta,
    };
  }

  steps.push({
    id: 'issuer',
    ok: true,
    api: '/api/emv/verify',
    label: 'Émetteur : ARQC reçu = ARQC calculé → ARPC',
    arpc: verRes.arpc,
  });

  bus.publish({
    txId,
    stage: 3,
    from: 'HSM-EMETTEUR',
    to: 'TPE',
    kind: 'crypto',
    label: `ARPC émetteur ${verRes.arpc}`,
    payload: { arpc: verRes.arpc },
  });

  bus.publish({
    txId,
    stage: 4,
    from: 'TPE',
    to: 'PUCE',
    kind: 'request',
    label: '④ Puce : MK-AC → recalcul ARPC, compare réponse émetteur',
    payload: { arpc: verRes.arpc },
  });

  /** Même MK-AC que l'émetteur : inclus dans /api/emv/verify (évite 3e HTTP + crash session) */
  const inlineCard =
    verRes.arpcCardValid !== undefined && verRes.arpcCardValid !== null;
  let arpcValid = false;
  let arpcExpected = verRes.arpcExpected || verRes.arpc || '';
  let arpcCheck = { rc: 0, valid: false, arpcExpected, engine: ENGINE };

  if (inlineCard) {
    arpcValid =
      verRes.arpcCardValid === true || verRes.arpcCardValid === 'true';
    arpcCheck = { rc: 0, valid: arpcValid, arpcExpected, engine: verRes.engine || ENGINE };
    bus.publish({
      txId,
      stage: 4,
      from: 'PayHSM (Banque A)',
      to: 'PUCE',
      kind: arpcValid ? 'crypto' : 'error',
      label: arpcValid
        ? 'PayHSM : EMV puce verify ARPC OK (emv.c, MK-AC session verify)'
        : `PayHSM : EMV puce verify ARPC KO — recv ${verRes.arpc} expect ${arpcExpected}`,
      payload: { api: '/api/emv/verify', arpc: verRes.arpc, arpcExpected },
    });
  } else {
    arpcCheck = await payhsmCall({
      txId,
      stage: 4,
      from: 'TPE',
      replyTo: 'PUCE',
      api: '/api/emv/verify-arpc',
      label: 'Puce verify ARPC (MK-AC, emv.c verify_arpc)',
      responseLabel: null,
      callFn: () =>
        HsmA.emvVerifyArpc({
          pan: panNorm,
          psn: psnVal,
          atc: atcVal,
          arqc,
          arpc: verRes.arpc,
          arc: '0000',
        }),
    });
    arpcValid =
      arpcCheck.rc === 0 &&
      (arpcCheck.valid === true || arpcCheck.valid === 'true');
    arpcExpected = arpcCheck.arpcExpected || arpcExpected;
  }

  steps.push({
    id: 'card_arpc',
    ok: arpcValid,
    api: inlineCard ? '/api/emv/verify' : '/api/emv/verify-arpc',
    label: arpcValid
      ? `Puce : ARPC reçu = ARPC recalculé (MK-AC) ✓`
      : `Puce : ARPC KO — reçu ${verRes.arpc} ≠ attendu ${arpcExpected || '?'}`,
    arpc: verRes.arpc,
    arpcExpected,
    mkAcHint: 'MK-AC = f(IMK, PAN, PSN) — dans la puce (simulation via emv.c)',
  });

  if (!arpcValid) {
    const msg =
      arpcCheck.message ||
      'ARPC invalide côté puce — réponse émetteur rejetée par la carte';
    bus.publish({
      txId,
      stage: 5,
      from: 'PUCE',
      to: 'TPE',
      kind: 'error',
      label: 'DECLINED — ' + msg,
      payload: { arpcReceived: verRes.arpc, arpcExpected },
    });
    return {
      txId,
      approved: false,
      arqc,
      arpc: verRes.arpc,
      arpcExpected,
      txData,
      atc: atcVal,
      psn: psnVal,
      steps,
      reason: msg,
      message: msg,
      engine: arpcCheck.engine || ENGINE,
      nextAtc: card.emv_atc,
      ...txMeta,
    };
  }

  bus.publish({
    txId,
    stage: 5,
    from: 'PUCE',
    to: 'TPE',
    kind: 'success',
    label: `Puce : ARPC validé (MK-AC) — transaction acceptée`,
    payload: { arpc: verRes.arpc },
  });

  let newBalance;
  try {
    newBalance = debitCard(panNorm, amountEur);
  } catch (e) {
    const msg = e.message || 'Débit solde impossible';
    steps.push({ id: 'balance', ok: false, label: msg });
    return {
      txId,
      approved: false,
      reason: msg,
      arqc,
      txData,
      steps,
      message: msg,
      engine: verRes.engine || ENGINE,
      ...txMeta,
    };
  }

  steps.push({
    id: 'balance',
    ok: true,
    label: `Core Banking : −${amountEur.toFixed(2)}€ → solde ${newBalance}€`,
  });

  bus.publish({
    txId,
    stage: 6,
    from: 'CORE-BANK',
    to: 'TPE',
    kind: 'info',
    label: `Solde mis à jour : ${newBalance}€`,
    payload: { pan: panNorm.replace(/.(?=.{4})/g, '*'), debited: amountEur },
  });

  return {
    txId,
    approved: true,
    ok: true,
    arqc,
    arpc: verRes.arpc,
    arpcExpected: arpcCheck.arpcExpected || verRes.arpc,
    arpcValid: true,
    txData,
    atc: atcVal,
    psn: psnVal,
    steps,
    message: `Paiement EMV approuvé — ARPC validé puce (MK-AC) — solde ${newBalance}€`,
    newBalance,
    debited: amountEur,
    engine: ENGINE,
    flow:
      'puce ARQC → switch → PayHSM (vérif ARQC + ARPC) → switch → puce (vérif ARPC MK-AC) → solde',
    nextAtc: card.emv_atc,
    ...txMeta,
  };
}
