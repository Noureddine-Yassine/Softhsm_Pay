/**
 * Switch — toutes les opérations crypto via payhsm-httpd (LMK + coffre src/lib/payhsm).
 */
import { bus } from '../bus.js';
import { db } from '../db/memdb.js';
import { CONFIG } from '../config.js';
import { HsmA } from '../hsm/hsmReal.js';
import { requireHsmReady } from '../hsm/hsmReal.js';
import { payhsmCall, PAYHSM } from './payhsmJournal.js';

function maskPan(pan) { return pan.replace(/.(?=.{4})/g, '*'); }

/* ═════════ Switch-A — INTRA-BANQUE ═════════ */
export async function switchA_intra({ txId, pan, pinBlock, terminal, amount }) {
  await requireHsmReady();

  bus.publish({
    txId, stage: 5, from: 'GAB-A', to: 'SWITCH-A', kind: 'request',
    label: 'Demande de retrait : PIN block (via PayHSM) + PAN + montant',
    payload: { pan: maskPan(pan), pinBlock, terminal, amount },
  });

  const cardRec = db.coreBankingCards.get(pan);
  const storedPvv = cardRec?.pvv || null;
  bus.publish({
    txId, stage: 5, from: 'BDD-A', to: 'SWITCH-A', kind: 'response',
    label: storedPvv ? `PVV (Core Banking) : ${storedPvv}` : 'PVV absent — créer carte d\'abord',
    payload: { storedPvv },
  });

  const verify = await payhsmCall({
    txId,
    stage: 6,
    from: 'SWITCH-A',
    api: '/api/verify',
    label: 'Verify PIN TPK + PVK (pin.c)',
    callFn: () => HsmA.verifyPVV(terminal, pan, pinBlock, storedPvv),
  });
  verify.approved = verify.result === 'APPROVED' && verify.code === 0;

  if (!verify.approved) return { approved: false, reason: 'PIN incorrect (code 55)' };

  const card = db.coreBankingCards.get(pan);
  if (!card) {
    return { approved: false, reason: 'Carte inconnue — métadonnées Core Banking' };
  }
  const enoughFunds = card.balance >= amount;
  if (enoughFunds) card.balance -= amount;

  bus.publish({
    txId, stage: 9, from: 'SWITCH-A', to: 'GAB-A',
    kind: enoughFunds ? 'response' : 'error',
    label: enoughFunds ? `APPROVED — ${amount}€` : 'DECLINED — solde insuffisant',
    payload: { approved: enoughFunds, newBalance: card.balance },
  });

  return { approved: enoughFunds, reason: enoughFunds ? 'APPROVED' : 'Solde insuffisant', newBalance: card.balance };
}

/* ═════════ Switch-A — INTER : TPK → ZPK (la vôtre, sous ZMK) ═════════ */
export async function switchA_translate({ txId, pinBlock_tpkA, terminal }) {
  await requireHsmReady();
  const term = terminal || CONFIG.GAB_TERMINAL;
  const tpk = CONFIG.KEYS.TPK;

  const r = await payhsmCall({
    txId,
    stage: 5,
    from: 'SWITCH-A',
    api: '/api/translate',
    label: `Switch → PayHSM : PIN block (${tpk}) reçu du GAB`,
    keysHint: `cryptogrammes TMK, ${tpk}, ZMK, ${CONFIG.KEYS.ZPK} (coffre Switch)`,
    responseLabel: `PayHSM : déchiffrement ${tpk} · rechiffrement ${CONFIG.KEYS.ZPK} (translate pin.c)`,
    callFn: () => HsmA.translate(term, pinBlock_tpkA, CONFIG.KEYS.ZPK),
  });

  if (r.rc !== 0 || !r.pinBlockZpk) {
    throw new Error(r.message || 'Translation TPK→ZPK PayHSM échouée');
  }

  bus.publish({
    txId, stage: 7, from: 'SWITCH-A', to: 'NETWORK', kind: 'crypto',
    label: `Switch → Réseau : PIN block sous ${CONFIG.KEYS.ZPK} (acquéreur)`,
    payload: { pinBlock_zpkA: r.pinBlockZpk, zpk: CONFIG.KEYS.ZPK },
  });

  return { pinBlock_zpkA: r.pinBlockZpk };
}

