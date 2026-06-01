/**
 * Scénario 1 — Retrait INTRA-BANQUE
 *
 *   Carte Banque A → GAB Banque A → Switch A → HSM Banque A
 *
 * Tout passe par le HSM RÉEL (payhsm-httpd). Le PVV doit avoir été
 * émis au préalable via /api/corebanking/issue (le frontend HSM existant
 * permet déjà de le faire — onglet Core Banking).
 */
import { gabA_intra } from '../services/gab.js';
import { switchA_intra } from '../services/switchBank.js';
import { bus } from '../bus.js';
import { db } from '../db/memdb.js';
import { HsmA } from '../hsm/hsmReal.js';

export async function runIntraBank({ pan, pin, amount, terminal }) {
  const txId = 'TX-INTRA-' + Date.now();
  bus.publish({
    txId, stage: 0, from: 'CLIENT', to: 'GAB-A', kind: 'info',
    label: 'Client insère carte Banque A et saisit PIN',
    payload: { scenario: 'INTRA-BANQUE', pan: pan.replace(/.(?=.{4})/g, '*'), amount },
  });

  const cardRow = db.coreBankingCards.get(pan);
  if (!cardRow) {
    return {
      txId,
      ok: false,
      error: 'Carte inconnue — créez-la dans Core Banking (ou utilisez 4111111111111111)',
    };
  }

  // PVV : émission auto uniquement si la carte est en base mais pas encore activée
  try {
    const lookup = await HsmA.coreBankingLookup(pan);
    if (!lookup.pvv && !cardRow.pvv) {
      bus.publish({
        txId, stage: 0, from: 'CORE-A', to: 'HSM-A', kind: 'info',
        label: 'Émission PVV automatique (carte en base, PVV absent)',
        payload: { pan: pan.replace(/.(?=.{4})/g, '*') },
      });
      const issued = await HsmA.coreBankingIssue(pan, pin);
      if (issued.pvv) cardRow.pvv = issued.pvv;
    }
  } catch (e) {
    bus.publish({
      txId, stage: 0, from: 'CORE-A', to: 'SYS', kind: 'error',
      label: 'Émission PVV échouée : ' + e.message, payload: {},
    });
    return { txId, ok: false, error: e.message };
  }

  try {
    const gap = await gabA_intra({ txId, pan, pin, amount, terminal });
    const sw = await switchA_intra({
      txId, pan, pinBlock: gap.pinBlock, terminal: gap.terminal, amount,
    });
    return { txId, ok: true, scenario: 'INTRA', ...sw };
  } catch (e) {
    bus.publish({
      txId, stage: 99, from: 'SYS', to: 'CLIENT', kind: 'error',
      label: 'Échec scénario INTRA : ' + e.message, payload: {},
    });
    return { txId, ok: false, error: e.message };
  }
}
