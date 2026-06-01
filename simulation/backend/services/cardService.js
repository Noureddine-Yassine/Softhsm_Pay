/**
 * Core Banking — métadonnées (nom, solde) en mémoire Switch.
 * PVV : uniquement dans le HSM (payment/pin.c → cards.pvv sur disque).
 */
import { db } from '../db/memdb.js';
import { HsmA, requireHsmReady } from '../hsm/hsmReal.js';
import { bus } from '../bus.js';
import {
  defaultEmvCardFields,
  getCardEmvProfile,
  formatDateDisplay,
} from './emvCardProfile.js';

export { getCardEmvProfile };

export async function listCards() {
  const cards = [...db.coreBankingCards.values()];
  const out = [];
  for (const c of cards) {
    let pvvSet = false;
    try {
      const lk = await HsmA.coreBankingLookup(c.pan);
      pvvSet = lk.rc === 0 && !!lk.pvv;
    } catch { /* HSM arrêté */ }
    out.push({
      pan: c.pan,
      panMasked: c.pan.replace(/.(?=.{4})/g, '*'),
      customer_name: c.customer_name,
      pvvSet,
      balance: c.balance,
      emv_psn: c.emv_psn || '01',
      emv_atc: c.emv_atc ?? '0000',
      emv_date_display: formatDateDisplay(c.emv_date),
    });
  }
  return out;
}

export async function createCard({ pan, customerName, pin, balance = 5000 }) {
  if (!pan || !/^\d{16}$/.test(pan)) {
    throw new Error('PAN invalide (16 chiffres)');
  }
  if (!pin || pin.length < 4) throw new Error('PIN invalide');
  if (!customerName) throw new Error('Nom client requis');

  await requireHsmReady();

  const txId = 'TX-ISSUE-' + Date.now();
  bus.publish({
    txId, stage: 1, from: 'CORE-BANK', to: 'HSM-A', kind: 'request',
    label: 'POST /api/corebanking/issue → pin_compute_pvv (pin.c)',
    payload: { pan: pan.replace(/.(?=.{4})/g, '*') },
  });

  const r = await HsmA.coreBankingIssue(pan, pin);
  if (r.rc !== 0 && !r.pvv) throw new Error(r.message || 'Échec PVV HSM');

  const emv = defaultEmvCardFields();
  db.coreBankingCards.set(pan, {
    pan,
    customer_name: customerName,
    pvv: r.pvv,          /* PVV stocké côté Core Banking, plus dans le HSM */
    balance: Number(balance) || 0,
    ...emv,
  });

  bus.publish({
    txId, stage: 2, from: 'HSM-A', to: 'CORE-BANK', kind: 'response',
    label: 'PVV calculé (pin_compute_pvv) — stocké Core Banking, PIN effacé',
    payload: { pan: pan.replace(/.(?=.{4})/g, '*'), pvv: r.pvv },
  });

  return {
    pan,
    customer_name: customerName,
    pvv: r.pvv,
    balance: Number(balance),
    emv_psn: emv.emv_psn,
    emv_atc: emv.emv_atc,
    emv_date: emv.emv_date,
    emv_date_display: formatDateDisplay(emv.emv_date),
  };
}

export function getCard(pan) {
  return db.coreBankingCards.get(pan);
}

export function debitCard(pan, amount) {
  const card = db.coreBankingCards.get(pan);
  if (!card) throw new Error('Carte inconnue (métadonnées Core Banking)');
  if (card.balance < amount) throw new Error('Solde insuffisant');
  card.balance -= amount;
  return card.balance;
}
