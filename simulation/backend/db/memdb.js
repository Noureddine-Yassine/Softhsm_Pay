/**
 * Base de données in-memory du Switch (Core Banking).
 *
 * SWITCH_KEY_VAULT : cryptogrammes (GCM sous LMK ou ECB sous TMK) — jamais en clair
 * CORE_BANKING_CARDS : métadonnées (PAN, nom, solde). PVV = HSM cards.pvv (pin.c)
 */
import { CONFIG } from '../config.js';

/** @typedef {'TPK'|'ZPK'|'PVK'|'IMK'|'TAK'|'ZMK'|'TMK'} KeyType */

/**
 * @typedef {Object} VaultEntry
 * @property {string} key_id
 * @property {KeyType} key_type
 * @property {string} cryptogram  GCM 88 hex (LMK) ou ECB 32 hex (TMK)
 * @property {string} kcv
 * @property {string} [terminal]
 * @property {'LMK'|string} [wrapped_by]
 * @property {string|null} [parent_key_id]
 */

/**
 * @typedef {Object} CardRecord
 * @property {string} pan
 * @property {string} customer_name
 * @property {string} pvv
 * @property {number} balance
 */

export const db = {
  /** @type {Map<string, VaultEntry>} */
  switchKeyVault: new Map(),
  /** @type {Map<string, CardRecord>} */
  coreBankingCards: new Map(),
  network: { name: CONFIG.NETWORK.NAME },
  lastLmkRef: null,
  /** Dernier bootId HSM vu (informatif) */
  lastHsmBootId: null,
  /** Répertoire données PayHSM (api/lmk/status) */
  lastHsmDataDir: null,
};

export function resetDemoCards() {
  db.coreBankingCards.clear();
  seedCards();
}

function seedCards() {
  const seeds = [
    {
      pan: '4111111111111111',
      customer_name: 'Yassine N.',
      pvv: '',
      balance: 12500,
      emv_psn: '01',
      emv_atc: '0000',
      emv_date: '260117',
    },
    {
      pan: '4222222222222222',
      customer_name: 'Saad B.',
      pvv: '',
      balance: 8200,
      emv_psn: '01',
      emv_atc: '0000',
      emv_date: '260201',
    },
    {
      pan: '5500000000000004',
      customer_name: 'Hicham B.',
      pvv: '',
      balance: 6400,
      emv_psn: '01',
      emv_atc: '0000',
      emv_date: '260315',
    },
    {
      pan: '5500000000000012',
      customer_name: 'Salma K.',
      pvv: '',
      balance: 3100,
      emv_psn: '01',
      emv_atc: '0000',
      emv_date: '260401',
    },
  ];
  for (const c of seeds) {
    db.coreBankingCards.set(c.pan, { ...c });
  }
}

seedCards();

/** Compatibilité scénarios ATM existants */
function cardAdapter(pan) {
  const c = db.coreBankingCards.get(pan);
  if (!c) return undefined;
  return {
    pvv: c.pvv,
    customerName: c.customer_name,
    balance: c.balance,
    pin: undefined,
  };
}

function cardSet(pan, partial) {
  const prev = db.coreBankingCards.get(pan) || {
    pan, customer_name: partial.customerName || 'Client', pvv: '', balance: 5000,
  };
  db.coreBankingCards.set(pan, {
    pan,
    customer_name: partial.customerName ?? prev.customer_name,
    pvv: partial.pvv ?? prev.pvv,
    balance: partial.balance ?? prev.balance,
    emv_psn: partial.emv_psn ?? prev.emv_psn ?? '01',
    emv_atc: partial.emv_atc ?? prev.emv_atc ?? '0000',
    emv_date: partial.emv_date ?? prev.emv_date,
  });
}

db.bankA = {
  name: CONFIG.BANK_A.NAME,
  cards: {
    get: cardAdapter,
    set: (pan, c) => cardSet(pan, c),
    entries: () => [...db.coreBankingCards.entries()].map(([pan, c]) => [pan, {
      pvv: c.pvv, customerName: c.customer_name, balance: c.balance,
    }]),
  },
};
db.bankB = db.bankA;
