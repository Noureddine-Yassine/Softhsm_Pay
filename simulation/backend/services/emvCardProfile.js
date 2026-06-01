/**
 * Profil EMV par carte — date d'émission, ATC compteur, PSN.
 * MK-AC est dérivée à la volée : IMK (Switch) + PAN + PSN (unique par carte).
 */
import { CONFIG } from '../config.js';
import { db } from '../db/memdb.js';
import { HsmA } from '../hsm/hsmReal.js';

export function yymmddToday() {
  const d = new Date();
  const yy = String(d.getFullYear() % 100).padStart(2, '0');
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${yy}${mm}${dd}`;
}

export function formatDateDisplay(yymmdd) {
  if (!yymmdd || yymmdd.length < 6) return '—';
  return `${yymmdd.slice(4, 6)}/${yymmdd.slice(2, 4)}/20${yymmdd.slice(0, 2)}`;
}

/** Valeurs par défaut à l'émission carte */
export function defaultEmvCardFields() {
  return {
    emv_psn: '01',
    emv_atc: '0000',
    emv_date: yymmddToday(),
  };
}

/**
 * @param {string} pan
 * @returns {Promise<object>}
 */
export async function getCardEmvProfile(pan) {
  const panNorm = String(pan || '').replace(/\s/g, '');
  if (!/^\d{16}$/.test(panNorm)) {
    return { registered: false, pan: panNorm, error: 'PAN invalide (16 chiffres)' };
  }

  const card = db.coreBankingCards.get(panNorm);
  if (!card) {
    return {
      registered: false,
      pan: panNorm,
      error: 'Carte absente — créez-la dans Core Banking',
    };
  }

  let pvvSet = false;
  try {
    const lk = await HsmA.coreBankingLookup(panNorm);
    pvvSet = lk.rc === 0 && !!lk.pvv;
  } catch {
    /* HSM arrêté */
  }

  const psn = card.emv_psn || '01';
  const nextAtc = card.emv_atc ?? '0000';
  const emvDate = card.emv_date || yymmddToday();

  return {
    registered: true,
    pvvSet,
    pan: panNorm,
    panMasked: panNorm.replace(/.(?=.{4})/g, '*'),
    customer_name: card.customer_name,
    balance: card.balance,
    emv_psn: psn,
    emv_atc: nextAtc,
    emv_date: emvDate,
    emv_date_display: formatDateDisplay(emvDate),
    terminal: CONFIG.TPE_TERMINAL,
    currency: '978',
    currency_label: 'EUR',
    imk_source: 'Coffre Switch (provision IMK sous LMK)',
    mk_ac_hint: `MK-AC = f(IMK, PAN …${panNorm.slice(-4)}, PSN ${psn}) — clé carte unique`,
    sk_ac_hint: `SK-AC (ICC) = f(MK-AC, ATC ${nextAtc}) — prochain paiement`,
    ready: pvvSet,
  };
}
