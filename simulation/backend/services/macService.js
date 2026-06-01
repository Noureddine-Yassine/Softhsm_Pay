/**
 * Contrôle intégrité ISO-8583 — MAC Retail sous TAK (clé chiffrée).
 */
import { HsmA, requireHsmReady } from '../hsm/hsmReal.js';
import { bus } from '../bus.js';
import { CONFIG } from '../config.js';

/** Exemple de trame ISO-8583 simplifiée (champ montant + PAN masqué) */
export function buildIso8583Message({ pan, amountCents, mti = '0200' }) {
  const amt = String(amountCents).padStart(12, '0');
  const panMasked = pan.replace(/.(?=.{4})/g, '*');
  return `${mti}|PAN=${panMasked}|AMT=${amt}|PROC=00|TERM=${CONFIG.GAB_TERMINAL}`;
}

export async function verifyIso8583Mac({ message, mac, terminal }) {
  await requireHsmReady();
  const term = terminal || CONFIG.GAB_TERMINAL;
  bus.publish({
    from: 'SWITCH', to: 'HSM-A', kind: 'request',
    label: 'Vérification MAC trame ISO-8583 (TAK)',
    payload: { terminal: term, macPreview: mac?.slice(0, 8) },
  });
  const r = await HsmA.macVerify({ terminal: term, message, mac });
  bus.publish({
    from: 'HSM-A', to: 'SWITCH', kind: r.valid ? 'success' : 'error',
    label: r.valid ? 'MAC valide — intégrité OK' : 'MAC invalide — trame altérée',
    payload: { valid: r.valid },
  });
  return r;
}

export async function signIso8583Mac({ message, terminal }) {
  await requireHsmReady();
  const term = terminal || CONFIG.GAB_TERMINAL;
  const r = await HsmA.macCalc({ terminal: term, message });
  return r;
}
