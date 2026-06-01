/**
 * Réseau inter-banques — routage BIN uniquement (pas de translate-zpk sur PayHSM acquéreur).
 *
 * PayHSM Banque A : GAP (TPK) + translate TPK→ZPK seulement.
 * Le réseau reçoit le PIN block sous ZPK acquéreur et route vers l’émetteur (simulation).
 */
import { bus } from '../bus.js';
import { CONFIG } from '../config.js';
import { requireHsmReady } from '../hsm/hsmReal.js';

export function resolveIssuerBank(pan) {
  if (pan.startsWith('4')) return 'BANK-A';
  if (pan.startsWith('55')) return 'BANK-B';
  return 'UNKNOWN';
}

export async function networkRoute({ txId, pan, pinBlock_zpkA, amount }) {
  await requireHsmReady();

  bus.publish({
    txId, stage: 8, from: 'NETWORK', to: 'NETWORK', kind: 'request',
    label: `ISO 8583 0200 — PIN block sous ${CONFIG.KEYS.ZPK} (acquéreur)`,
    payload: { pan: pan.replace(/.(?=.{4})/g, '*'), amount, pinBlock_zpkA },
  });

  const issuer = resolveIssuerBank(pan);
  bus.publish({
    txId, stage: 9, from: 'NETWORK', to: 'NETWORK', kind: 'info',
    label: `Routage BIN ${pan.slice(0, 6)} → émetteur ${issuer}`,
    payload: { bin: pan.slice(0, 6), issuer },
  });

  bus.publish({
    txId,
    stage: 10,
    from: 'NETWORK',
    to: issuer === 'BANK-B' ? 'SWITCH-B' : 'SWITCH-ÉMETTEUR',
    kind: 'crypto',
    label:
      'Réseau CMI : opération inter-banques (hors PayHSM Banque A — pas de ZPK émetteur dans le coffre)',
    payload: {
      pinBlock_zpkA,
      zpkAcquirer: CONFIG.KEYS.ZPK,
      note: 'En production : HSM réseau / émetteur traduit vers sa ZPK',
    },
  });

  bus.publish({
    txId,
    stage: 11,
    from: 'NETWORK',
    to: 'NETWORK',
    kind: 'response',
    label: `Message prêt pour ${issuer} — fin démo acquéreur`,
    payload: { simulated: true, issuer },
  });

  return {
    issuer,
    bin: pan.slice(0, 6),
    pinBlock_zpkA,
    networkTranslation: 'routing-only',
  };
}
