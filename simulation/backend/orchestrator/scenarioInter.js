/**
 * INTER-BANQUES (démo acquéreur PayHSM) :
 *   GAB (ATM001) → GAP/TPK → Switch → PayHSM translate TPK→ZPK → réseau (routage BIN).
 * PayHSM Banque A ne fait pas de translation ZPK inter-banques.
 */
import { gabA_inter } from '../services/gab.js';
import { switchA_translate } from '../services/switchBank.js';
import { networkRoute, resolveIssuerBank } from '../services/networkCentral.js';
import { bus } from '../bus.js';
import { CONFIG } from '../config.js';

function maskPan(pan) {
  return pan.replace(/.(?=.{4})/g, '*');
}

export function validateInterPan(pan) {
  if (!pan || !/^\d{16}$/.test(pan)) {
    throw new Error('PAN invalide (16 chiffres)');
  }
  if (pan.startsWith('4')) {
    throw new Error(
      'PAN 4xxx = votre Banque A (PayHSM) — utilisez INTRA. Inter : carte autre banque (ex. 55xx).',
    );
  }
  const issuer = resolveIssuerBank(pan);
  if (issuer !== 'BANK-B') {
    throw new Error(
      `BIN ${pan.slice(0, 6)} → ${issuer}. Démo : PAN commençant par 55 (émetteur Banque B simulée).`,
    );
  }
  return { issuer, bin: pan.slice(0, 6) };
}

export async function runInterBank({ pan, pin, amount }) {
  const txId = 'TX-INTER-' + Date.now();
  const term = CONFIG.GAB_TERMINAL;

  let issuer;
  let bin;
  try {
    ({ issuer, bin } = validateInterPan(pan));
  } catch (e) {
    return { txId, ok: false, error: e.message };
  }

  bus.publish({
    txId,
    stage: 0,
    from: 'CLIENT',
    to: 'GAB-A',
    kind: 'info',
    label: `Carte ${maskPan(pan)} (BIN ${bin} → ${issuer}) au GAB ${term} — Banque A acquéreur`,
    payload: {
      scenario: 'INTER-BANQUES',
      pan: maskPan(pan),
      amount,
      terminal: term,
    },
  });

  try {
    const gap = await gabA_inter({ txId, pan, pin, amount });
    const sw = await switchA_translate({
      txId,
      pinBlock_tpkA: gap.pinBlock,
      terminal: gap.terminal,
    });
    const net = await networkRoute({
      txId,
      pan,
      pinBlock_zpkA: sw.pinBlock_zpkA,
      amount,
    });

    bus.publish({
      txId,
      stage: 12,
      from: 'NETWORK',
      to: 'CLIENT',
      kind: 'response',
      label:
        'Fin démo acquéreur — PayHSM a fait GAP + TPK→ZPK ; le réseau a routé vers l’émetteur',
      payload: { issuer: net.issuer, bin },
    });

    const cryptoPath = `TPK-${term} → ${CONFIG.KEYS.ZPK} (PayHSM) · réseau → ${issuer}`;

    return {
      txId,
      ok: true,
      demonstration: true,
      scenario: 'INTER',
      hsm: 'payhsm-httpd — GAP + translate TPK→ZPK uniquement',
      issuer: net.issuer,
      bin,
      terminal: term,
      cryptoPath,
      pinBlockZpk: sw.pinBlock_zpkA,
      message:
        'PayHSM Banque A : GAP + translation TPK→ZPK. Réseau : routage BIN (pas de translate-zpk sur payhsm-httpd).',
    };
  } catch (e) {
    bus.publish({
      txId,
      stage: 99,
      from: 'SYS',
      to: 'CLIENT',
      kind: 'error',
      label: 'Échec INTER : ' + e.message,
      payload: {},
    });
    return { txId, ok: false, error: e.message };
  }
}
