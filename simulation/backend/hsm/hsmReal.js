/**
 * Client HTTP vers payhsm-httpd — crypto via LMK ; clés fournies par le Switch.
 */
import fetch from 'node-fetch';
import { CONFIG } from '../config.js';
import {
  switchPayloadTerminal,
  switchPayloadZpk,
  switchPayloadImk,
  switchPayloadZpkPair,
  requireVaultKey,
} from '../services/switchKeys.js';

async function call(path, body) {
  const url = CONFIG.HSM_A_URL + path;
  let res;
  try {
    res = await fetch(url, {
      method: body ? 'POST' : 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    const msg = String(e.message || e);
    let hint =
      'Lancez payhsm-httpd : ./scripts/start-console.sh (console http://127.0.0.1:8765).';
    if (msg.includes('ECONNREFUSED') || msg.includes('fetch failed')) {
      hint =
        'payhsm-httpd n\'écoute pas sur ce port — la console web seule ne suffit pas.';
    } else if (msg.includes('hang up') || msg.includes('ECONNRESET')) {
      hint =
        'payhsm-httpd a fermé la connexion (crash ?) — relancez ./scripts/start-console.sh.';
    }
    throw new Error(`HSM injoignable sur ${CONFIG.HSM_A_URL}. ${hint} (${msg})`);
  }
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('Réponse HSM invalide: ' + text.slice(0, 100)); }
  if (!res.ok) throw new Error(data.message || `HSM error ${res.status}`);
  return data;
}

export const HsmA = {
  health: () => call('/api/health'),
  status: () => call('/api/status'),
  securityLogs: () => call('/api/security/logs'),
  lmkStatus: () => call('/api/lmk/status'),
  lmkFragments: () => call('/api/lmk/fragments'),

  wrapKey: (keyHex) => call('/api/switch/wrap-key', { keyHex }),
  wrapZpk: (zmkCryptogram, keyHex) =>
    call('/api/switch/wrap-zpk', { zmkCryptogram, keyHex }),
  deriveTerminal: (tmkCryptogram, terminal) =>
    call('/api/switch/derive-terminal', { tmkCryptogram, terminal }),

  gap: (terminal, pin, pan) =>
    call('/api/gap', { terminal, pin, pan, ...switchPayloadTerminal(terminal) }),

  verifyPVV: async (terminal, pan, pinBlock, pvv) => {
    const sp = switchPayloadTerminal(terminal);
    const pvkCryptogram = requireVaultKey(CONFIG.KEYS.PVK).cryptogram;
    const r = await call('/api/verify', {
      pan,
      pinBlock,
      pvv,              /* PVV fourni par le Core Banking, recalculé par le HSM pour comparer */
      tmkCryptogram: sp.tmkCryptogram,
      tpkCryptogram: sp.tpkCryptogram,
      pvkCryptogram,
    });
    return { ...r, approved: r.result === 'APPROVED' && r.code === 0 };
  },

  translate: (terminal, pinBlock, zpkId = CONFIG.KEYS.ZPK) => {
    const sp = switchPayloadTerminal(terminal);
    const zp = switchPayloadZpk(zpkId);
    return call('/api/translate', {
      pinBlock,
      zpkId,
      tmkCryptogram: sp.tmkCryptogram,
      tpkCryptogram: sp.tpkCryptogram,
      zmkCryptogram: zp.zmkCryptogram,
      zpkCryptogram: zp.zpkCryptogram,
    });
  },

  translateZpk: (pinBlock, fromZpkId, toZpkId) =>
    call('/api/translate-zpk', {
      pinBlock,
      fromZpkId,
      toZpkId,
      ...switchPayloadZpkPair(fromZpkId, toZpkId),
    }),

  verifyZpk: (pan, pinBlock, zpkId) =>
    call('/api/verify-zpk', { pan, pinBlock, zpkId, ...switchPayloadZpk(zpkId) }),

  coreBankingIssue: (pan, pin) => {
    const pvk = requireVaultKey(CONFIG.KEYS.PVK).cryptogram;
    return call('/api/corebanking/issue', {
      pan,
      pin,
      pvkCryptogram: pvk,
    });
  },

  coreBankingLookup: (pan) => call('/api/corebanking/lookup', { pan }),

  macCalc: ({ terminal, message }) => {
    const sp = switchPayloadTerminal(terminal);
    return call('/api/mac/calc', {
      message,
      tmkCryptogram: sp.tmkCryptogram,
      takCryptogram: sp.takCryptogram,
    });
  },

  macVerify: ({ terminal, message, mac }) => {
    const sp = switchPayloadTerminal(terminal);
    return call('/api/mac/verify', {
      message,
      mac,
      tmkCryptogram: sp.tmkCryptogram,
      takCryptogram: sp.takCryptogram,
    });
  },

  emvArqc: (p) =>
    call('/api/emv/arqc', {
      pan: p.pan,
      psn: p.psn || '01',
      atc: p.atc || '0001',
      amountCents: String(p.amountCents),
      currency: p.currency || '978',
      date: p.date,
      terminal: p.terminal,
      ...switchPayloadImk(),
    }),

  emvVerify: (p) =>
    call('/api/emv/verify', {
      pan: p.pan,
      psn: p.psn || '01',
      atc: p.atc || '0001',
      txData: p.txData,
      txDataLen: p.txDataLen != null ? String(p.txDataLen) : undefined,
      arqc: p.arqc,
      ...switchPayloadImk(),
    }),

  /** Puce : MK-AC → recalcul ARPC, compare à l'ARPC émetteur */
  emvVerifyArpc: (p) =>
    call('/api/emv/verify-arpc', {
      pan: p.pan,
      psn: p.psn || '01',
      atc: p.atc || '0001',
      arqc: p.arqc,
      arpc: p.arpc,
      arc: p.arc || '0000',
      ...switchPayloadImk(),
    }),

  emvPurchase: (p) =>
    call('/api/emv/purchase', {
      pan: p.pan,
      psn: p.psn || '01',
      atc: p.atc || '0001',
      amountCents: String(p.amountCents),
      currency: p.currency || '978',
      date: p.date,
      terminal: p.terminal,
      ...switchPayloadImk(),
    }),

  paymentModules: () => call('/api/payment/modules'),
};

export async function requireHsmReady() {
  const h = await HsmA.health();
  if (!h.initialized) {
    throw new Error(
      'HSM non démarré. Console http://127.0.0.1:8765 → Provision (LMK seule) puis Démarrer.',
    );
  }
  return h;
}
