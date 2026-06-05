/**
 * Trames wire payShield / Thales (mode PAYSHIELD_COMPAT).
 * Cycle opérateur : A0 (gen) → A8 (export) → Switch A6 (auto).
 */

/** Key Type Codes — alignés PayHSM / cahier Paylogic */
export const PS_KEY_TYPE = {
  ZMK: '000',
  ZPK: '001',
  TPK: '002',
  TAK: '003',
  TMK: '007',
  PVK: '008',
  IMK: '109',
  ZAK: '009',
  IMK_ALT: '00B',
};

export function keyTypeCode(name) {
  const n = String(name || '').toUpperCase();
  const c = PS_KEY_TYPE[n];
  if (!c) throw new Error(`KEY_TYPE inconnu: ${name}`);
  return c;
}

/** KEK de transport pour export A8 / import A6 */
export function transportKeyId(keyTypeName) {
  const n = String(keyTypeName || '').toUpperCase();
  if (n === 'TPK' || n === 'TAK') return 'TMK';
  if (n === 'ZPK' || n === 'PVK' || n === 'IMK') return 'ZMK';
  throw new Error(`Pas de transport pour ${n}`);
}

/** Commandes Thales exactes à taper (concaténées, sans espace) */
export const OPERATOR_COMMANDS = {
  ZPK: {
    a0: '0001A00001U00',
    a8: (zpk88) => `0001A8L${PS_KEY_TYPE.ZPK}U${zpk88}`,
    a8Legacy: (zmk88, zpk88) => `0001A8U${zmk88}${PS_KEY_TYPE.ZPK}U${zpk88}`,
    transport: 'ZMK',
    type: '001',
  },
  TPK: {
    a0: '0001A00002U00',
    a8: (tpk88) => `0001A8L${PS_KEY_TYPE.TPK}U${tpk88}`,
    a8Legacy: (tmk88, tpk88) => `0001A8U${tmk88}${PS_KEY_TYPE.TPK}U${tpk88}`,
    transport: 'TMK',
    type: '002',
  },
  TAK: {
    a0: '0001A00003U00',
    a8: (tak88) => `0001A8L${PS_KEY_TYPE.TAK}U${tak88}`,
    a8Legacy: (tmk88, tak88) => `0001A8U${tmk88}${PS_KEY_TYPE.TAK}U${tak88}`,
    transport: 'TMK',
    type: '003',
  },
  PVK: {
    a0: '0001A00008U00',
    a8: (zmk88, pvk88) => `0001A8U${zmk88}${PS_KEY_TYPE.PVK}U${pvk88}`,
    transport: 'ZMK',
  },
  IMK: {
    a0: '0001A00109U00',
    a8: (zmk88, imk88) => `0001A8U${zmk88}${PS_KEY_TYPE.IMK}U${imk88}`,
    transport: 'ZMK',
  },
};

export function toThalesBlock(scheme, value) {
  const v = String(value || '').toUpperCase();
  if (v.length === 33) return v;
  if (v.length === 32) return `${scheme || 'U'}${v}`;
  throw new Error('Attendu 32 hex ou bloc 33 (scheme+32hex)');
}

export function buildA0Mode0(hdr, keyTypeName, scheme = 'U', lmkId = '00') {
  return `${hdr || '0001'}A00${keyTypeCode(keyTypeName)}${scheme}${lmkId}`;
}

export function parseA1Mode0(raw) {
  const s = String(raw || '');
  if (s.slice(6, 8) !== '00') throw new Error(`A1 erreur ${s.slice(6, 8)}`);
  const d = s.slice(8);
  return { keyUnderLmk: d.slice(0, 33), kcv: d.slice(33, 39), cryptogram: null };
}

export function buildA8Export(hdr, keyTypeName, kekGcm88, keyGcm88, opts = {}) {
  const kek = String(kekGcm88 || '').toUpperCase();
  const key = String(keyGcm88 || '').toUpperCase();
  if (kek.length !== 88 || key.length !== 88) throw new Error('KEK et clé : 88 hex (GCM sous LMK)');
  return `${hdr || '0001'}A8${opts.kekScheme || 'U'}${kek}${keyTypeCode(keyTypeName)}${opts.keyScheme || 'U'}${key}`;
}

export function parseA9Export(raw) {
  const s = String(raw || '');
  if (s.slice(6, 8) !== '00') throw new Error(`A9 erreur ${s.slice(6, 8)}`);
  const d = s.slice(8);
  return {
    keyUnderZmk: d.slice(0, 33),
    kcv: d.slice(33, 39),
  };
}

export function buildA6Import(hdr, keyTypeName, kekGcm88, keyUnderKek, kcvExpected) {
  const type = keyTypeCode(keyTypeName);
  const kek = String(kekGcm88 || '').toUpperCase();
  const keyBlk = toThalesBlock('U', keyUnderKek);
  const kcv = String(kcvExpected || '').toUpperCase().replace(/[^0-9A-F]/g, '').slice(0, 6);
  if (kek.length !== 88) throw new Error('KEK coffre : 88 hex');
  if (kcv.length !== 6) throw new Error('KCV attendu : 6 hex');
  return `${hdr || '0001'}A6${type}${kek}${keyBlk}UU${kcv}`;
}

export function parseA7Import(raw) {
  const s = String(raw || '');
  if (s.slice(6, 8) !== '00') throw new Error(`A7 erreur ${s.slice(6, 8)}`);
  const d = s.slice(8);
  return {
    keyUnderLmk: d.length >= 33 ? d.slice(0, 33) : '',
    kcv: d.length >= 39 ? d.slice(33, 39) : d.slice(-6),
  };
}

export async function ensurePayshieldMode(hsmApi) {
  await hsmApi.hsmModeSet('PAYSHIELD_COMPAT');
}
