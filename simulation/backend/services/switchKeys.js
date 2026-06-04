/**
 * Coffre Switch — lecture des cryptogrammes (jamais de clé en clair).
 * LMK : GCM 88 hex · TPK/TAK/ZPK : GCM 88 sous LMK (PULL) ou ECB 32 sous TMK/ZMK (dérivation / export).
 */
import { db } from '../db/memdb.js';
import { CONFIG } from '../config.js';

/** Ancienne démo inter — ne plus charger ni afficher (KCV 8C700F = clé Banque B statique). */
const OBSOLETE_KEY_IDS = new Set(['ZPK-PEER']);

/** Alias terminal obsolètes (TPK-ATM001…) — clés métier = TPK / TAK directement. */
const LEGACY_TERMINAL_KEY_RE = /^T(PK|TAK)-/;

export function purgeLegacyTerminalKeyAliases() {
  let n = 0;
  for (const id of [...db.switchKeyVault.keys()]) {
    if (LEGACY_TERMINAL_KEY_RE.test(id) && db.switchKeyVault.delete(id)) n += 1;
  }
  return n;
}

export function purgeObsoleteVaultKeys() {
  let n = 0;
  for (const id of OBSOLETE_KEY_IDS) {
    if (db.switchKeyVault.delete(id)) n += 1;
  }
  n += purgeLegacyTerminalKeyAliases();
  return n;
}

export function listVault() {
  return [...db.switchKeyVault.values()].filter((k) => !OBSOLETE_KEY_IDS.has(k.key_id));
}

export function getVaultKey(keyId) {
  return db.switchKeyVault.get(keyId);
}

export function requireVaultKey(keyId) {
  const k = db.switchKeyVault.get(keyId);
  if (!k) {
    throw new Error(
      `Clé Switch « ${keyId} » absente — HSM : LMK seule sur :8765, puis « Initialiser coffre Switch ».`,
    );
  }
  return k;
}

/** GAP / verify / MAC — TPK et TAK du coffre (ids CONFIG.KEYS.TPK / TAK). */
export function switchPayloadTerminal(_terminal = CONFIG.GAB_TERMINAL) {
  const tmk = requireVaultKey(CONFIG.KEYS.TMK);
  const tpk = requireVaultKey(CONFIG.KEYS.TPK);
  const tak = requireVaultKey(CONFIG.KEYS.TAK);
  return {
    tmkCryptogram: tmk.cryptogram,
    tpkCryptogram: tpk.cryptogram,
    takCryptogram: tak.cryptogram,
  };
}

export function switchPayloadZpk(zpkId) {
  const zmk = requireVaultKey(CONFIG.KEYS.ZMK);
  const zpk = requireVaultKey(zpkId);
  const pvk = requireVaultKey(CONFIG.KEYS.PVK);
  return {
    zmkCryptogram: zmk.cryptogram,
    zpkCryptogram: zpk.cryptogram,
    pvkCryptogram: pvk.cryptogram,
  };
}

export function switchPayloadImk() {
  const imk = requireVaultKey(CONFIG.KEYS.IMK);
  return { imkCryptogram: imk.cryptogram };
}

export function switchPayloadZpkPair(fromId, toId) {
  const zmk = requireVaultKey(CONFIG.KEYS.ZMK);
  const from = requireVaultKey(fromId);
  const to = requireVaultKey(toId);
  return {
    zmkCryptogram: zmk.cryptogram,
    fromZpkCryptogram: from.cryptogram,
    toZpkCryptogram: to.cryptogram,
  };
}
