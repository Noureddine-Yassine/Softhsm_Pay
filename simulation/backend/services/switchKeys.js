/**
 * Coffre Switch — lecture des cryptogrammes (jamais de clé en clair).
 * LMK : GCM 88 hex · TPK/TAK sous TMK : ECB 32 hex · ZPK sous ZMK : ECB 32 hex.
 */
import { db } from '../db/memdb.js';
import { CONFIG } from '../config.js';

/** Ancienne démo inter — ne plus charger ni afficher (KCV 8C700F = clé Banque B statique). */
const OBSOLETE_KEY_IDS = new Set(['ZPK-PEER']);

export function purgeObsoleteVaultKeys() {
  let n = 0;
  for (const id of OBSOLETE_KEY_IDS) {
    if (db.switchKeyVault.delete(id)) n += 1;
  }
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

export function switchPayloadTerminal(terminal = CONFIG.GAB_TERMINAL) {
  const tmk = requireVaultKey(CONFIG.KEYS.TMK);
  const tpk = requireVaultKey(`TPK-${terminal}`);
  const tak = requireVaultKey(`TAK-${terminal}`);
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
