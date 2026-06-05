/**
 * Persistance SWITCH_KEY_VAULT — disque local + OpenBao (KV v2).
 * Cryptogrammes liés à la LMK PayHSM (hmacRefPrefix).
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { db } from '../db/memdb.js';
import { HsmA } from '../hsm/hsmReal.js';
import { listVault, purgeObsoleteVaultKeys, purgeLegacyTerminalKeyAliases } from './switchKeys.js';
import { CONFIG } from '../config.js';
import {
  isOpenBaoEnabled,
  saveSwitchVaultToOpenBao,
  loadSwitchVaultFromOpenBao,
  clearSwitchVaultInOpenBao,
} from '../../openbao/lib/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '..', 'data');
const VAULT_FILE = path.join(DATA_DIR, 'switch-vault.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function buildPayload(lmkRef, dataDir) {
  return {
    lmkRef,
    dataDir: dataDir || null,
    savedAt: new Date().toISOString(),
    keys: listVault(),
  };
}

function applyPayloadToMemory(stored) {
  db.switchKeyVault.clear();
  for (const k of stored.keys) {
    if (k.key_id === 'ZPK-PEER') continue;
    db.switchKeyVault.set(k.key_id, k);
  }
  db.lastLmkRef = stored.lmkRef;
  if (stored.dataDir) db.lastHsmDataDir = stored.dataDir;
  purgeObsoleteVaultKeys();
}

/** Récupère l'empreinte LMK PayHSM (requise pour sauvegarder le coffre). */
export async function ensureLmkRef() {
  if (db.lastLmkRef) return db.lastLmkRef;
  try {
    const health = await HsmA.health();
    if (!health?.initialized) return null;
    const lmk = await HsmA.lmkStatus();
    db.lastLmkRef = lmk?.hmacRefPrefix || null;
    if (lmk?.dataDir) db.lastHsmDataDir = lmk.dataDir;
  } catch (e) {
    console.log('[Switch] ensureLmkRef:', e.message);
    return null;
  }
  return db.lastLmkRef;
}

/** Sauvegarde disque + OpenBao si le coffre contient des clés. */
export async function persistSwitchVault() {
  if (listVault().length === 0) {
    return { disk: false, openbao: false, reason: 'empty' };
  }
  const ref = await ensureLmkRef();
  if (!ref) {
    console.log('[Switch] Coffre non persisté — LMK indisponible (startup HSM ?)');
    return { disk: false, openbao: false, reason: 'no_lmk_ref' };
  }
  db.switchInitialized = true;
  return saveSwitchVault(ref, db.lastHsmDataDir);
}

/**
 * @param {string} lmkRef
 * @param {string} [dataDir]
 * @returns {Promise<{ disk: boolean, openbao: boolean }>}
 */
export async function saveSwitchVault(lmkRef, dataDir = '') {
  const ref = lmkRef || db.lastLmkRef;
  if (!ref) return { disk: false, openbao: false };
  purgeObsoleteVaultKeys();
  const payload = buildPayload(ref, dataDir);
  const out = { disk: false, openbao: false };

  ensureDataDir();
  fs.writeFileSync(VAULT_FILE, JSON.stringify(payload, null, 2), { mode: 0o600 });
  out.disk = true;
  console.log(`[Switch] Coffre → disque (${payload.keys.length} clés) ${VAULT_FILE}`);

  if (isOpenBaoEnabled()) {
    try {
      const ob = await saveSwitchVaultToOpenBao(payload);
      out.openbao = ob.saved;
      console.log(
        `[Switch] Coffre → OpenBao (${payload.keys.length} clés) path=${CONFIG.OPENBAO.kvPath}` +
          (ob.version != null ? ` v${ob.version}` : ''),
      );
    } catch (e) {
      console.log('[Switch] OpenBao écriture échouée (disque OK):', e.message);
    }
  }

  return out;
}

/** @deprecated alias */
export function saveSwitchVaultToDisk(lmkRef, dataDir) {
  return saveSwitchVault(lmkRef, dataDir);
}

function loadSwitchVaultFromDisk(expectedLmkRef) {
  if (!fs.existsSync(VAULT_FILE)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
    if (!Array.isArray(raw.keys) || raw.keys.length === 0) return null;
    if (raw.lmkRef !== expectedLmkRef) {
      console.log(
        `[Switch] Coffre disque ignoré (LMK fichier=${raw.lmkRef} ≠ LMK courante=${expectedLmkRef})`,
      );
      return null;
    }
    return raw;
  } catch (e) {
    console.log('[Switch] Lecture disque:', e.message);
    return null;
  }
}

export async function clearSwitchVaultStorage() {
  db.switchInitialized = false;
  if (fs.existsSync(VAULT_FILE)) {
    fs.unlinkSync(VAULT_FILE);
    console.log('[Switch] Fichier coffre supprimé (nouvelle LMK)');
  }
  await clearSwitchVaultInOpenBao();
}

/** @deprecated */
export function clearSwitchVaultFile() {
  clearSwitchVaultStorage().catch((e) => console.log('[Switch] clear:', e.message));
}

/**
 * @returns {Promise<boolean>}
 */
export async function tryRestoreSwitchVault() {
  try {
    const health = await HsmA.health();
    if (!health?.initialized) return false;

    const lmk = await HsmA.lmkStatus();
    const ref = lmk?.hmacRefPrefix;
    if (!ref) return false;

    let stored = null;
    let source = '';

    if (isOpenBaoEnabled()) {
      try {
        stored = await loadSwitchVaultFromOpenBao(ref);
        if (stored) source = 'OpenBao';
      } catch (e) {
        console.log('[Switch] OpenBao lecture:', e.message, '— repli disque');
      }
    }

    if (!stored) {
      stored = loadSwitchVaultFromDisk(ref);
      if (stored) source = 'disque';
    }

    if (!stored) return false;

    applyPayloadToMemory(stored);
    purgeLegacyTerminalKeyAliases();
    db.switchInitialized = listVault().length > 0;
    await saveSwitchVault(ref, stored.dataDir);

    console.log(
      `[Switch] Coffre restauré depuis ${source} (${listVault().length} clés, LMK ${ref})`,
    );
    return true;
  } catch (e) {
    console.log('[Switch] Restauration coffre:', e.message);
    return false;
  }
}
