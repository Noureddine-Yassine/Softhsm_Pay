/**
 * SWITCH_KEY_VAULT :
 *   LMK → TMK, ZMK, IMK, PVK (aléatoire, via HSM)
 *   ZMK → ZPK acquéreur (aléatoire) — pas de ZPK émetteur (réseau / Banque B hors coffre)
 *   TMK → TPK/TAK (ATM001)
 */
import crypto from 'crypto';
import { db } from '../db/memdb.js';
import { CONFIG } from '../config.js';
import { HsmA, requireHsmReady } from '../hsm/hsmReal.js';
import { bus } from '../bus.js';
import { listVault, purgeObsoleteVaultKeys } from './switchKeys.js';
import { saveSwitchVault } from './switchVaultPersist.js';
import { isOpenBaoEnabled } from '../../openbao/lib/index.js';

const LMK_MASTERS = [
  { key_id: 'TMK', key_type: 'TMK' },
  { key_id: 'ZMK', key_type: 'ZMK' },
  { key_id: 'IMK', key_type: 'IMK' },
  { key_id: 'PVK', key_type: 'PVK' },
];

function randomKeyHex() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

async function wrapUnderLmk(entry, keyHex) {
  const r = await HsmA.wrapKey(keyHex);
  if (r.rc !== 0 || !r.cryptogram) {
    throw new Error(`Chiffrement LMK échoué pour ${entry.key_id}`);
  }
  db.switchKeyVault.set(entry.key_id, {
    key_id: entry.key_id,
    key_type: entry.key_type,
    cryptogram: r.cryptogram,
    kcv: '',
    wrapped_by: 'LMK',
    parent_key_id: null,
    terminal: '',
  });
}

async function wrapZpkUnderZmk(zmkEntry, keyId, keyType, keyHex) {
  const r = await HsmA.wrapZpk(zmkEntry.cryptogram, keyHex);
  if (r.rc !== 0 || !r.zpkCryptogram) {
    throw new Error(`ZPK sous ZMK échoué pour ${keyId}`);
  }
  db.switchKeyVault.set(keyId, {
    key_id: keyId,
    key_type: keyType,
    cryptogram: r.zpkCryptogram,
    kcv: r.kcv || '',
    wrapped_by: zmkEntry.key_id,
    parent_key_id: zmkEntry.key_id,
    terminal: '',
  });
}

async function deriveGabKeys(tmkEntry) {
  const term = CONFIG.GAB_TERMINAL;
  const dr = await HsmA.deriveTerminal(tmkEntry.cryptogram, term);
  if (dr.rc !== 0) {
    throw new Error(`Dérivation TPK/TAK ${term} échouée`);
  }
  const parent = tmkEntry.key_id;
  db.switchKeyVault.set(`TPK-${term}`, {
    key_id: `TPK-${term}`,
    key_type: 'TPK',
    cryptogram: dr.tpkCryptogram,
    kcv: dr.tpkKcv || '',
    wrapped_by: parent,
    parent_key_id: parent,
    terminal: term,
  });
  db.switchKeyVault.set(`TAK-${term}`, {
    key_id: `TAK-${term}`,
    key_type: 'TAK',
    cryptogram: dr.takCryptogram,
    kcv: dr.takKcv || '',
    wrapped_by: parent,
    parent_key_id: parent,
    terminal: term,
  });
}

export async function provisionSwitchVault() {
  await requireHsmReady();

  let ref = null;
  let dataDir = null;
  try {
    const lmk = await HsmA.lmkStatus();
    ref = lmk.hmacRefPrefix || null;
    dataDir = lmk.dataDir || null;
  } catch (e) {
    console.log('[switchProvision] Impossible de lire le statut LMK:', e.message);
  }

  db.switchKeyVault.clear();
  purgeObsoleteVaultKeys();

  for (const m of LMK_MASTERS) {
    await wrapUnderLmk(m, randomKeyHex());
  }

  const zmk = db.switchKeyVault.get(CONFIG.KEYS.ZMK);
  await wrapZpkUnderZmk(zmk, CONFIG.KEYS.ZPK, 'ZPK', randomKeyHex());

  const tmk = db.switchKeyVault.get(CONFIG.KEYS.TMK);
  await deriveGabKeys(tmk);

  const count = db.switchKeyVault.size;
  db.lastLmkRef = ref;
  if (dataDir) db.lastHsmDataDir = dataDir;
  const persisted = await saveSwitchVault(ref, dataDir);

  bus.publish({
    from: 'SWITCH',
    to: isOpenBaoEnabled() ? 'OpenBao' : 'DISQUE',
    kind: 'info',
    label: `Coffre Switch — ${count} clés (LMK, ZMK, ZPK, TPK/TAK ATM001)`,
    payload: { count, lmkRef: ref, persisted },
  });

  await ensureDemoCardsEnrolled();

  return {
    count,
    keys: listVault(),
    persisted,
    openBao: isOpenBaoEnabled(),
  };
}

/** PVV HSM pour cartes démo — requis avant EMV (IMK dérive ICC Key par PAN). */
async function ensureDemoCardsEnrolled() {
  const demos = [
    { pan: '4111111111111111', pin: '1234' },
    { pan: '4222222222222222', pin: '5678' },
    { pan: '5500000000000004', pin: '1234' },
    { pan: '5500000000000012', pin: '5678' },
  ];
  for (const { pan, pin } of demos) {
    if (!db.coreBankingCards.has(pan)) continue;
    try {
      const lk = await HsmA.coreBankingLookup(pan);
      if (lk.rc === 0 && lk.pvv) continue;
      await HsmA.coreBankingIssue(pan, pin);
    } catch (e) {
      console.log(`[switchProvision] PVV démo ${pan.slice(-4)}: ${e.message}`);
    }
  }
}
