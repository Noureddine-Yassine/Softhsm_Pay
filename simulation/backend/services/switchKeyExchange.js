/**
 * Échange manuel HSM (console) → Switch exécute A6 automatiquement + logs.
 * ZMK/TMK : cérémonie NE+A4 dans le terminal HSM, puis SWITCH STORE (pas d'A6).
 */
import { db } from '../db/memdb.js';
import { CONFIG } from '../config.js';
import { HsmA } from '../hsm/hsmReal.js';
import { requireVaultKey, purgeLegacyTerminalKeyAliases } from './switchKeys.js';
import { persistSwitchVault } from './switchVaultPersist.js';
import { bus } from '../bus.js';
import {
  ensurePayshieldMode,
  buildA6Import,
  parseA7Import,
  toThalesBlock,
  transportKeyId as kekIdForKeyType,
} from './payshieldWire.js';

const MAX_LOGS = 200;

export function appendSwitchExchangeLog(line) {
  if (!db.switchExchangeLogs) db.switchExchangeLogs = [];
  const entry = { ts: Date.now(), message: line };
  db.switchExchangeLogs.push(entry);
  if (db.switchExchangeLogs.length > MAX_LOGS) {
    db.switchExchangeLogs.splice(0, db.switchExchangeLogs.length - MAX_LOGS);
  }
  console.log(`[Switch A6] ${line}`);
  bus.publish({
    from: 'SWITCH',
    to: 'PayHSM',
    kind: 'info',
    label: line,
    payload: { op: 'A6' },
  });
  return entry;
}

export function listSwitchExchangeLogs(limit = 50) {
  const logs = db.switchExchangeLogs || [];
  return logs.slice(-limit).reverse();
}

/**
 * Stocker ZMK/TMK après A4 manuel dans le terminal HSM (KEY_BLOCK 88 hex).
 */
export async function storeLmkMasterKey({ keyId, keyType, cryptogram, kcv }) {
  if (!cryptogram || String(cryptogram).length !== 88) {
    throw new Error('cryptogram 88 hex requis (sortie A4 / KEY_BLOCK)');
  }
  db.switchKeyVault.set(keyId, {
    key_id: keyId,
    key_type: keyType,
    cryptogram: String(cryptogram).toUpperCase(),
    kcv: (kcv || '').toUpperCase(),
    wrapped_by: 'LMK',
    parent_key_id: null,
    terminal: '',
    origin: 'NE+A4-manual',
  });
  db.switchInitialized = true;
  const msg = `STORE ${keyType} ${keyId} KCV=${kcv || '—'} (cérémonie, coffre Switch)`;
  appendSwitchExchangeLog(msg);
  const persisted = await persistSwitchVault();
  return { key_id: keyId, kcv, origin: 'NE+A4-manual', persisted };
}

/**
 * ZMK/TMK pour A6 : même cryptogramme que A8/L (coffre PayHSM), pas une copie Switch désynchronisée.
 */
async function transportCryptogramForA6(transportKeyId) {
  const tid = (transportKeyId || 'ZMK').toUpperCase();
  const ttype = tid === 'TMK' ? 'TMK' : 'ZMK';

  try {
    const tg = await HsmA.transportGcm(ttype);
    if (tg.rc === 0 && tg.cryptogram?.length === 88) {
      const hsm88 = String(tg.cryptogram).toUpperCase();
      appendSwitchExchangeLog(`A6 — ${ttype} ext_keys (identique A8/L) · ${tg.keyId || tid}`);
      /* Resynchroniser coffre Switch pour les prochains appels REST */
      try {
        const sw = requireVaultKey(tid);
        if (sw.cryptogram.toUpperCase() !== hsm88) {
          db.switchKeyVault.set(tid, {
            ...sw,
            cryptogram: hsm88,
            key_id: sw.key_id || tid,
            key_type: ttype,
            origin: 'sync-ext_keys',
          });
          appendSwitchExchangeLog(`A6 — coffre Switch ${ttype} resynchronisé`);
        }
      } catch {
        await storeLmkMasterKey({
          keyId: tid,
          keyType: ttype,
          cryptogram: hsm88,
          kcv: '',
        });
      }
      return hsm88;
    }
  } catch (e) {
    appendSwitchExchangeLog(`A6 — transport-gcm PayHSM (${e.message})`);
  }

  const switchEntry = requireVaultKey(tid);
  if (switchEntry?.cryptogram?.length === 88) {
    appendSwitchExchangeLog(`A6 — ${ttype} depuis coffre Switch (fallback)`);
    return switchEntry.cryptogram.toUpperCase();
  }
  throw new Error(`${ttype} introuvable — A4 NE+A4 puis SWITCH STORE ${ttype}`);
}

/**
 * Import automatique A6 côté Switch (PayHSM → Switch après A0+A8 manuels sur HSM).
 */
export async function switchAutoImportA6({
  keyId,
  keyType,
  keyUnderZmk,
  kcvExpected,
  transportKeyId: transportKeyIdParam,
}) {
  const kt = (keyType || keyId || 'ZPK').toUpperCase();
  const transportKeyId = transportKeyIdParam || kekIdForKeyType(kt);
  const kek88 = await transportCryptogramForA6(transportKeyId);
  const enc = toThalesBlock('U', keyUnderZmk);

  appendSwitchExchangeLog(
    `A6 début — import ${kt} (${keyId}) wire Thales sous ${transportKeyId}`,
  );

  await ensurePayshieldMode(HsmA);
  const wire = buildA6Import('0001', kt, kek88, enc, kcvExpected);
  appendSwitchExchangeLog(`A6 wire (${wire.length} car.)`);

  const a6 = await HsmA.hsmCmd(wire);

  if (a6.rc !== 0) {
    appendSwitchExchangeLog(`A6 ÉCHEC ${kt} ${keyId} — ${a6.message || a6.errorCode || 'erreur'}`);
    const code = a6.errorCode || (a6.rawResponse || '').slice(6, 8);
    const msg = a6.message || `A6 import ${kt} échoué (${code || '?'})`;
    if (code === '07') {
      const kek = (transportKeyId || 'ZMK').toUpperCase();
      throw new Error(
        `${msg} — KCV: A8/L et A6 doivent utiliser la même ${kek} (ext_keys). ` +
          (kek === 'TMK'
            ? 'TPK/TAK : 0001A8L002U$tpk_88 (pas L001).'
            : 'ZPK : 0001A8L001U$zpk_88.'),
      );
    }
    throw new Error(msg);
  }

  const parsed = parseA7Import(a6.rawResponse);
  const recvKcv = (a6.kcv || parsed.kcv || '').toUpperCase();
  const expectKcv = (kcvExpected || '').toUpperCase();
  if (expectKcv && recvKcv && recvKcv !== expectKcv) {
    appendSwitchExchangeLog(`A6 KCV ÉCHEC ${kt} — attendu ${expectKcv} reçu ${recvKcv}`);
    throw new Error(`KCV verification failed (15) — attendu ${expectKcv}`);
  }

  const kcv = (a6.kcv || parsed.kcv || kcvExpected || '').toUpperCase();
  const stored = a6.cryptogram || parsed.keyUnderLmk;
  db.switchKeyVault.set(keyId, {
    key_id: keyId,
    key_type: keyType,
    cryptogram: stored,
    kcv,
    wrapped_by: 'LMK',
    parent_key_id: transportKeyId,
    terminal: '',
    origin: 'A0+A8+A6-wire-Thales',
  });

  db.switchInitialized = true;

  appendSwitchExchangeLog(
    `A6 OK — ${keyType} ${keyId} · KCV=${kcv} · bloc LMK ${String(stored).length} hex`,
  );

  const persisted = await persistSwitchVault();
  if (!persisted.disk) {
    appendSwitchExchangeLog('A6 — coffre en mémoire seulement (persist échouée — relancer SWITCH PROVISION)');
  }

  return {
    key_id: keyId,
    key_type: keyType,
    kcv,
    cryptogram: db.switchKeyVault.get(keyId)?.cryptogram,
    persisted,
  };
}

/** TPK/TAK : dérivation après TMK manuellement stocké */
export async function deriveGabKeysFromTmk() {
  const tmk = requireVaultKey(CONFIG.KEYS.TMK);
  const term = CONFIG.GAB_TERMINAL;
  const dr = await HsmA.deriveTerminal(tmk.cryptogram, term);
  if (dr.rc !== 0) throw new Error(`Dérivation TPK/TAK ${term} échouée`);
  const parent = tmk.key_id;
  db.switchKeyVault.set(CONFIG.KEYS.TPK, {
    key_id: CONFIG.KEYS.TPK,
    key_type: 'TPK',
    cryptogram: dr.tpkCryptogram,
    kcv: dr.tpkKcv || '',
    wrapped_by: parent,
    parent_key_id: parent,
    terminal: term,
    origin: 'TMK-derive',
  });
  db.switchKeyVault.set(CONFIG.KEYS.TAK, {
    key_id: CONFIG.KEYS.TAK,
    key_type: 'TAK',
    cryptogram: dr.takCryptogram,
    kcv: dr.takKcv || '',
    wrapped_by: parent,
    parent_key_id: parent,
    terminal: term,
    origin: 'TMK-derive',
  });
  purgeLegacyTerminalKeyAliases();
  await persistSwitchVault();
  appendSwitchExchangeLog(`Dérivation TPK/TAK ${term} OK`);
  return { terminal: term, tpkKcv: dr.tpkKcv, takKcv: dr.takKcv };
}
