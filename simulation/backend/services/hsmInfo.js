/**
 * Métadonnées HSM réel (KCV, LMK) — lues depuis payhsm-httpd, jamais depuis config.js.
 */
import { HsmA } from '../hsm/hsmReal.js';
import { listVault } from './switchKeys.js';
import { CONFIG } from '../config.js';

export async function getHsmInfo() {
  const vault = listVault();
  const vaultById = Object.fromEntries(vault.map((k) => [k.key_id, k]));

  let status = null;
  let lmk = null;
  let health = null;

  try {
    health = await HsmA.health();
    if (health.initialized) {
      status = await HsmA.status();
      lmk = await HsmA.lmkStatus();
    }
  } catch (e) {
    return {
      source: 'payhsm-httpd',
      reachable: false,
      error: e.message,
      vault,
    };
  }

  const pick = (id) => vaultById[id]?.kcv || '—';

  return {
    source: 'payhsm-httpd',
    reachable: true,
    initialized: !!health.initialized,
    lmk: lmk
      ? {
          fragmented: !!lmk.fragmented,
          integrityOk: !!lmk.integrityOk,
          hmacRefPrefix: lmk.hmacRefPrefix,
          dataDir: lmk.dataDir,
        }
      : null,
    keyCount: status?.keyCount,
    keys: {
      TPK: pick(CONFIG.KEYS.TPK),
      TAK: pick(CONFIG.KEYS.TAK),
      ZPK: pick(CONFIG.KEYS.ZPK),
      PVK: pick(CONFIG.KEYS.PVK),
      IMK: pick(CONFIG.KEYS.IMK),
      TMK: pick(CONFIG.KEYS.TMK),
      ZMK: pick(CONFIG.KEYS.ZMK),
    },
    vault,
    config: {
      bankA: CONFIG.BANK_A,
      bankB: CONFIG.BANK_B,
      network: CONFIG.NETWORK,
      keyIds: CONFIG.KEYS,
    },
  };
}
