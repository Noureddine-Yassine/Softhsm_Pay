/**
 * Coffre Switch — clés établies MANUELLEMENT dans le terminal HSM (:8765).
 * Le Switch n'exécute que A6 (import auto) + logs ; pas de génération automatique.
 */
import { db } from '../db/memdb.js';
import { HsmA, requireHsmReady } from '../hsm/hsmReal.js';
import { listVault, purgeObsoleteVaultKeys } from './switchKeys.js';
import { persistSwitchVault } from './switchVaultPersist.js';
import { isOpenBaoEnabled } from '../../openbao/lib/index.js';

export async function provisionSwitchVault() {
  await requireHsmReady();

  purgeObsoleteVaultKeys();
  const countBefore = listVault().length;
  if (!db.switchInitialized && countBefore === 0) {
    throw new Error(
      'Coffre vide — établir les clés dans le terminal HSM (SWITCH STORE / PULL) puis sauvegarder',
    );
  }

  const persisted = await persistSwitchVault();
  const count = db.switchKeyVault.size;

  return {
    count,
    keys: listVault(),
    persisted,
    openBao: isOpenBaoEnabled(),
    manual: true,
    hint:
      'Mode manuel : ZMK/TMK (NE+A4) dans terminal HSM → SWITCH STORE · ZPK/IMK/TAK (A0+EXPORT) → SWITCH PULL · PVK idem',
  };
}
