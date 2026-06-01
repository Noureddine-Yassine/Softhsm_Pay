/**
 * Routes REST OpenBao — montées sur le backend simulateur (/api/openbao/*).
 * @param {{ listVault: () => object[], express: typeof import('express') }} deps
 */
import { OPENBAO } from './config.js';
import {
  isOpenBaoEnabled,
  openBaoHealth,
  readSwitchVaultRawFromOpenBao,
} from './client.js';
import { summarizeVaultKeys } from './vaultSummary.js';

const HINT = 'Définir OPENBAO_ADDR et OPENBAO_TOKEN (voir simulation/openbao/start.sh)';

export function createOpenBaoRouter(deps) {
  const { listVault, express } = deps;
  const router = express.Router();

  router.get('/status', async (_req, res) => {
    if (!isOpenBaoEnabled()) {
      return res.json({ enabled: false, hint: HINT });
    }
    try {
      const h = await openBaoHealth();
      res.json({
        enabled: true,
        addr: OPENBAO.addr,
        kvPath: OPENBAO.kvPath,
        kvMount: OPENBAO.kvMount,
        ...h,
      });
    } catch (e) {
      res.status(502).json({ enabled: true, ok: false, error: e.message });
    }
  });

  router.get('/coffre', async (_req, res) => {
    if (!isOpenBaoEnabled()) {
      return res.json({ enabled: false, hint: HINT });
    }
    try {
      const [health, raw, memoryKeys] = await Promise.all([
        openBaoHealth(),
        readSwitchVaultRawFromOpenBao(),
        Promise.resolve(listVault()),
      ]);
      const payload = raw.found ? raw.payload : null;
      res.json({
        enabled: true,
        addr: OPENBAO.addr,
        kvPath: OPENBAO.kvPath,
        kvMount: OPENBAO.kvMount,
        health,
        openbao: {
          found: raw.found,
          version: raw.version,
          savedAt: payload?.savedAt || null,
          lmkRef: payload?.lmkRef || null,
          keyCount: payload?.keys?.length ?? 0,
          keys: summarizeVaultKeys(payload?.keys),
        },
        memory: {
          keyCount: memoryKeys.length,
          keys: summarizeVaultKeys(memoryKeys),
        },
      });
    } catch (e) {
      res.status(502).json({ enabled: true, ok: false, error: e.message });
    }
  });

  return router;
}
