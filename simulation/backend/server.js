/**
 * Simulateur bancaire — Express + SSE.
 * Monétique : Core Banking, GAB, Switch, EMV, MAC → HSM réel (payhsm-httpd).
 */
import express from 'express';
import cors from 'cors';
import { CONFIG } from './config.js';
import { bus } from './bus.js';
import { db } from './db/memdb.js';
import { HsmA } from './hsm/hsmReal.js';
import { getHsmInfo } from './services/hsmInfo.js';
import { runIntraBank } from './orchestrator/scenarioIntra.js';
import { runInterBank } from './orchestrator/scenarioInter.js';
import { listVault, purgeLegacyTerminalKeyAliases } from './services/switchKeys.js';
import { provisionSwitchVault } from './services/switchProvision.js';
import {
  switchAutoImportA6,
  storeLmkMasterKey,
  deriveGabKeysFromTmk,
  listSwitchExchangeLogs,
} from './services/switchKeyExchange.js';
import {
  tryRestoreSwitchVault,
  clearSwitchVaultStorage,
  saveSwitchVault,
  persistSwitchVault,
} from './services/switchVaultPersist.js';
import {
  createOpenBaoRouter,
  isOpenBaoEnabled,
  openBaoHealth,
} from '../openbao/lib/index.js';
import { listCards, createCard, getCardEmvProfile } from './services/cardService.js';
import { processEmvPurchase } from './services/emvService.js';
import {
  buildIso8583Message, verifyIso8583Mac, signIso8583Mac,
} from './services/macService.js';

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/health', async (_req, res) => {
  let hsmA = { reachable: false, error: 'unknown' };
  try {
    const r = await HsmA.health();
    hsmA = { reachable: true, initialized: !!r.initialized, raw: r };

    if (r.initialized) {
      try {
        const bootId = r.raw?.bootId ?? null;
        if (bootId != null) db.lastHsmBootId = bootId;

        const lmk = await HsmA.lmkStatus();
        const currentRef = lmk.hmacRefPrefix || null;
        if (lmk.dataDir) db.lastHsmDataDir = lmk.dataDir;

        if (currentRef && db.lastLmkRef != null && db.lastLmkRef !== currentRef) {
          db.switchKeyVault.clear();
          db.switchInitialized = false;
          await clearSwitchVaultStorage();
          console.log(
            `[HSM] Nouvelle LMK (${db.lastLmkRef} → ${currentRef}) — SWITCH INIT puis provision-keys requis.`,
          );
        }
        if (currentRef) db.lastLmkRef = currentRef;

        if (db.switchKeyVault.size === 0 && currentRef) {
          await tryRestoreSwitchVault();
        }
        if (db.switchKeyVault.size > 0) {
          const purged = purgeLegacyTerminalKeyAliases();
          if (purged > 0 && currentRef) {
            await saveSwitchVault(currentRef, lmk.dataDir).catch(() => {});
          }
        }
      } catch (err) {
        console.log('[health] Lecture statut LMK:', err.message);
      }
    } else {
      db.lastHsmBootId = null;
    }
  } catch (e) {
    hsmA = { reachable: false, error: e.message };
  }
  let openbao = { enabled: isOpenBaoEnabled(), ok: false };
  if (isOpenBaoEnabled()) {
    openbao = { enabled: true, ...(await openBaoHealth()) };
  }

  res.json({
    backend: 'ok',
    apiVersion: 3,
    interScenario: 'bin-55xx-network-routing',
    port: CONFIG.PORT,
    hsmA_url: CONFIG.HSM_A_URL,
    hsmA,
    openbao,
    vaultKeys: db.switchKeyVault.size,
    cards: db.coreBankingCards.size,
    routes: [
      'POST /api/cards/create',
      'GET /api/cards/:pan/emv',
      'POST /api/switch/init',
      'POST /api/switch/reset',
      'POST /api/switch/provision-keys',
      'POST /api/emv/purchase',
      'GET /api/payment/modules',
      'POST /api/mac/sign',
      'POST /api/mac/verify',
    ],
  });
});

app.get('/api/info', async (_req, res) => {
  try {
    res.json(await getHsmInfo());
  } catch (e) {
    console.error('[api/info]', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/cards', async (_req, res) => {
  try {
    res.json({ cards: await listCards() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/cards/create', async (req, res) => {
  try {
    const r = await createCard(req.body || {});
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/cards/:pan/emv', async (req, res) => {
  try {
    res.json(await getCardEmvProfile(req.params.pan));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/vault', async (_req, res) => {
  if (listVault().length === 0) {
    try {
      await tryRestoreSwitchVault();
    } catch (e) {
      console.log('[vault] restore:', e.message);
    }
  }
  purgeLegacyTerminalKeyAliases();
  res.json({ SWITCH_KEY_VAULT: listVault(), persisted: listVault().length > 0 });
});

app.use('/api/openbao', createOpenBaoRouter({ listVault, express }));

app.post('/api/switch/init', async (_req, res) => {
  let restored = false;
  let keys = 0;
  try {
    restored = await tryRestoreSwitchVault();
    keys = listVault().length;
  } catch (e) {
    console.log('[switch/init] restore:', e.message);
  }
  db.switchInitialized = keys > 0 || db.switchInitialized;
  const purged = purgeLegacyTerminalKeyAliases();
  if (purged > 0) {
    try {
      await persistSwitchVault();
    } catch (e) {
      console.log('[switch/init] purge legacy persist:', e.message);
    }
  }
  res.json({
    ok: true,
    initialized: true,
    restored,
    vaultKeys: listVault().length,
    legacyAliasesPurged: purged,
    lmkRef: db.lastLmkRef,
    message: restored
      ? `Switch OK — ${keys} clé(s) restaurée(s) (même LMK)`
      : 'Switch initialisé — établir les clés (STORE / PULL manuels)',
  });
});

app.post('/api/switch/reset', async (_req, res) => {
  db.switchKeyVault.clear();
  db.switchInitialized = false;
  db.lastLmkRef = null;
  await clearSwitchVaultStorage();
  res.json({
    ok: true,
    message: 'Coffre Switch réinitialisé — après nouvelle LMK : switch/init puis provision-keys',
  });
});

app.post('/api/switch/provision-keys', async (_req, res) => {
  try {
    const r = await provisionSwitchVault();
    const ob = r.persisted?.openbao ? ' + OpenBao' : '';
    const disk = r.persisted?.disk ? 'disque' : '';
    res.json({
      ok: true,
      ...r,
      hint: r.hint || `Coffre : ${count} clé(s) — établissement manuel terminal HSM.`,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** ZMK/TMK après A4 manuel terminal HSM — KEY_BLOCK 88 hex */
app.post('/api/switch/store-key', async (req, res) => {
  try {
    const { keyId, keyType, cryptogram, kcv } = req.body || {};
    const r = await storeLmkMasterKey({
      keyId: keyId || keyType,
      keyType: (keyType || keyId || 'ZMK').toUpperCase(),
      cryptogram,
      kcv,
    });
    const persisted = r.persisted || await persistSwitchVault();
    res.json({ ok: true, ...r, persisted });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** A6 automatique (après A0+EXPORT manuels côté PayHSM) */
app.post('/api/switch/import-a6', async (req, res) => {
  try {
    const { keyId, keyType, keyUnderZmk, kcvExpected, transportKeyId } = req.body || {};
    const r = await switchAutoImportA6({
      keyId,
      keyType: (keyType || keyId || 'ZPK').toUpperCase(),
      keyUnderZmk,
      kcvExpected,
      transportKeyId,
    });
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/switch/derive-gab-keys', async (_req, res) => {
  try {
    const r = await deriveGabKeysFromTmk();
    const persisted = await persistSwitchVault();
    res.json({ ok: true, ...r, persisted });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/switch/exchange-logs', (_req, res) => {
  res.json({ logs: listSwitchExchangeLogs(80) });
});

app.post('/api/emv/purchase', async (req, res) => {
  try {
    const r = await processEmvPurchase(req.body || {});
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/mac/sign', async (req, res) => {
  try {
    const { pan, amountCents, terminal } = req.body || {};
    const message = buildIso8583Message({ pan, amountCents });
    const r = await signIso8583Mac({ message, terminal });
    res.json({ message, mac: r.mac, rc: r.rc });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/mac/verify', async (req, res) => {
  try {
    const { message, mac, terminal } = req.body || {};
    const r = await verifyIso8583Mac({ message, mac, terminal });
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/scenario/intra', async (req, res) => {
  const { pan, pin, amount, terminal } = req.body || {};
  if (!pan || !pin || !amount) {
    return res.status(400).json({ error: 'pan, pin et amount requis' });
  }
  const r = await runIntraBank({
    pan, pin, amount: Number(amount),
    terminal: terminal || CONFIG.GAB_TERMINAL,
  });
  res.json(r);
});

app.post('/api/scenario/inter', async (req, res) => {
  const { pan, pin, amount } = req.body || {};
  if (!pan || !pin || !amount) {
    return res.status(400).json({ error: 'pan, pin et amount requis' });
  }
  const r = await runInterBank({ pan, pin, amount: Number(amount) });
  res.json(r);
});

app.post('/api/issue-pvv', async (req, res) => {
  const { pan, pin, bank } = req.body || {};
  if (!pan || !pin) return res.status(400).json({ error: 'pan et pin requis' });
  try {
    const r = await createCard({
      pan, pin,
      customerName: `Carte ${bank || 'A'}`,
      balance: 5000,
    });
    res.json({ ok: true, pvv: r.pvv });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 2000\n\n');
  for (const e of bus.history) {
    res.write(`data: ${JSON.stringify(e)}\n\n`);
  }
  const onEvent = (e) => res.write(`data: ${JSON.stringify(e)}\n\n`);
  const onReset = () => res.write('event: reset\ndata: {}\n\n');
  bus.on('event', onEvent);
  bus.on('reset', onReset);
  const hb = setInterval(() => res.write(': keepalive\n\n'), 15000);
  req.on('close', () => {
    clearInterval(hb);
    bus.off('event', onEvent);
    bus.off('reset', onReset);
  });
});

app.post('/api/reset', (_req, res) => {
  bus.clear();
  for (const [, card] of db.coreBankingCards) {
    if (card.pan === '4111111111111111') card.balance = 12500;
    if (card.pan === '4222222222222222') card.balance = 8200;
    if (card.pan === '5500000000000004') card.balance = 6400;
    if (card.pan === '5500000000000012') card.balance = 3100;
    card.pvv = '';
  }
  res.json({ reset: true });
});

app.listen(CONFIG.PORT, async () => {
  console.log(`▶ Simulateur bancaire http://127.0.0.1:${CONFIG.PORT}`);
  console.log(`  HSM PayHSM (LMK réelle): ${CONFIG.HSM_A_URL}`);
  console.log('  HSM = LMK seule · Switch = SWITCH_KEY_VAULT (cryptogrammes)');
  console.log('  INTER : PAN 55xx → PayHSM GAP + TPK→ZPK · réseau routage BIN (sans ZPK-PEER)');
  if (isOpenBaoEnabled()) {
    const ob = await openBaoHealth();
    if (ob.ok) {
      console.log(`  ✓ OpenBao ${ob.addr} (KV ${ob.kvPath})`);
    } else {
      console.log(`  ⚠ OpenBao configuré mais injoignable: ${ob.error || 'sealed?'}`);
    }
  } else {
    console.log('  ○ OpenBao désactivé — coffre Switch = fichier data/switch-vault.json');
  }
  try {
    const h = await HsmA.health();
    if (h.initialized) {
      const restored = await tryRestoreSwitchVault();
      const n = listVault().length;
      if (n > 0) {
        console.log(
          `  ✓ Coffre Switch (${n} clés, LMK liée, ${restored ? 'restauré disque/OpenBao' : 'mémoire'})`,
        );
      } else {
        console.log(
          '  → Coffre Switch vide — après LMK : POST /api/switch/init puis provision-keys (ou hsmctl)',
        );
      }
    } else {
      console.log('  ⚠ HSM joignable mais non démarré — reconstruire LMK (console :8765 → SSS)');
    }
  } catch (e) {
    console.log(`  ⚠ HSM injoignable: ${e.message}`);
  }
});
