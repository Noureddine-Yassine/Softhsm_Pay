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
import { listVault } from './services/switchKeys.js';
import { provisionSwitchVault } from './services/switchProvision.js';
import {
  tryRestoreSwitchVault,
  clearSwitchVaultStorage,
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
          await clearSwitchVaultStorage();
          console.log(
            `[HSM] Nouvelle LMK (${db.lastLmkRef} → ${currentRef}) — réinitialisez le coffre Switch.`,
          );
        }
        if (currentRef) db.lastLmkRef = currentRef;

        if (db.switchKeyVault.size === 0 && currentRef) {
          await tryRestoreSwitchVault();
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

app.get('/api/vault', (_req, res) => {
  res.json({ SWITCH_KEY_VAULT: listVault() });
});

app.use('/api/openbao', createOpenBaoRouter({ listVault, express }));

app.post('/api/switch/provision-keys', async (_req, res) => {
  try {
    const r = await provisionSwitchVault();
    const ob = r.persisted?.openbao ? ' + OpenBao' : '';
    const disk = r.persisted?.disk ? 'disque' : '';
    res.json({
      ok: true,
      ...r,
      hint: `Coffre prêt (${disk}${ob}) — cartes Core Banking si besoin.`,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
      await tryRestoreSwitchVault();
      const n = listVault().length;
      if (n > 0) {
        console.log(`  ✓ Coffre Switch prêt (${n} clés, lié LMK PayHSM)`);
      } else {
        console.log('  → Initialiser coffre Switch (UI) — sauvegardé pour cette LMK');
      }
    } else {
      console.log('  ⚠ HSM joignable mais non démarré — Provision LMK + Démarrer sur :8765');
    }
  } catch (e) {
    console.log(`  ⚠ HSM injoignable: ${e.message}`);
  }
});
