/* PayHSM — console HSM simulation (backend C via payhsm-httpd) */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** LCD matériel — texte monospace + curseur clignotant */
function lcd(lines) {
  const el = $('#hsm-lcd');
  if (!el) return;
  const txt = typeof lines === 'string' ? lines : (Array.isArray(lines) ? lines.join('\n') : String(lines));
  el.replaceChildren(document.createTextNode(txt));
  const c = document.createElement('span');
  c.className = 'lcd-cursor';
  el.appendChild(c);
}

function lcdPassphraseDots(len) {
  const n = Math.min(Math.max(Number(len) || 0, 0), 32);
  return '●'.repeat(n) || '—';
}

function setHwLeds({ pwr = true, net = false, busy = false, fault = false, key = false } = {}) {
  const setLed = (name, mode) => {
    const el = $(`.led-strip .led[data-led="${name}"]`);
    if (!el) return;
    el.classList.remove('off', 'ok', 'busy', 'alert');
    if (mode === 'off') el.classList.add('off');
    else if (mode === 'ok') el.classList.add('ok');
    else if (mode === 'busy') el.classList.add('busy');
    else if (mode === 'alert') el.classList.add('alert');
  };
  setLed('pwr', pwr ? 'ok' : 'off');
  setLed('net', net ? 'ok' : 'off');
  setLed('busy', busy ? 'busy' : 'off');
  setLed('flt', fault ? 'alert' : 'off');
  setLed('key', key ? 'ok' : 'off');
}

const state = {
  pinBlock: '',
  pinBlockZpk: '',
  lmkBlobs: { tmk: '', zmk: '' },   /* stockage temporaire blobs étape 1 */
  demoStepIndex: 0,
  demoRunningAuto: false,
  config: {
    api: localStorage.getItem('payhsm_api') || 'http://127.0.0.1:8765',
    password: '',
    dataDir: localStorage.getItem('payhsm_data') || '/home/oussama/Desktop/payhsm-data',
    terminals: localStorage.getItem('payhsm_terms') || 'ATM001,ATM002',
    terminal: localStorage.getItem('payhsm_term') || 'ATM001',
    pan: localStorage.getItem('payhsm_pan') || '4111111111111111',
  },
};

/** Définition guide démo projet (réel crypto C) */
const DEMO_DEF = [
  {
    title: 'Lier ce poste au payhsm-httpd (GET /health)',
    lcdIntro: ['NETWORK ............ SYNC', '> PROBE API', 'WAIT ...'],
    run: async () => {
      lcd(['NETWORK ............. ONLINE', '> GET /api/health', 'WAIT .... OK']);
      setHwLeds({ pwr: true, net: true, busy: true });
      saveConfig();
      const h = await PayHsmApi.health();
      setHwLeds({ pwr: true, net: true, busy: false, fault: false, key: !!h.initialized });
      lcd([
        `API INITIALIZED .... ${h.initialized ? 'TRUE ' : 'FALSE'}`,
        'FEATURE SET ......... OK',
        h.initialized ? '> HSM ALREADY UP' : '> NEED STARTUP SEQ',
      ]);
      demoLog(`Health: initialized=${h.initialized}`, 'ok');
      await refreshStatus();
    },
  },
  {
    title: '(Option première install) Provision LMK + coffre terminaux',
    lcdIntro: ['SECURE STORE ....... FORMAT', '> PROVISION SEQ', '(skip if existe)'],
    run: async () => {
      log('Provision (tour démo — ignorez si données déjà là)', 'warn');
      saveConfig();
      const st = await PayHsmApi.status().catch(() => ({ keyCount: -1 }));
      if (typeof st.keyCount === 'number' && st.keyCount > 0) {
        demoLog('Coffre non vide → étape provision ignorée.', 'warn');
        lcd(['SKIP PROVISION ...... VAULT NZ', '> KEYS ALREADY LOAD', '> GOTO START SEQUENCE']);
        return;
      }
      demoLog('Provision LMK/vault → voir résultat API', '');
      lcd(['SECURITY EVENT ..... PROVISION', 'FRAGMENTS P1..P3 ..... WRITE', '> DO NOT REMOVE POWER']);
      setHwLeds({ busy: true, net: true, pwr: true });
      const r = await PayHsmApi.provision(state.config.password, state.config.dataDir, state.config.terminals);
      lcd([r.rc === 0 ? 'PROVISION .......... DONE' : 'PROVISION .......... WARN', `${r.message || ''}`.slice(0, 40), '> NEXT: START']);
      demoLog(`Provision rc=${r.rc} ${r.message}`, r.rc === 0 ? 'ok' : 'warn');
      setHwLeds({ busy: false, net: true, pwr: true, fault: r.rc !== 0 });
      await sleep(280);
      setHwLeds({ busy: false, net: true, pwr: true, fault: false });
      await refreshStatus();
    },
  },
  {
    title: 'Déverrouiller LMK avec la passphrase utilisateur',
    lcdIntro: ['SECURE GATE ........ ARMED', '> PASSPHRASE REQUIRED', '[setup] puis OK'],
    run: async () => {
      await passphraseLcdPulse();
      log('Startup HSM (démo pas à pas)...');
      lcd(['SELF-TEST .......... PASS', 'UNWRAP LMK ........... ....', '> STARTUP']);
      setHwLeds({ busy: true, net: true, pwr: true });
      saveConfig();
      const r = await PayHsmApi.startup(state.config.password, state.config.dataDir);
      const ok = r.rc === 0;
      lcd([ok ? 'LMK READY ............ YES' : 'LMK READY ............ NO', `${r.message || ''}`.slice(0, 44), ok ? '> KEY VAULT ONLINE' : '> CHECK CRED / DIR']);
      setHwLeds({ busy: false, net: true, fault: !ok, key: ok, pwr: true });
      log(r.message, ok ? 'ok' : 'err');
      demoLog(`Startup: ${r.message}`, ok ? 'ok' : 'err');
      await refreshStatus();
    },
  },
  {
    title: 'Core Banking — émettre le PVV (contrat carte + PIN)',
    lcdIntro: ['HOST LINK .......... BANK', '> ISSUE PVV', 'PAN + PIN (test)'],
    run: async () => {
      const pan = $('#cb-pan').value.trim() || state.config.pan;
      const pin = $('#cb-pin').value.trim() || '1234';
      lcd(['CORE SESSION ....... ACTIVE', `PAN ${pan.slice(-4).padStart(16, '*')}`, '> COMPUTING PVV']);
      setHwLeds({ busy: true, net: true, key: true, pwr: true });
      saveConfig();
      const r = await PayHsmApi.corebankingIssue(pan, pin);
      $('#cb-out-pan').textContent = r.pan || pan;
      $('#cb-out-pvv').textContent = r.pvv || '—';
      const ok = r.rc === 0;
      lcd([ok ? 'PVV PROFILE ........ ISSUED' : 'PVV PROFILE ........ FAIL', ok ? `${r.pvv || ''}` : `${r.message || ''}`.slice(0, 24), '> VERIFY WITH GAP NEXT']);
      setHwLeds({ busy: false, net: true, key: true });
      demoLog(ok ? `PVV=${r.pvv} pour PAN` : r.message || 'échec', ok ? 'ok' : 'err');
      log(`Core Banking: ${r.message || ''}`, ok ? 'ok' : 'err');
    },
  },
  {
    title: 'GAP — créer PIN block chiffré TPK au guichet',
    lcdIntro: ['TERMINAL PED ....... GAP', '> CAPTURE PIN', 'puce keypad OK'],
    run: async () => {
      $('#gap-pin').value = $('#cb-pin').value.trim() || '1234';
      await doGap();
      demoLog(state.pinBlock ? `PIN block TPK = ${state.pinBlock}` : 'GAP échec ou HSM OFF', state.pinBlock ? 'ok' : 'err');
    },
  },
  {
    title: 'HSM — vérifier PIN vs PVV (réseau = pas de PIN clair)',
    lcdIntro: ['CRYPTO ENG ......... PVV CMP', '> TPK DECRYPT', '> APPROVED?'],
    run: async () => {
      $('#verify-pb').value = state.pinBlock || $('#verify-pb').value.trim();
      await doVerify();
      const lbl = $('#verify-result-label')?.textContent || '';
      const ok = lbl.includes('APPROVED') && !lbl.includes('DECLINED');
      demoLog(`Verify: ${lbl}`, lbl.indexOf('DECLINED') >= 0 ? 'warn' : ok ? 'ok' : '');
    },
  },
  {
    title: 'Switch — traduction PIN block vers ZPK (acquéreur)',
    lcdIntro: ['NETWORK KEY ........ ZPK PATH', '> RE-WRAP PIN', '> ISO ZONE'],
    run: async () => {
      $('#switch-pb').value = state.pinBlock || $('#switch-pb').value.trim();
      await doTranslate();
      demoLog(`ZPK PIN block=${state.pinBlockZpk}`, state.pinBlockZpk ? 'ok' : 'err');
    },
  },
  {
    title: 'MAC TAK — intégrité message ISO8583 acquéreur',
    lcdIntro: ['MAC ENG ............ TAK', '> CALC AUTH CODE', '> VERIFY'],
    run: async () => {
      const term = $('#mac-term').value.trim() || state.config.terminal;
      const msg = $('#mac-msg').value || '0200 DEMO ISO8583';
      setHwLeds({ busy: true, net: true, key: true });
      const c = await PayHsmApi.macCalc(term, msg);
      $('#mac-out').textContent = c.mac || '—';
      $('#mac-val').value = (c.mac && c.mac.slice(0, -2) + ((parseInt(c.mac.slice(-1), 16) ^ 1) % 16).toString(16).toUpperCase()) || '';
      const forged = xorHexFlipLastByte(c.mac.trim());
      const vGood = await PayHsmApi.macVerify(term, msg, c.mac.trim());
      const vBad = await PayHsmApi.macVerify(term, msg, forged);
      lcd([
        `MAC CALC ............. OK`,
        `VERIFY GOOD ........ ${vGood.valid}`,
        `ALTERED MAC ........ ${vBad.valid} (démo)`,
      ]);
      $('#mac-val').value = forged;
      demoLog(`MAC calc OK; bon MAC valid=${vGood.valid}; falsifiée valid=${vBad.valid}`, 'ok');
      setHwLeds({ busy: false, net: true, key: true });
      log('MAC calc + contre-exemple rejoueur', 'ok');
    },
  },
  {
    title: 'Paiement EMV — chaîne complète ARQC / ARPC',
    lcdIntro: ['CHIP CONTACT ....... ACTIVE', '> ARQC REQ', '> ARPC RESP'],
    run: async () => {
      await doEmvPurchase();
      demoLog(`EMV: écran décision maj panel EMV`, 'ok');
      lcd(['ICC SESSION ........ END', '> SEE EMV TAB', 'THANK YOU']);
      await sleep(400);
      const dec = $('#emv-res-decision')?.textContent || '';
      if (dec.indexOf('APPROUV') >= 0) {
        lcd(['AUTH RESULT ........ ACCEPT', '> ARPC RETURNED TO TERM', '_']);
      }
    },
  },
];

function demoLog(msg, cls = '') {
  const el = $('#demo-log');
  if (!el) return;
  const line = document.createElement('div');
  line.className = 'entry' + (cls ? ' ' + cls : '');
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  el.prepend(line);
}

function renderDemoChecklist(statuses = {}) {
  const ol = $('#demo-checklist');
  if (!ol) return;
  ol.innerHTML = '';
  DEMO_DEF.forEach((_d, i) => {
    const li = document.createElement('li');
    li.textContent = DEMO_DEF[i].title;
    const st = statuses[i];
    if (st === 'done') li.classList.add('done');
    else if (st === 'fail') li.classList.add('fail');
    else if (st === 'active') li.classList.add('active');
    ol.appendChild(li);
  });

  const numEl = $('#demo-step-num');
  const ttlEl = $('#demo-step-title');

  if (statuses.complete) {
    if (numEl) numEl.textContent = `Étapes ✓ (${DEMO_DEF.length})`;
    if (ttlEl) ttlEl.textContent = 'Onglet Attaques pour les scénarios offensifs.';
    return;
  }

  const activeIdx = DEMO_DEF.findIndex((_d, i) => statuses[i] === 'active');
  const doneCount = DEMO_DEF.reduce((acc, _, i) => acc + (statuses[i] === 'done' ? 1 : 0), 0);
  const titleIdx =
    activeIdx >= 0
      ? activeIdx
      : Math.min(doneCount, DEMO_DEF.length - 1);

  if (numEl) {
    numEl.textContent =
      activeIdx >= 0
        ? `Étape ${activeIdx + 1} / ${DEMO_DEF.length}`
        : `Progression ${doneCount} / ${DEMO_DEF.length}`;
  }
  if (ttlEl) ttlEl.textContent = DEMO_DEF[titleIdx]?.title ?? '';
}

async function passphraseLcdPulse() {
  const pass = $('#cfg-pass')?.value || state.config.password;
  saveConfig();
  lcd([
    'SECURE INPUT ....... GATE',
    'PASS LENGTH ........ ' + lcdPassphraseDots(pass.length),
    '> ACCEPT ...',
    'UNWRAP KEY MAT ....... pending',
  ]);
  setHwLeds({ busy: true, net: true, pwr: true });
  await sleep(650);
}

function resetDemoTour() {
  state.demoStepIndex = 0;
  state.demoRunningAuto = false;
  renderDemoChecklist({ 0: 'active' });
}

async function demoRunStepBody(index) {
  const d = DEMO_DEF[index];
  if (!d) return;
  lcd(d.lcdIntro);
  await sleep(state.demoRunningAuto ? 520 : 200);
  try {
    await d.run();
  } catch (e) {
    log(e.message, 'err');
    demoLog(e.message, 'err');
    lcd(['EXCEPTION .......... SEE LOG', '> API CHECK', `${e.message}`.slice(0, 40)]);
    setHwLeds({ fault: true, busy: false });
    throw e;
  }
}

function markDoneStatuses(upto) {
  const s = {};
  for (let j = 0; j <= upto; j++) s[j] = 'done';
  return s;
}

async function demoNextStepManual() {
  if (state.demoRunningAuto) return;
  const i = state.demoStepIndex;
  if (i >= DEMO_DEF.length) {
    demoLog('Parcours déjà terminé — réinitialiser si besoin', 'warn');
    return;
  }
  const pre = {};
  for (let j = 0; j < i; j++) pre[j] = 'done';
  pre[i] = 'active';
  renderDemoChecklist(pre);
  await demoRunStepBody(i);
  state.demoStepIndex = i + 1;
  if (state.demoStepIndex >= DEMO_DEF.length) {
    lcd(['PROGRAM ............ COMPLETE', 'ALL STAGES GREEN', '> ATTACK LAB']);
    demoLog('Tour manuel terminé — onglet Attaques.', 'ok');
    const all = markDoneStatuses(DEMO_DEF.length - 1);
    all.complete = true;
    renderDemoChecklist(all);
  } else {
    const next = markDoneStatuses(i);
    next[state.demoStepIndex] = 'active';
    renderDemoChecklist(next);
  }
}

async function demoRunFullAutomatic() {
  if (state.demoRunningAuto) return;
  state.demoRunningAuto = true;
  $('#btn-demo-quick').disabled = true;
  $('#btn-demo-step').disabled = true;
  demoLog('=== Tour automatique ===', 'ok');
  try {
    for (let i = 0; i < DEMO_DEF.length; i++) {
      state.demoStepIndex = i;
      const statuses = {};
      for (let j = 0; j < i; j++) statuses[j] = 'done';
      statuses[i] = 'active';
      renderDemoChecklist(statuses);
      await demoRunStepBody(i);
      await sleep(400);
      renderDemoChecklist(markDoneStatuses(i));
    }
    state.demoStepIndex = DEMO_DEF.length;
    const allDone = markDoneStatuses(DEMO_DEF.length - 1);
    allDone.complete = true;
    renderDemoChecklist(allDone);
    lcd(['FULL DEMO FINISH ... OK', 'READY FOR SECURITY LAB', '> TAB ATTACKS']);
    demoLog('Tour auto terminé.', 'ok');
  } catch (_) {
    demoLog('Tour interrompu — corriger erreur puis réessayer.', 'err');
  } finally {
    state.demoRunningAuto = false;
    $('#btn-demo-quick').disabled = false;
    $('#btn-demo-step').disabled = false;
  }
}

async function passphraseDemoOnly() {
  await passphraseLcdPulse();
  lcd(['PASSPHRASE SAMPLE .. OK', '[simulation UX only]', '> USE START FOR REAL']);
  setHwLeds({ busy: false, net: true, fault: false, pwr: true });
  log('LCD passphrase (les secrets ne sont pas affichés en clair).', 'ok');
}

/** Attaques : toujours vraie API JSON */
async function flushAttack(payload) {
  const pre = $('#attack-out');
  if (pre) pre.textContent = JSON.stringify(payload, null, 2);
}

function xorHexFlipLastByte(hexStr) {
  if (!hexStr || hexStr.length !== 16) return hexStr;
  const nib = hexStr.slice(-1);
  const map = '0123456789ABCDEF';
  let v = parseInt(nib, 16);
  if (Number.isNaN(v)) return hexStr;
  v ^= 8;
  return hexStr.slice(0, -1) + map[v];
}

async function attackWrongPin() {
  const term = state.config.terminal;
  const pan = state.config.pan;
  setHwLeds({ busy: true, key: true });
  const pb = await PayHsmApi.gap(term, '9999', pan);
  if (pb.rc !== 0) await flushAttack({ scene: 'wrong-pin-gap', pb });
  const v = pb.pinBlock ? await PayHsmApi.verify(term, pan, pb.pinBlock).catch((e) => ({ error: e.message })) : { skip: true };
  await flushAttack({
    attaque: 'PIN ≠ contrat PVV (9999)',
    gap: pb,
    verify: v,
    story: 'Le PIN block est légitime crypto mais PVV mismatch → DECLINED.',
  });
  setHwLeds({ busy: false });
  lcd(['ATTACK BOX ......... RED TEAM', '> WRONG PIN PATH', '> DECLINED']);
  log('Attaque PIN incorrect.', 'warn');
}

async function attackTamperPb() {
  const term = state.config.terminal;
  const pan = state.config.pan;
  const g = await PayHsmApi.gap(term, '1234', pan);
  if (g.rc !== 0 || !g.pinBlock) {
    await flushAttack({ err: 'GAP requis avant', gap: g });
    return;
  }
  const bad = xorHexFlipLastByte(g.pinBlock);
  const v = await PayHsmApi.verify(term, pan, bad);
  await flushAttack({
    attaque: 'PIN block falsifiée (nonce bit flip)',
    original: g.pinBlock,
    tampered: bad,
    verify: v,
    story: 'Mac/dérivation interne KO → DECLINED sans exposer erreur exploitable.',
  });
  lcd(['ATTACK ............... REPLAY', '> TPK DECRYPT?', '> INTERNAL FAIL']);
}

async function attackWrongTerminal() {
  const pan = state.config.pan;
  const g = await PayHsmApi.gap(state.config.terminal, '1234', pan);
  if (g.rc !== 0 || !g.pinBlock) {
    await flushAttack({ err: 'GAP sur terminal valide dabord impossible', gap: g });
    return;
  }
  const v = await PayHsmApi.verify('ATM_DOES_NOT_EXIST', pan, g.pinBlock);
  await flushAttack({
    attaque: 'terminal inconnu (TPK vault)',
    verify: v,
    story: 'Impossible unwrap TPK → échec côté HSM avant comparaison PVV.',
  });
}

async function attackMacTamper() {
  const term = state.config.terminal;
  const msg = $('#mac-msg').value || '0200 DEMO ISO8583';
  const c = await PayHsmApi.macCalc(term, msg);
  const genuine = String(c.mac || '').replace(/\s/g, '').toUpperCase().slice(0, 16);
  const fake =
    genuine.length === 16 ? xorHexFlipLastByte(genuine) : genuine + 'DE';
  const vBad = await PayHsmApi.macVerify(term, msg, genuine.length === 16 ? fake.slice(0, 16) : fake);
  await flushAttack({
    attaque: 'MAC altérée',
    genuine: c.mac,
    forged: fake.slice(0, 16),
    verifyForgedAccepted: vBad.valid,
    story:
      genuine.length !== 16
        ? 'MAC hex inattendu — vérifiez terminaux.'
        : 'Comparaison en temps constant → valid:false (voir mac.c backend).',
  });
}

function randomHex16() {
  let out = '';
  for (let i = 0; i < 16; i++) out += '0123456789ABCDEF'.charAt(Math.floor(Math.random() * 16));
  return out;
}

async function attackArqcForge() {
  const pan = $('#emv-pan').value.trim() || state.config.pan;
  const psn = $('#emv-psn').value.trim() || '00';
  const atc = $('#emv-atc').value.trim() || '0001';
  const tx = $('#emv-tx').value || '000000000100000978';
  const txHex = [...tx].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('').toUpperCase();
  const forged = randomHex16() + randomHex16();
  const v = await PayHsmApi.emvVerify(pan, psn, atc, txHex, forged.slice(0, 16));
  await flushAttack({
    attaque: 'ARQC aléatoire',
    bogusArqc: forged.slice(0, 16),
    verify: v,
    story: 'valid=false et pas d’ARPC légitime → TPE doit refuser.',
  });
}

async function attackEmvMitmAmount() {
  const pan = $('#emv-pay-pan').value.trim() || state.config.pan;
  const psn = $('#emv-pay-psn').value.trim() || '00';
  const atc = $('#emv-pay-atc').value.trim() || '0001';
  const rLegit = await PayHsmApi.emvPurchase(pan, psn, atc, 1000, '978');
  const rFake = await PayHsmApi.emvPurchase(pan, psn, atc, 999999, '978');
  await flushAttack({
    attaque: 'montant différent même ATC — pas de même ARQC sous-jacent',
    achatHonneteCentimes: 1000,
    arqcHonnete: rLegit.arqc,
    arpcHonnete: rLegit.arpc,
    achatGreedyCents: 999999,
    resultatGreedyApproved: rFake.approved,
    messageGreedy: rFake.message,
  });
}

async function attackColdGap() {
  lcd(['SECURITY SHUTDOWN .. INIT', '> STRIKE: COLD OPS']);
  saveConfig();
  await PayHsmApi.shutdown().catch(() => null);
  const r = await PayHsmApi.gap(state.config.terminal, '1234', state.config.pan).catch((e) => ({ error: e.message }));
  await PayHsmApi.startup(state.config.password, state.config.dataDir).catch(() => null);
  await refreshStatus().catch(() => {});
  await flushAttack({
    attaque: 'GAP sans HSM up',
    résultat: r,
    story: 'Puis remise en ligne automatique dans ce sandbox.',
  });
  lcd(['RECOVERY ........... BOOT', '> HSM RESTART TRY', 'SEE SETUP TAB']);
}

async function attackBadPassphrase() {
  saveConfig();
  const wrong = `${state.config.password}_INVALID`;
  const r = await PayHsmApi.startup(wrong, state.config.dataDir);
  await flushAttack({
    attaque: 'startup passphrase invalide',
    rc: r.rc,
    message: r.message,
  });
  lcd([r.rc === 0 ? 'UNEXPECTED ACCEPT' : 'AUTH FAIL GATE ....... OK', '> REAL PASS IN SETUP', '']);
}

async function runAttack(kind) {
  const atkOut = $('#attack-out');
  if (atkOut) atkOut.textContent = 'chargement...\n';
  setHwLeds({ busy: true, net: true, key: true });
  demoLog(`Attaque "${kind}" — exécution`, '');
  try {
    switch (kind) {
      case 'wrong-pin': await attackWrongPin(); break;
      case 'tamper-pb': await attackTamperPb(); break;
      case 'wrong-terminal': await attackWrongTerminal(); break;
      case 'mac-tamper': await attackMacTamper(); break;
      case 'arqc-forge': await attackArqcForge(); break;
      case 'emv-mitm-amt': await attackEmvMitmAmount(); break;
      case 'cold-gap': await attackColdGap(); break;
      case 'bad-passphrase': await attackBadPassphrase(); break;
      default: await flushAttack({ error: kind });
    }
  } catch (e) {
    await flushAttack({ error: String(e.message || e) });
    log(`Attaque ${kind}: ${e.message}`, 'err');
  } finally {
    setHwLeds({ busy: false });
  }
}

/** Lit les champs Setup avant Provision/Startup (évite passphrase vide si pas de blur). */
function syncConfigFromForm() {
  state.config.api = $('#cfg-api')?.value?.trim() || state.config.api;
  state.config.password = $('#cfg-pass')?.value || '';
  state.config.dataDir = $('#cfg-dir')?.value?.trim() || state.config.dataDir;
  state.config.terminals = $('#cfg-terms')?.value?.trim() || state.config.terminals;
  if (state.config.dataDir && !state.config.dataDir.startsWith('/')) {
    state.config.dataDir = `/${state.config.dataDir.replace(/^\/+/, '')}`;
  }
}

function saveConfig() {
  syncConfigFromForm();
  localStorage.setItem('payhsm_api', state.config.api);
  localStorage.setItem('payhsm_data', state.config.dataDir);
  localStorage.setItem('payhsm_terms', state.config.terminals);
  localStorage.setItem('payhsm_term', state.config.terminal);
  localStorage.setItem('payhsm_pan', state.config.pan);
  PayHsmApi.setBase(state.config.api);
}

function log(msg, cls = '') {
  const el = $('#event-log');
  if (!el) return;
  const line = document.createElement('div');
  line.className = 'entry' + (cls ? ' ' + cls : '');
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  el.prepend(line);
}

function setStatus(ok, text) {
  const dot = $('#status-dot');
  const lbl = $('#status-label');
  if (dot) {
    dot.className = 'status-dot ' + (ok ? 'status-unlocked' : ok === false ? 'status-error' : 'status-locked');
  }
  if (lbl) lbl.textContent = text;
}

function bindConfig() {
  $('#cfg-api').value = state.config.api;
  $('#cfg-pass').value = state.config.password;
  $('#cfg-dir').value = state.config.dataDir;
  $('#cfg-terms').value = state.config.terminals;
  $$('[data-cfg]').forEach((inp) => {
    const k = inp.dataset.cfg;
    if (state.config[k] !== undefined) inp.value = state.config[k];
    inp.addEventListener('change', () => {
      state.config[k] = inp.value;
      saveConfig();
    });
  });
  $('#cfg-api').addEventListener('change', () => {
    state.config.api = $('#cfg-api').value;
    saveConfig();
  });
  $('#cfg-pass').addEventListener('change', () => {
    state.config.password = $('#cfg-pass').value;
    saveConfig();
  });
  $('#cfg-dir').addEventListener('change', () => {
    state.config.dataDir = $('#cfg-dir').value;
    saveConfig();
  });
  $('#cfg-terms').addEventListener('change', () => {
    state.config.terminals = $('#cfg-terms').value;
    saveConfig();
  });
}

async function refreshStatus() {
  try {
    const h = await PayHsmApi.health();
    const s = await PayHsmApi.status();
    setStatus(h.initialized, h.initialized ? 'HSM actif (C)' : 'HSM hors ligne ou arrêté');
    setHwLeds({
      pwr: true,
      net: true,
      busy: false,
      fault: false,
      key: !!h.initialized,
    });
    $('#metric-keys').textContent = 'STATELESS (0)';
    $('#metric-integ').textContent = s.integrity ? 'OK' : '—';
    $('#metric-lmk').textContent = s.lmk?.fragmented ? 'P1|P2|P3' : '—';
    const tbody = $('#keys-body');
    if (tbody) tbody.innerHTML = '';
    ['frag-p1', 'frag-p2', 'frag-p3'].forEach((_id, i) => {
      const elid = `#frag-p${i + 1}`;
      const el = $(elid);
      if (el) el.classList.toggle('mutate', s.lmk?.fragmented);
    });
    log('Status OK — Mode Stateless', 'ok');
    if (h.initialized) {
      lcd(['SECURE KERNEL ...... ACTIVE', 'STATELESS VAULT .... ACTIVE', '> OPERATIONS READY']);
    } else {
      lcd(['MODULE ............. IDLE', '> AWAIT BOOTSTRAP', 'SETUP → START HSM']);
    }
  } catch (e) {
    setStatus(false, 'API hors ligne');
    setHwLeds({ pwr: true, net: false, fault: true, busy: false, key: false });
    lcd(['NETWORK ............ DOWN', '> CHECK HTTPD PORT', '> scripts/start-console.sh']);
    log(e.message, 'err');
  }
}

async function doProvision() {
  saveConfig();
  if (!state.config.password) {
    log('Passphrase vide — saisissez-la puis recliquez Provision', 'err');
    return;
  }
  if (!state.config.dataDir) {
    log('Répertoire données vide', 'err');
    return;
  }
  log('Provision (LMK + vault)...');
  lcd(['FMT SECURE AREA .... WAIT', '> PROVISION TOKEN', '> DO NOT INTERRUPT']);
  setHwLeds({ busy: true, net: true });
  const r = await PayHsmApi.provision(state.config.password, state.config.dataDir, state.config.terminals);
  setHwLeds({ busy: false, net: true, fault: r.rc !== 0 });
  log(r.message, r.rc === 0 ? 'ok' : 'err');
  lcd([r.rc === 0 ? 'PROVISION DONE ... OK' : 'PROVISION FAILURE', `${r.message}`.slice(0, 40), '> STARTUP AFTER OK']);
  await refreshStatus();
}

async function doStartup() {
  saveConfig();
  if (!state.config.password) {
    log('Passphrase vide — saisissez-la puis Démarrer HSM', 'err');
    return;
  }
  log('Startup HSM...');
  await passphraseLcdPulse();
  lcd(['SELF-TEST .......... RUN', '> UNWRAP LMK', '']);
  setHwLeds({ busy: true, net: true });
  const r = await PayHsmApi.startup(state.config.password, state.config.dataDir);
  setHwLeds({ busy: false, fault: r.rc !== 0, key: r.rc === 0, net: true, pwr: true });
  log(r.message, r.rc === 0 ? 'ok' : 'err');
  lcd([r.rc === 0 ? 'HSM ONLINE ......... ***' : 'STARTUP FAILURE', `${r.message}`.slice(0, 40), r.rc === 0 ? '> READY' : '> SEE LOG']);
  await refreshStatus();
}

async function doShutdown() {
  lcd(['POWER DOWN ......... USER', '> FLUSH VOLATILE', '> BYE']);
  setHwLeds({ busy: true });
  await PayHsmApi.shutdown().catch(() => null);
  setHwLeds({ busy: false, key: false, fault: false, net: true, pwr: true });
  log('HSM arrêté.', 'warn');
  await refreshStatus().catch(() => {});
}

async function doCoreBankingIssue() {
  const pan = $('#cb-pan').value.trim();
  const pin = $('#cb-pin').value.trim();
  if (!pan || pin.length < 4) {
    log('Core Banking: PAN et PIN (4+) requis', 'err');
    return;
  }
  const h = await PayHsmApi.health().catch(() => null);
  if (!h?.initialized) {
    $('#cb-out-pan').textContent = pan;
    $('#cb-out-pvv').textContent = 'HSM non démarré';
    log('Core Banking: onglet Setup → Démarrer HSM (même répertoire données)', 'err');
    return;
  }
  const r = await PayHsmApi.corebankingIssue(pan, pin);
  if (r.rc !== 0 && r.rc !== undefined) {
    $('#cb-out-pan').textContent = pan;
    $('#cb-out-pvv').textContent = r.message || 'échec';
    log('Core Banking echec: ' + (r.message || 'API obsolete — scripts/start-console.sh'), 'err');
    return;
  }
  $('#cb-out-pan').textContent = r.pan || pan;
  $('#cb-out-pvv').textContent = r.pvv || '—';
  log(`Core Banking: PVV=${r.pvv} pour PAN ${pan}`, 'ok');
}

async function doCoreBankingLookup() {
  const pan = $('#cb-lookup-pan').value.trim();
  if (!pan) {
    log('Consulter PVV: saisir un PAN', 'err');
    return;
  }
  const r = await PayHsmApi.corebankingLookup(pan);
  if (r.rc === -1 && r.message && r.message.indexOf('route') >= 0) {
    $('#cb-lookup-pvv').textContent = 'API obsolète — relancez scripts/start-console.sh';
    log(r.message, 'err');
    return;
  }
  if (r.message && r.message.indexOf('non demarre') >= 0) {
    $('#cb-lookup-pvv').textContent = 'HSM non démarré (Setup)';
    log(r.message, 'err');
    return;
  }
  const found = r.found === true || r.found === 'true' || (r.rc === 0 && r.pvv);
  $('#cb-lookup-pvv').textContent = found ? `PVV = ${r.pvv}` : 'Aucun PVV pour ce PAN — émettre d\'abord';
  log(found ? `PVV stocké: ${r.pvv}` : 'PAN inconnu — cliquez Émettre PVV', found ? 'ok' : 'warn');
}

async function doGap() {
  const term = $('#gap-term').value.trim();
  const pin = $('#gap-pin').value.trim();
  const pan = $('#gap-pan').value.trim();

  if (!term || !pan) {
    log('GAP: terminal et PAN obligatoires', 'err');
    return;
  }
  if (pin.length < 4) {
    log('GAP: saisir un PIN (4-12 chiffres) puis OK sur le pave', 'err');
    return;
  }

  const h = await PayHsmApi.health();
  if (!h.initialized) {
    log('GAP: HSM arrete — Setup → Demarrer HSM (meme dataDir que provision)', 'err');
    return;
  }

  lcd(['PED CAPTURE ..........OK', '> ZPK SESSION', '> GEN PIN BLOCK']);

  const r = await PayHsmApi.gap(term, pin, pan);
  if (r.rc !== 0) {
    log('GAP echec: ' + (r.message || 'erreur inconnue'), 'err');
    $('#gap-pb').textContent = '—';
    setPipeline('gap', false);
    return;
  }
  state.pinBlock = r.pinBlock || '';
  $('#gap-pb').textContent = state.pinBlock || '—';
  log('GAP pin block: ' + state.pinBlock, 'ok');
  lcd(['GAP OK ......... TPKWRAP', '> PIN CLR DESTROY OK', '> SEND HEX TO SWITCH']);
  setPipeline('gap', true);
}

function setHsmVerifySteps(activeStep, ok) {
  const order = ['recv', 'tpk', 'dec', 'pvv', 'cmp'];
  $$('#hsm-verify-steps li').forEach((li) => {
    li.classList.remove('active', 'done', 'fail');
    const s = li.dataset.step;
    const idx = order.indexOf(s);
    const aidx = order.indexOf(activeStep);
    if (idx < aidx) li.classList.add('done');
    else if (s === activeStep) li.classList.add(ok ? 'active' : 'fail');
  });
  if (activeStep === 'cmp' && ok) {
    $$('#hsm-verify-steps li').forEach((li) => li.classList.add('done'));
  }
}

async function doVerify() {
  const term = $('#verify-term').value.trim();
  const pan = $('#verify-pan').value.trim();
  const pb = ($('#verify-pb').value || state.pinBlock || '').trim().replace(/\s/g, '');

  const lbl = $('#verify-result-label');
  lbl.textContent = '—';
  lbl.className = 'verify-result';

  if (!term || !pan) {
    log('VERIFY: terminal et PAN obligatoires', 'err');
    lbl.textContent = 'Terminal et PAN requis';
    lbl.classList.add('fail');
    return;
  }
  if (!pb || pb.length !== 16) {
    log('VERIFY: PIN block hex invalide (16 caractères)', 'err');
    lbl.textContent = 'PIN block hex requis (16 car.) — voir onglet GAP';
    lbl.classList.add('fail');
    return;
  }

  lcd(['PROCESS PIN BLOCK ....', '> TPK ROUTE']);

  setHsmVerifySteps('recv', true);
  await sleep(140);
  setHsmVerifySteps('tpk', true);
  await sleep(140);
  setHsmVerifySteps('dec', true);
  await sleep(140);
  setHsmVerifySteps('pvv', true);

  try {
    const r = await PayHsmApi.verify(term, pan, pb);
    const approved = r.code === 0;
    setHsmVerifySteps('cmp', approved);
    lbl.textContent = r.result || (approved ? 'APPROVED' : 'DECLINED');
    lbl.classList.add(approved ? 'ok' : 'fail');
    log(
      `VERIFY ${pan}: ${r.result} (PIN block TPK reçu, jamais transmis en clair)`,
      approved ? 'ok' : 'warn'
    );
    lcd([
      `${approved ? 'DECISION .......... APPROVE' : 'DECISION .......... DECLINE'}`,
      `CODE ${String(r.code)}`,
      approved ? '> ISSUER ACCEPT' : '> THREAT ANALYSIS LOG',
    ]);
    setPipeline('verify', approved);
  } catch (e) {
    setHsmVerifySteps('pvv', false);
    lbl.textContent = e.message;
    lbl.classList.add('fail');
    log('VERIFY: ' + e.message, 'err');
  }
}

async function doTranslate() {
  const pb = $('#switch-pb').value || state.pinBlock;
  setHwLeds({ busy: true, key: true });
  const r = await PayHsmApi.translate($('#switch-term').value, pb);
  state.pinBlockZpk = r.pinBlockZpk || '';
  $('#switch-zpk').textContent = state.pinBlockZpk;
  log('ZPK pin block: ' + state.pinBlockZpk, r.rc === 0 ? 'ok' : 'err');
  setPipeline('switch', r.rc === 0);
  setHwLeds({ busy: false, key: true });
  lcd(['ZPK SESSION ......... OK', '> REWRAP DONE', '> FORWARD SWITCH']);
}

async function doMacCalc() {
  const r = await PayHsmApi.macCalc($('#mac-term').value, $('#mac-msg').value);
  $('#mac-out').textContent = r.mac || '—';
  log('MAC TAK: ' + r.mac, r.rc === 0 ? 'ok' : 'err');
}

async function doMacVerify() {
  const r = await PayHsmApi.macVerify($('#mac-term').value, $('#mac-msg').value, $('#mac-val').value);
  log('MAC verify: ' + (r.valid ? 'OK' : 'KO'), r.valid ? 'ok' : 'err');
}

async function doEmvArqc() {
  const tx = $('#emv-tx').value;
  const txHex = [...tx].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('').toUpperCase();
  const r = await PayHsmApi.emvArqc($('#emv-pan').value, $('#emv-psn').value, $('#emv-atc').value, txHex);
  $('#emv-arqc').textContent = r.arqc || '—';
  $('#emv-arqc-in').value = r.arqc || '';
  log('ARQC: ' + r.arqc, 'ok');
}

async function doEmvVerify() {
  const tx = $('#emv-tx').value;
  const txHex = [...tx].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('').toUpperCase();
  const r = await PayHsmApi.emvVerify(
    $('#emv-pan').value, $('#emv-psn').value, $('#emv-atc').value, txHex, $('#emv-arqc-in').value
  );
  $('#emv-arpc').textContent = r.arpc || '—';
  log('EMV ' + (r.valid ? 'ARQC OK, ARPC ' + r.arpc : 'ARQC KO'), r.valid ? 'ok' : 'err');
}

function setEmvPipeline(steps, approved) {
  $$('#emv-pipeline li').forEach((li) => {
    li.classList.remove('active', 'done', 'fail');
    const id = li.dataset.step;
    const st = steps?.find((s) => s.id === id);
    if (!st) return;
    if (st.ok) li.classList.add('done');
    else li.classList.add('fail');
  });
  if (approved) {
    $$('#emv-pipeline li').forEach((li) => li.classList.add('done'));
  }
}

async function doEmvPurchase() {
  const pan = $('#emv-pay-pan').value.trim();
  const psn = $('#emv-pay-psn').value.trim() || '00';
  const atc = $('#emv-pay-atc').value.trim() || '0001';
  const euros = parseFloat($('#emv-amount').value) || 0;
  const cents = Math.round(euros * 100);

  const screen = $('#emv-pay-screen');
  screen.textContent = 'Lecture puce…';

  const h = await PayHsmApi.health();
  if (!h.initialized) {
    screen.textContent = 'HSM non demarre';
    log('EMV: Demarrer HSM dans Setup', 'err');
    return;
  }

  try {
    screen.textContent = 'Calcul ARQC…';
    const r = await PayHsmApi.emvPurchase(pan, psn, atc, cents, '978');

    $('#emv-res-amount').textContent = r.amount || (euros + ' EUR');
    $('#emv-res-tx').textContent = r.txData || '—';
    $('#emv-res-arqc').textContent = r.arqc || '—';
    $('#emv-res-arpc').textContent = r.arpc || '—';
    const dec = $('#emv-res-decision');
    if (r.approved) {
      dec.textContent = 'APPROUVÉ';
      dec.style.color = 'var(--green)';
      screen.textContent = 'Paiement accepté';
    } else {
      dec.textContent = 'REFUSÉ';
      dec.style.color = 'var(--red)';
      screen.textContent = 'Paiement refusé';
    }

    setEmvPipeline(r.steps, r.approved);
    log('EMV achat: ' + r.message + ' ARQC=' + r.arqc, r.approved ? 'ok' : 'err');

    $('#emv-arqc').textContent = r.arqc || '—';
    $('#emv-arqc-in').value = r.arqc || '';
    $('#emv-arpc').textContent = r.arpc || '—';
    $('#emv-tx').value = r.txData || '';
  } catch (e) {
    screen.textContent = 'Erreur';
    log('EMV: ' + e.message, 'err');
  }
}

/* ------------------------------------------------------------------ */
/*  Test rotation LMK                                                  */
/* ------------------------------------------------------------------ */

function lmkLog(msg, cls = '') {
  const el = $('#lmk-log');
  if (!el) return;
  const line = document.createElement('div');
  line.className = 'entry' + (cls ? ' ' + cls : '');
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  el.prepend(line);
}

function setLmkPipeline(step, ok) {
  $$('#lmk-test-pipeline li').forEach((li) => {
    li.classList.remove('active', 'done', 'fail');
    if (li.dataset.step === step)
      li.classList.add(ok ? 'done' : 'fail');
  });
}

async function doLmkEncrypt() {
  const tmkHex = $('#lmk-tmk-in').value.trim().toUpperCase();
  const zmkHex = $('#lmk-zmk-in').value.trim().toUpperCase();

  if (tmkHex.length !== 32 || !/^[0-9A-F]+$/.test(tmkHex)) {
    lmkLog('TMK invalide — saisir 32 caractères hexadécimaux', 'err');
    return;
  }
  if (zmkHex.length !== 32 || !/^[0-9A-F]+$/.test(zmkHex)) {
    lmkLog('ZMK invalide — saisir 32 caractères hexadécimaux', 'err');
    return;
  }

  const h = await PayHsmApi.health().catch(() => null);
  if (!h?.initialized) {
    lmkLog('HSM non démarré — onglet Bootstrap → Démarrer HSM', 'err');
    return;
  }

  lmkLog('Chiffrement TMK sous LMK courante…');
  setHwLeds({ busy: true, net: true, key: true });

  try {
    const rTmk = await PayHsmApi.lmkEncrypt('TMK', tmkHex);
    if (!rTmk.ok) throw new Error(rTmk.message);

    const rZmk = await PayHsmApi.lmkEncrypt('ZMK', zmkHex);
    if (!rZmk.ok) throw new Error(rZmk.message);

    state.lmkBlobs.tmk = rTmk.blob;
    state.lmkBlobs.zmk = rZmk.blob;

    $('#lmk-blob-tmk').textContent = rTmk.blob;
    $('#lmk-blob-zmk').textContent = rZmk.blob;
    $('#lmk-enc-result').style.display = 'block';

    lmkLog('TMK + ZMK chiffrés — blobs stockés en mémoire', 'ok');
    lcd(['LMK WRAP .......... OK', '> TMK BLOB READY', '> ZMK BLOB READY']);
  } catch (e) {
    lmkLog('Échec chiffrement : ' + e.message, 'err');
  } finally {
    setHwLeds({ busy: false, net: true, key: true });
  }
}

async function doLmkReprovision() {
  if (!state.lmkBlobs.tmk || !state.lmkBlobs.zmk) {
    lmkLog('Effectuez d\'abord l\'étape 1 (chiffrer TMK + ZMK)', 'err');
    return;
  }
  lmkLog('Re-provision — génération nouvelle LMK…', 'warn');
  lcd(['REPROVISION ....... WAIT', '> NEW LMK GEN', '> FRAGMENTS RESET']);
  setHwLeds({ busy: true, net: true });
  try {
    const r = await PayHsmApi.provision(
      state.config.password,
      state.config.dataDir,
      state.config.terminals
    );
    const ok = r.rc === 0;
    $('#lmk-reprov-status').textContent = ok
      ? '✓ Nouveau HSM provisionné — LMK_2 active'
      : '✗ ' + (r.message || 'échec provision');
    $('#lmk-reprov-status').style.color = ok ? 'var(--green)' : 'var(--red)';
    lmkLog(ok ? 'Nouvelle LMK générée — ancienne LMK effacée' : 'Échec : ' + r.message,
           ok ? 'ok' : 'err');
    lcd([ok ? 'NEW LMK ......... ACTIVE' : 'PROVISION FAIL', r.message.slice(0, 40), '> STEP 3 READY']);
    if (ok) await refreshStatus();
  } catch (e) {
    lmkLog('Échec re-provision : ' + e.message, 'err');
  } finally {
    setHwLeds({ busy: false, net: true });
  }
}

async function doLmkDecryptTest() {
  if (!state.lmkBlobs.tmk || !state.lmkBlobs.zmk) {
    lmkLog('Aucun blob disponible — effectuez l\'étape 1 d\'abord', 'err');
    return;
  }

  lmkLog('Tentative déchiffrement avec LMK courante…');
  setHwLeds({ busy: true, net: true });

  let tmkOk = false, zmkOk = false;
  let tmkResult = '—', zmkResult = '—';

  try {
    /* --- TMK --- */
    const rTmk = await PayHsmApi.lmkDecrypt('TMK', state.lmkBlobs.tmk);
    tmkOk = rTmk.ok === true;
    if (tmkOk) {
      tmkResult = rTmk.keyHex;
      /* Vérification : le hex récupéré doit correspondre à ce qu'on avait saisi */
      const saisie = $('#lmk-tmk-in').value.trim().toUpperCase();
      if (saisie && rTmk.keyHex.toUpperCase() !== saisie)
        tmkResult += ' ⚠ différent de la saisie initiale';
    } else {
      tmkResult = '✗ ' + (rTmk.message || 'tag invalide');
    }
    setLmkPipeline('tmk', tmkOk);
    lmkLog('TMK : ' + (tmkOk ? 'déchiffré OK → ' + rTmk.keyHex : 'REJETÉ — ' + rTmk.message),
           tmkOk ? 'ok' : 'err');

    /* --- ZMK --- */
    const rZmk = await PayHsmApi.lmkDecrypt('ZMK', state.lmkBlobs.zmk);
    zmkOk = rZmk.ok === true;
    if (zmkOk) {
      zmkResult = rZmk.keyHex;
      const saisie = $('#lmk-zmk-in').value.trim().toUpperCase();
      if (saisie && rZmk.keyHex.toUpperCase() !== saisie)
        zmkResult += ' ⚠ différent de la saisie initiale';
    } else {
      zmkResult = '✗ ' + (rZmk.message || 'tag invalide');
    }
    setLmkPipeline('zmk', zmkOk);
    lmkLog('ZMK : ' + (zmkOk ? 'déchiffré OK → ' + rZmk.keyHex : 'REJETÉ — ' + rZmk.message),
           zmkOk ? 'ok' : 'err');
  } catch (e) {
    lmkLog('Erreur API : ' + e.message, 'err');
  } finally {
    setHwLeds({ busy: false, net: true });
  }

  $('#lmk-dec-tmk').textContent = tmkResult;
  $('#lmk-dec-zmk').textContent = zmkResult;

  const verdict = $('#lmk-verdict');
  if (tmkOk && zmkOk) {
    verdict.textContent = '✓ LMK correcte — TMK et ZMK déchiffrés';
    verdict.style.color = 'var(--green)';
    lcd(['LMK VERIFY ........ OK', '> KEYS DECRYPTED', '> SAME LMK CONFIRMED']);
    lmkLog('RÉSULTAT : même LMK → déchiffrement réussi', 'ok');
  } else if (!tmkOk && !zmkOk) {
    verdict.textContent = '✗ LMK différente — blobs rejetés par GCM (attendu après re-provision)';
    verdict.style.color = 'var(--red)';
    lcd(['LMK CHANGED ....... OK', '> BLOBS REJECTED', '> ROTATION PROUVEE']);
    lmkLog('RÉSULTAT : LMK différente → blobs illisibles ✓ (sécurité validée)', 'ok');
  } else {
    verdict.textContent = '⚠ Résultat partiel — vérifier les logs';
    verdict.style.color = 'var(--yellow, orange)';
  }
}

async function runFullScenario() {
  saveConfig();
  setPipeline(null, false);
  log('=== Scenario PIN complet ===');
  lcd(['AUTO PIPELINE ..... RUN', '> STARTUP SEQ', '']);
  await doStartup();
  await sleep(320);
  const cb = await PayHsmApi.corebankingIssue(state.config.pan, '1234');
  log(`Core Banking PVV=${cb.pvv}`, 'ok');
  const g = await PayHsmApi.gap(state.config.terminal, '1234', state.config.pan);
  state.pinBlock = g.pinBlock;
  $('#gap-pb').textContent = state.pinBlock;
  setPipeline('gap', true);
  const v = await PayHsmApi.verify(state.config.terminal, state.config.pan, state.pinBlock);
  log('Verify: ' + v.result, v.code === 0 ? 'ok' : 'err');
  setPipeline('verify', v.code === 0);
  const t = await PayHsmApi.translate(state.config.terminal, state.pinBlock);
  state.pinBlockZpk = t.pinBlockZpk;
  $('#switch-zpk').textContent = state.pinBlockZpk;
  setPipeline('switch', t.rc === 0);
  lcd(['SEQ COMPLETE .........', '> OK', '> DEMO CARD TAB']);
  log('=== Scenario termine ===', 'ok');
}

function setPipeline(step, ok) {
  const order = ['gap', 'hsm', 'verify', 'switch'];
  const map = { gap: 'gap', verify: 'verify', switch: 'switch' };
  const active = map[step];
  $$('#flow-pipeline li').forEach((li) => {
    const s = li.dataset.step;
    li.classList.remove('active', 'done', 'fail');
    if (!active) return;
    const idx = order.indexOf(s);
    const aidx = order.indexOf(active === 'gap' ? 'gap' : active === 'verify' ? 'verify' : 'switch');
    if (idx < aidx) li.classList.add('done');
    else if (s === active) li.classList.add(ok ? 'active' : 'fail');
  });
}

function initPinPad() {
  const display = $('#pin-display');
  let buf = '';
  const render = () => { display.textContent = buf ? '*'.repeat(buf.length) : '____'; };
  $$('.pin-pad button').forEach((btn) => {
    btn.addEventListener('click', () => {
      const k = btn.dataset.key;
      if (k === 'C') buf = '';
      else if (k === 'OK') {
        $('#gap-pin').value = buf;
        buf = '';
      } else if (buf.length < 12) buf += k;
      render();
    });
  });
}

function initTabs() {
  const tabs = [
    ['demo', '0. Démo projet'],
    ['setup', '1. Bootstrap'],
    ['dashboard', '2. Coffre'],
    ['corebanking', '3. Core Bank'],
    ['gap', '4. Guichet GAP'],
    ['hsm', '5. Vérif PIN'],
    ['switch', '6. Switch ZPK'],
    ['emv', '7. EMV'],
    ['mac', '8. MAC'],
    ['attacks', '9. Attaques'],
    ['flow', '10. Scénario PIN'],
    ['lmktest', '11. Test LMK'],
  ];
  const nav = $('#tabs');
  tabs.forEach(([id, label], i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    b.dataset.panel = id;
    if (i === 0) b.classList.add('active');
    b.addEventListener('click', () => {
      $$('.tabs button').forEach((x) => x.classList.remove('active'));
      $$('.panel').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      $('#panel-' + id).classList.add('active');
    });
    nav.appendChild(b);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  PayHsmApi.setBase(state.config.api);
  bindConfig();
  initTabs();
  initPinPad();
  resetDemoTour();
  setHwLeds({ pwr: true, net: false, fault: false, busy: false, key: false });
  lcd(['PayHSM-1 ..... POWER ON', 'WAIT API LINK ...', ' ', '> LOADING INTERFACE']);

  $('#btn-health').addEventListener('click', () =>
    refreshStatus().catch((e) => log(e.message, 'err')));
  $('#btn-passphrase-demo').addEventListener('click', () =>
    passphraseDemoOnly().catch((e) => log(e.message, 'err')));
  $('#btn-provision').addEventListener('click', () => doProvision().catch((e) => log(e.message, 'err')));
  $('#btn-startup').addEventListener('click', () => doStartup().catch((e) => log(e.message, 'err')));
  $('#btn-shutdown').addEventListener('click', () => doShutdown().catch((e) => log(e.message, 'err')));
  $('#btn-cb-issue').addEventListener('click', () => doCoreBankingIssue().catch((e) => log(e.message, 'err')));
  $('#btn-cb-lookup').addEventListener('click', () => doCoreBankingLookup().catch((e) => log(e.message, 'err')));
  $('#btn-gap').addEventListener('click', () => doGap().catch((e) => log(e.message, 'err')));
  $('#btn-verify').addEventListener('click', () => doVerify().catch((e) => log(e.message, 'err')));
  $('#btn-translate').addEventListener('click', () => doTranslate().catch((e) => log(e.message, 'err')));
  $('#btn-mac-calc').addEventListener('click', () => doMacCalc().catch((e) => log(e.message, 'err')));
  $('#btn-mac-verify').addEventListener('click', () => doMacVerify().catch((e) => log(e.message, 'err')));
  $('#btn-emv-pay').addEventListener('click', () => doEmvPurchase().catch((e) => log(e.message, 'err')));
  $('#btn-emv-arqc').addEventListener('click', () => doEmvArqc().catch((e) => log(e.message, 'err')));
  $('#btn-emv-verify').addEventListener('click', () => doEmvVerify().catch((e) => log(e.message, 'err')));
  $('#btn-scenario').addEventListener('click', () => runFullScenario().catch((e) => log(e.message, 'err')));

  /* Test LMK */
  $('#btn-lmk-encrypt').addEventListener('click',       () => doLmkEncrypt().catch((e) => lmkLog(e.message, 'err')));
  $('#btn-lmk-reprovision').addEventListener('click',   () => doLmkReprovision().catch((e) => lmkLog(e.message, 'err')));
  $('#btn-lmk-decrypt-test').addEventListener('click',  () => doLmkDecryptTest().catch((e) => lmkLog(e.message, 'err')));

  $('#btn-demo-quick').addEventListener('click', () => demoRunFullAutomatic());
  $('#btn-demo-step').addEventListener('click', () =>
    demoNextStepManual().catch((e) => log(e.message, 'err')));
  $('#demo-reset-steps').addEventListener('click', resetDemoTour);
  $('#jump-setup').addEventListener('click', () => {
    $$('.tabs button').forEach((x) => x.classList.remove('active'));
    $$('.panel').forEach((x) => x.classList.remove('active'));
    const bt = $(".tabs button[data-panel='setup']");
    bt?.classList.add('active');
    $('#panel-setup').classList.add('active');
  });

  $$('.attack-chip[data-attack]').forEach((btn) => {
    btn.addEventListener('click', () => runAttack(btn.getAttribute('data-attack')));
  });

  refreshStatus().catch(() => {});
});
