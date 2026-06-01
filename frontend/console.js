/* Console technique HSM — LMK, fragments, logs */
const $ = (s, r = document) => r.querySelector(s);

const state = {
  api: localStorage.getItem('payhsm_api') || 'http://127.0.0.1:8765',
  pass: '',
  dataDir: localStorage.getItem('payhsm_data') || '/home/oussama/Desktop/softHSM_main/payhsm-data',
};

function lcd(lines) {
  const el = $('#hsm-lcd');
  if (!el) return;
  const txt = Array.isArray(lines) ? lines.join('\n') : String(lines);
  el.replaceChildren(document.createTextNode(txt));
  const c = document.createElement('span');
  c.className = 'lcd-cursor';
  el.appendChild(c);
}

function setLeds({ pwr = true, net = false, busy = false, fault = false, key = false } = {}) {
  const map = { pwr, net, busy, flt: fault, key };
  for (const [name, on] of Object.entries(map)) {
    const el = $(`.led[data-led="${name}"]`);
    if (!el) continue;
    el.classList.remove('off', 'ok', 'busy', 'alert');
    if (!on) el.classList.add('off');
    else if (name === 'busy') el.classList.add('busy');
    else if (name === 'flt') el.classList.add('alert');
    else el.classList.add('ok');
  }
}

function log(elId, msg, cls = '') {
  const el = $(elId);
  if (!el) return;
  const line = document.createElement('div');
  line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  el.prepend(line);
}

function saveCfg() {
  PayHsmApi.setBase(state.api);
  localStorage.setItem('payhsm_data', state.dataDir);
}

function lcStatus(elId, cls, msg) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.className = 'lifecycle-status ' + cls;
  el.textContent = msg;
}

function applyHeaderState(h, s = {}) {
  const ok = !!h?.initialized;
  $('#status-dot').className = 'status-dot ' + (ok ? 'status-unlocked' : 'status-locked');
  $('#status-label').textContent = ok
    ? `HSM actif · ${s.keyCount ?? '?'} clés`
    : 'HSM arrêté — Provision puis Démarrer';
  setLeds({ net: true, key: ok, pwr: true });
  lcd([
    ok ? 'LMK FRAGMENTED .... YES' : 'LMK FRAGMENTED .... NO',
    `KEYS IN VAULT ...... ${s.keyCount ?? '—'}`,
    `INTEGRITY ......... ${s.integrity ? 'OK' : '—'}`,
  ]);
}

async function refreshHeader() {
  const label = $('#status-label');
  if (label) label.textContent = 'Vérification API…';
  try {
    const h = await PayHsmApi.health();
    applyHeaderState(h, {});
    PayHsmApi.status()
      .then((s) => applyHeaderState(h, s))
      .catch(() => { /* status optionnel */ });
  } catch (e) {
    if (label) label.textContent = 'HSM injoignable';
    $('#status-dot').className = 'status-dot status-error';
    setLeds({ net: false, fault: true });
    lcd(['NETWORK ............. OFF', e.message.slice(0, 48)]);
  }
}

async function loadLmk() {
  const st = await PayHsmApi.lmkStatus();
  $('#lmk-status-json').textContent = JSON.stringify(st, null, 2);
}

async function loadFragments() {
  const f = await PayHsmApi.lmkFragments();
  const refEl = $('#frag-lmk-ref');
  if (f.lmkRefPrefix && f.lmkRefPrefix !== '--------') {
    refEl.hidden = false;
    const mut = f.mutationCount != null ? f.mutationCount : '—';
    refEl.innerHTML = `
      <span class="lmk-ref-label">Référence intégrité LMK</span>
      <span class="lmk-ref-hint">(stable tant que la LMK logique ne change pas — provision)</span>
      <code class="lmk-ref-code">${f.lmkRefPrefix}</code>
      <span class="lmk-ref-ok">${f.integrityOk ? '✓ intégrité OK' : '✗ intégrité'}</span>
      <span class="lmk-ref-hint">Mutations : <strong>${mut}</strong> (après chaque opération crypto)</span>`;
  } else {
    refEl.hidden = true;
    refEl.innerHTML = '';
  }
  const host = $('#frag-grid');
  host.innerHTML = '';
  for (const fr of f.fragments || []) {
    const card = document.createElement('div');
    card.className = 'frag-card';
    card.innerHTML = `
      <h3>${fr.id}</h3>
      <p>Zone : <strong>${fr.zone}</strong></p>
      <p>Chargé : ${fr.loaded ? 'oui' : 'non'}</p>
      <p class="fp">Empreinte fragment : <code>${fr.fingerprint}</code></p>`;
    host.appendChild(card);
  }
}

async function loadVault() {
  const v = await PayHsmApi.vault();
  const tbody = $('#vault-table tbody');
  tbody.innerHTML = '';
  const keys = v.keys || [];
  if (!keys.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="5" style="text-align:center;color:var(--muted);padding:.75rem">Coffre vide — initialisez le HSM puis utilisez A0 ou le Switch</td>';
    tbody.appendChild(tr);
    return;
  }
  for (const k of keys) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${k.id}</code></td><td>${k.type}</td><td>${k.terminal || '—'}</td><td><code>${k.kcv}</code></td><td style="color:var(--muted);font-size:.8em">🔒 LMK</td>`;
    tbody.appendChild(tr);
  }
}

async function loadSecurityLogs() {
  const r = await PayHsmApi.securityLogs();
  const el = $('#security-log');
  el.innerHTML = '';
  for (const entry of (r.logs || []).slice().reverse()) {
    const d = new Date(entry.ts * 1000).toLocaleString();
    const line = document.createElement('div');
    line.textContent = `${d} — ${entry.message}`;
    el.appendChild(line);
  }
}

const $$ = (s, r = document) => [...r.querySelectorAll(s)];

function initTabs() {
  $('#tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-panel]');
    if (!btn) return;
    $$('#tabs button').forEach((b) => b.classList.toggle('active', b === btn));
    $$('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${btn.dataset.panel}`));
    if (btn.dataset.panel === 'vault') loadVault().catch(() => {});
  });
}

/* ══════════════════════════════════════════════
   Vérificateur de force de passphrase
   ══════════════════════════════════════════════ */
function checkPassStrength(pass) {
  const p = pass.toLowerCase();

  function hasSimpleSeq() {
    const runs = ['01234','12345','23456','34567','45678','56789',
                  'abcde','bcdef','cdefg','defgh',
                  'qwerty','azerty','asdfg','zxcvb',
                  'password','motdepasse','passphrase'];
    for (const s of runs) if (p.includes(s)) return true;
    if (/(.)\1{3,}/.test(pass)) return true;   /* 4+ mêmes chars */
    return false;
  }

  function hasCommonPattern() {
    if (/\d{7,}/.test(pass)) return true;                      /* téléphone */
    if (/(19|20)\d{2}/.test(pass)) return true;                /* année */
    if (/\d{2}[\/\-\.]\d{2}/.test(pass)) return true;         /* JJ/MM */
    const words = [
      'admin','root','user','test','guest','login',
      'payhsm','hsm','bank','banque','switch','payment',
      'jean','pierre','ahmed','ali','mohamed','sara','karim',
      'paris','france','maroc','algerie','tunisie',
      'esi','insat','fst','ensias','insea','iset',
      '2023','2024','2025','2026',
    ];
    for (const w of words) if (p.includes(w)) return true;
    return false;
  }

  return {
    len16:    pass.length >= 16,
    len20:    pass.length >= 20,
    upper:    /[A-Z]/.test(pass),
    lower:    /[a-z]/.test(pass),
    digit:    /[0-9]/.test(pass),
    symbol:   /[^A-Za-z0-9]/.test(pass),
    noSeq:    !hasSimpleSeq(),
    noCommon: !hasCommonPattern(),
  };
}

function renderPassStrength(inp, wrap) {
  const pass = inp.value;
  if (!pass) { wrap.classList.remove('visible'); return; }
  wrap.classList.add('visible');

  const c = checkPassStrength(pass);
  const required = [c.len16, c.upper, c.lower, c.digit, c.symbol, c.noSeq, c.noCommon];
  const score = required.filter(Boolean).length + (c.len20 ? 1 : 0); /* 0–8 */

  const pct   = Math.round((score / 8) * 100);
  const color = score <= 2 ? '#ef4444'
              : score <= 4 ? '#f97316'
              : score <= 5 ? '#eab308'
              : score <= 6 ? '#84cc16'
              : '#22c55e';
  const label = score <= 2 ? 'Très faible'
              : score <= 4 ? 'Faible'
              : score <= 5 ? 'Moyen'
              : score <= 6 ? 'Fort'
              : 'Très fort';

  const cls = (ok) => ok ? 'ok' : 'fail';
  const lenCls = c.len16 ? (c.len20 ? 'ok' : 'warn') : 'fail';
  const lenTxt = c.len20 ? '20–32 caractères ✓'
               : c.len16 ? `${pass.length} car. — 20 recommandé`
               : `${pass.length} car. — min. 16`;

  wrap.innerHTML = `
    <div class="pass-strength-header">
      <span class="pass-strength-label" style="color:${color}">${label}</span>
      <span class="pass-strength-chars">${pass.length} car.</span>
    </div>
    <div class="pass-strength-track">
      <div class="pass-strength-fill" style="width:${pct}%;background:${color}"></div>
    </div>
    <ul class="pass-rules">
      <li class="pass-rule ${lenCls}">${lenTxt}</li>
      <li class="pass-rule ${cls(c.upper)}">Majuscule (A–Z)</li>
      <li class="pass-rule ${cls(c.lower)}">Minuscule (a–z)</li>
      <li class="pass-rule ${cls(c.digit)}">Chiffre (0–9)</li>
      <li class="pass-rule ${cls(c.symbol)}">Symbole (!@#…)</li>
      <li class="pass-rule ${cls(c.noSeq)}">Pas de suite simple</li>
      <li class="pass-rule ${cls(c.noCommon)}">Pas de date/tél/école</li>
      <li class="pass-rule ${cls(c.noCommon && c.noSeq)}">Pas de mot courant</li>
    </ul>`;
}

function initPassStrength(inputId, wrapId) {
  const inp  = document.getElementById(inputId);
  const wrap = document.getElementById(wrapId);
  if (!inp || !wrap) return;
  inp.addEventListener('input', () => renderPassStrength(inp, wrap));
}

async function refreshMkStatus(dir, bannerId = 'mk-status-banner') {
  const banner = document.getElementById(bannerId);
  if (!banner) return;
  try {
    const r = await PayHsmApi.mkStatus(dir || '');
    if (r.mkExists) {
      banner.className = 'shamir-status-banner shamir-status-ok';
      const s = r.sharesReady
        ? ' — parts SSS générées ✓'
        : ' — parts SSS non encore générées';
      banner.textContent = `✓ mk.bin présent${s}`;
    } else {
      banner.className = 'shamir-status-banner shamir-status-err';
      banner.textContent = '✗ mk.bin absent — générer la MK d\'abord (Étape 0)';
    }
  } catch (e) {
    banner.className = 'shamir-status-banner shamir-status-unknown';
    banner.textContent = `Statut indisponible : ${e.message}`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  lcd(['PAYHSM-1 MODULE', 'BOOT ............. OK', 'NETWORK ........... SYNC', '> GET /api/health', 'WAIT ...']);
  setLeds({ pwr: true, net: false, busy: true });
  PayHsmApi.setBase(state.api);
  initTabs();

  /* ── Cycle de vie — Provisionnement ── */
  $('#btn-provision').onclick = async () => {
    saveCfg();
    if (!state.dataDir) { lcStatus('status-provision', 'lc-err', 'Répertoire données manquant'); return; }
    lcStatus('status-provision', 'lc-pending', 'Provisionnement en cours…');
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.provision(state.dataDir);
      lcStatus('status-provision', r.rc === 0 ? 'lc-ok' : 'lc-err', r.message);
      if (r.rc === 0) await refreshHeader();
    } catch (e) {
      lcStatus('status-provision', 'lc-err', `Erreur de provisionnement : ${e.message}`);
    }
    setLeds({ busy: false });
  };

  /* ── Cycle de vie — Démarrage HSM ── */
  $('#btn-startup').onclick = async () => {
    saveCfg();
    lcStatus('status-startup', 'lc-pending', 'Démarrage en cours…');
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.startup();
      if (r.rc === 0) {
        lcStatus('status-startup', 'lc-ok', r.message);
      } else if (r.rc === -2) {
        lcStatus('status-startup', 'lc-warn', r.message);
      } else {
        lcStatus('status-startup', 'lc-err', `Échec du démarrage : ${r.message}`);
      }
      await refreshHeader();
    } catch (e) {
      lcStatus('status-startup', 'lc-err', `Échec du démarrage : ${e.message}`);
    }
    setLeds({ busy: false });
  };

  /* ── Cycle de vie — Extinction ── */
  $('#btn-shutdown').onclick = async () => {
    lcStatus('status-startup', 'lc-pending', 'Extinction en cours…');
    try {
      await PayHsmApi.shutdown();
      lcStatus('status-startup', 'lc-warn', 'HSM arrêté');
      await refreshHeader();
    } catch (e) {
      lcStatus('status-startup', 'lc-err', e.message);
    }
  };

  $('#btn-lmk-refresh').onclick = () => loadLmk().catch((e) => alert(e.message));
  $('#btn-frag-refresh').onclick = () => loadFragments().catch((e) => alert(e.message));
  $('#btn-vault-refresh').onclick = () => loadVault().catch((e) => alert(e.message));
  $('#btn-logs-refresh').onclick = () => loadSecurityLogs().catch((e) => alert(e.message));

  /* ── Indicateurs force passphrase + confirmation ── */
  initPassStrength('mk-gen-pass', 'pstr-mkgen');
  initPassStrength('shamir-gen-pass', 'pstr-shamirgen');

  const passConfirmEl = document.getElementById('mk-gen-pass-confirm');
  const passMatchEl   = document.getElementById('mk-gen-pass-match');
  function checkPassMatch() {
    const p1 = document.getElementById('mk-gen-pass').value;
    const p2 = passConfirmEl.value;
    if (!p2) { passMatchEl.className = 'pass-match-hint'; passMatchEl.textContent = ''; return; }
    if (p1 === p2) {
      passMatchEl.className = 'pass-match-hint pass-match-ok';
      passMatchEl.textContent = '✓ Les mots de passe correspondent';
    } else {
      passMatchEl.className = 'pass-match-hint pass-match-err';
      passMatchEl.textContent = '✗ Les mots de passe ne correspondent pas';
    }
  }
  if (passConfirmEl) {
    passConfirmEl.addEventListener('input', checkPassMatch);
    document.getElementById('mk-gen-pass').addEventListener('input', checkPassMatch);
  }

  /* ── T0 : Générer la LMK (TRNG) ── */
  $('#btn-mk-gen').onclick = async () => {
    const pass    = document.getElementById('mk-gen-pass').value;
    const confirm = document.getElementById('mk-gen-pass-confirm').value;
    const dir     = document.getElementById('mk-gen-dir').value.trim();
    if (!pass)    { log('#mk-gen-log', 'Mot de passe requis.', 'err'); return; }
    if (!confirm) { log('#mk-gen-log', 'Confirmation du mot de passe requise.', 'err'); return; }
    if (pass !== confirm) { log('#mk-gen-log', 'Les mots de passe ne correspondent pas.', 'err'); return; }
    if (!dir)     { log('#mk-gen-log', 'Répertoire requis.', 'err'); return; }
    const c = checkPassStrength(pass);
    const required = [c.len16, c.upper, c.lower, c.digit, c.symbol, c.noSeq, c.noCommon];
    if (!required.every(Boolean)) {
      log('#mk-gen-log', 'Mot de passe trop faible — respectez toutes les règles de sécurité.', 'err');
      return;
    }
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.mkGenerate(pass, dir);
      log('#mk-gen-log', r.message, r.rc === 0 ? 'ok' : 'err');
      if (r.rc === 0) await refreshMkStatus(dir);
    } catch (e) { log('#mk-gen-log', e.message, 'err'); }
    setLeds({ busy: false });
  };

  $('#btn-mk-status').onclick = async () => {
    const dir = document.getElementById('mk-gen-dir').value.trim();
    await refreshMkStatus(dir);
  };

  /* ── T1 : Générer les parts SSS ── */
  $('#btn-shamir-gen').onclick = async () => {
    const pass = document.getElementById('shamir-gen-pass').value;
    const dir  = document.getElementById('shamir-gen-dir').value.trim();
    if (!pass) { log('#shamir-gen-log', 'Passphrase requise.', 'err'); return; }
    if (!dir)  { log('#shamir-gen-log', 'Répertoire requis.', 'err'); return; }
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.shamirGenerate(pass, dir);
      if (r.rc !== 0) { log('#shamir-gen-log', r.message, 'err'); return; }
      document.getElementById('shamir-gen-files').style.display = 'block';
      log('#shamir-gen-log',
        `Parts LMK générées : lmk_share_1/2/3.sss dans ${dir}`, 'ok');
    } catch (e) { log('#shamir-gen-log', e.message, 'err'); }
    setLeds({ busy: false });
  };

  /* ── SSS : Lecteur de fichiers .sss ── */
  function readSssFile(input) {
    return new Promise((resolve) => {
      const file = input.files[0];
      if (!file) { resolve(''); return; }
      const reader = new FileReader();
      reader.onload  = (e) => resolve(e.target.result.trim());
      reader.onerror = ()  => resolve('');
      reader.readAsText(file);
    });
  }

  function updateSssFileBanner() {
    const ok1 = !!document.getElementById('sss-file-1').files[0];
    const ok2 = !!document.getElementById('sss-file-2').files[0];
    const ok3 = !!document.getElementById('sss-file-3').files[0];
    const count = [ok1, ok2, ok3].filter(Boolean).length;
    const banner = document.getElementById('sss-files-ok-banner');
    const btn    = document.getElementById('btn-shamir-rec');
    if (count === 3) {
      banner.className = 'shamir-status-banner shamir-status-ok';
      banner.textContent = '✓ 3 fichiers SSS sélectionnés — reconstruction possible';
      btn.disabled = false;
    } else {
      banner.className = 'shamir-status-banner shamir-status-unknown';
      banner.textContent = `${count}/3 fichier(s) sélectionné(s) — sélectionnez les 3 parts SSS`;
      btn.disabled = true;
    }
  }

  function setSssStatus(n, ok, text) {
    const el = document.getElementById(`sss-status-${n}`);
    if (!el) return;
    el.className = 'sss-file-status ' + (ok ? 'ok' : 'err');
    el.textContent = text;
  }

  [1, 2, 3].forEach((n) => {
    const inp = document.getElementById(`sss-file-${n}`);
    if (!inp) return;
    inp.addEventListener('change', async () => {
      const file = inp.files[0];
      if (!file) { setSssStatus(n, false, '—'); updateSssFileBanner(); return; }
      const content = await readSssFile(inp);
      const valid = /^[0-9a-fA-F]{66}$/.test(content);
      setSssStatus(n, valid,
        valid ? `✓ ${file.name}` : `✗ Format invalide`);
      updateSssFileBanner();
    });
  });

  /* ── SSS : Reconstruction LMK + init HSM ── */
  $('#btn-shamir-rec').onclick = async () => {
    const dir = document.getElementById('shamir-rec-dir').value.trim();
    if (!dir) { log('#shamir-rec-log', 'Répertoire requis.', 'err'); return; }
    const [s1, s2, s3] = await Promise.all([
      readSssFile(document.getElementById('sss-file-1')),
      readSssFile(document.getElementById('sss-file-2')),
      readSssFile(document.getElementById('sss-file-3')),
    ]);
    if (!s1 || !s2 || !s3) { log('#shamir-rec-log', 'Sélectionnez les 3 fichiers .sss.', 'err'); return; }
    if (!/^[0-9a-fA-F]{66}$/.test(s1) || !/^[0-9a-fA-F]{66}$/.test(s2) || !/^[0-9a-fA-F]{66}$/.test(s3)) {
      log('#shamir-rec-log', 'Un ou plusieurs fichiers sont invalides (format attendu : 66 hex).', 'err');
      return;
    }
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.shamirReconstruct(dir, s1, s2, s3);
      if (r.rc !== 0) { log('#shamir-rec-log', r.message, 'err'); return; }
      log('#shamir-rec-log', r.message, 'ok');
      await refreshHeader();
    } catch (e) { log('#shamir-rec-log', e.message, 'err'); }
    setLeds({ busy: false });
  };

  /* ── Méthode TRNG / SSS — bascule d'onglet ── */
  document.getElementById('btn-method-trng').onclick = () => {
    document.getElementById('section-trng').style.display = '';
    document.getElementById('section-sss').style.display  = 'none';
    document.getElementById('btn-method-trng').classList.add('active');
    document.getElementById('btn-method-sss').classList.remove('active');
  };
  document.getElementById('btn-method-sss').onclick = () => {
    document.getElementById('section-trng').style.display = 'none';
    document.getElementById('section-sss').style.display  = '';
    document.getElementById('btn-method-sss').classList.add('active');
    document.getElementById('btn-method-trng').classList.remove('active');
  };

  /* ── Mutation en fin de session (fermeture / navigation hors page) ── */
  const mutateOnSessionEnd = () => {
    navigator.sendBeacon('/api/lmk/mutate', new Blob(['{}'], { type: 'application/json' }));
  };
  window.addEventListener('pagehide',         mutateOnSessionEnd, { once: false });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') mutateOnSessionEnd();
  });

  async function doManualMutate(statusElId, refreshFn) {
    const el = document.getElementById(statusElId);
    if (el) { el.style.display = ''; lcStatus(statusElId, 'lc-pending', '⟳ Mutation en cours…'); }
    try {
      await PayHsmApi.mutateFragments();
      const ts = new Date().toLocaleTimeString();
      if (el) lcStatus(statusElId, 'lc-ok', `✓ Fragments mutés manuellement — ${ts}`);
      if (refreshFn) await refreshFn();
    } catch (e) {
      if (el) lcStatus(statusElId, 'lc-err', `✗ Échec : ${e.message}`);
    }
  }

  document.getElementById('btn-lmk-mutate').onclick =
    () => doManualMutate('mutate-status', loadFragments);

  const btnFragMutate = document.getElementById('btn-frag-mutate');
  if (btnFragMutate) btnFragMutate.onclick =
    () => doManualMutate('frag-mutate-status', loadFragments);

  refreshHeader();
  setInterval(refreshHeader, 15000);
});

/* ══════════════════════════════════════════════
   Terminal HSM — moteur de commandes interactif
   ══════════════════════════════════════════════ */
function createHsmTerminal(outSel, inSel, clearSel) {
  const termOut = $(outSel);
  const termIn  = $(inSel);
  if (!termOut || !termIn) return;

  const cmdHistory = [];
  let histIdx = -1;
  const vars  = {};   /* $1, $zpk, $zmk … → valeur stockée */
  let varCnt  = 0;

  /* ── Affichage ── */
  function tLine(html, cls = '') {
    const d = document.createElement('div');
    if (cls) d.className = cls;
    d.innerHTML = html;
    termOut.appendChild(d);
  }

  function tRow(label, value, cls = 't-ok') {
    const pad = label.padEnd(18);
    tLine(`  <span class="t-muted">${pad}</span><span class="${cls}" style="word-break:break-all">${value}</span>`);
  }

  function tEcho(cmd) {
    tLine(`<span class="t-cmd">HSM&gt; ${cmd}</span>`);
  }

  function tScroll() {
    termOut.scrollTop = termOut.scrollHeight;
  }

  /* ── Variables ── */
  function storeVar(value, alias) {
    varCnt++;
    const k = `$${varCnt}`;
    vars[k] = value;
    if (alias) vars[`$${alias}`] = value;
    return k;
  }

  function resolve(tok) {
    if (tok && tok.startsWith('$')) return vars[tok] ?? null;
    return tok;
  }

  /* ── Commandes ── */
  function showHelp() {
    tLine('<span class="t-info">╔══ Commandes PayHSM Terminal ══════════════════════╗</span>');
    const cmds = [
      ['health',                         'Tester la connexion au HSM'],
      ['status',                         'Statut HSM (nb clés, intégrité)'],
      ['lmk',                            'Statut LMK (fragments, mutations)'],
      ['fragments',                      'Détail empreintes P1 / P2 / P3'],
      ['vault',                          'Liste des clés du coffre (KCV)'],
      ['logs',                           'Journal sécurité (20 dernières lignes)'],
      ['mutate',                         'Mutation manuelle des fragments LMK'],
      ['─────────────────────────────', '──────────────────────────────────────────'],
      ['A0 [type] [16|24|32]',            'Générer une clé sous LMK → $N / $type'],
      ['A6 <$zmk> <key32hex> [type]',    'Importer clé ZMK→LMK (re-chiffrement)'],
      ['A8 <$cle> [H|V] [type]',         'Consulter KCV (H=KCV seul, V=clair+KCV)'],
      ['GEN',                            'Générer 16 octets aléatoires → $rawkey'],
      ['WRAP <$zmk> <$rawkey> [type]',   'Chiffrer clé sous ZMK (pour A6) → $enc'],
      ['─────────────────────────────', '──────────────────────────────────────────'],
      ['vars',                           'Afficher toutes les variables stockées'],
      ['clear / cls',                    'Effacer le terminal'],
      ['─────────────────────────────', '──────────────────────────────────────────'],
      ['0001A01001U  (ou tout hex)',      'Protocole wire Thales brut (A0/A6/A8)'],
    ];
    for (const [cmd, desc] of cmds) {
      if (cmd.startsWith('─')) {
        tLine(`  <span class="t-muted">${cmd}</span>`);
      } else {
        tLine(`  <span class="t-cmd">${cmd.padEnd(32)}</span><span class="t-muted">${desc}</span>`);
      }
    }
    tLine('<span class="t-info">╚═══════════════════════════════════════════════════╝</span>');
    tLine(`  <span class="t-muted">Types de clés : ZMK · ZPK · TMK · TPK · TAK · PVK · IMK</span>`);
    tLine(`  <span class="t-muted">Flux typique : <span class="t-cmd">A0 ZMK</span> → <span class="t-cmd">GEN</span> → <span class="t-cmd">WRAP $zmk $rawkey ZPK</span> → <span class="t-cmd">A6 $zmk $enc ZPK</span> → <span class="t-cmd">A8 $zpk H</span></span>`);
  }

  async function runCmd(raw) {
    const parts = raw.trim().split(/\s+/);
    const verb  = parts[0].toUpperCase();

    /* ── Protocole wire Thales brut : ex. "0001A01001U" ── */
    if (/^[0-9A-Fa-f]{4}[Aa][0-9A-Fa-f]/i.test(parts[0])) {
      tLine(`<span class="t-muted">→ POST /api/hsm/cmd  { cmd: "${parts[0]}" }</span>`);
      try {
        const r = await PayHsmApi.hsmCmd(parts[0]);
        if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); return; }
        tRow('rawResponse', r.rawResponse ?? '—', 't-warn');
        if (r.kcv)        tRow('KCV',        r.kcv,        't-ok');
        if (r.cryptogram) {
          const k = storeVar(r.cryptogram, r.keyType ? r.keyType.toLowerCase() : undefined);
          tRow('cryptogram', r.cryptogram.slice(0, 44) + '…', 't-warn');
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span>`);
        }
        if (r.keyClear)   tRow('keyClear',   r.keyClear,   't-err');
        tLine('<span class="t-ok">✓ Commande wire OK</span>');
      } catch (e) {
        tLine(`<span class="t-err">✗ ${e.message}</span>`);
      }
      tScroll();
      return;
    }

    switch (verb) {

      case 'HELP': case '?':
        showHelp();
        break;

      case 'CLEAR': case 'CLS':
        termOut.innerHTML = '';
        break;

      case 'VARS': {
        const keys = Object.keys(vars);
        if (!keys.length) { tLine('<span class="t-muted">Aucune variable.</span>'); break; }
        tLine('<span class="t-info">── Variables ──</span>');
        for (const [k, v] of Object.entries(vars)) {
          const disp = v.length > 48 ? v.slice(0, 48) + '…' : v;
          tRow(k, disp, 't-warn');
        }
        break;
      }

      case 'HEALTH': {
        tLine('<span class="t-muted">→ GET /api/health</span>');
        try {
          const r = await PayHsmApi.health();
          tRow('initialized', r.initialized ? 'OUI' : 'NON', r.initialized ? 't-ok' : 't-err');
          if (r.apiVersion) tRow('apiVersion', r.apiVersion, 't-info');
          tLine(r.initialized
            ? '<span class="t-ok">✓ HSM joignable et démarré</span>'
            : '<span class="t-warn">⚠ HSM joignable mais non démarré</span>');
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      case 'STATUS': {
        tLine('<span class="t-muted">→ GET /api/status</span>');
        try {
          const r = await PayHsmApi.status();
          tRow('initialized', r.initialized ? 'OUI' : 'NON', r.initialized ? 't-ok' : 't-err');
          tRow('keyCount',    String(r.keyCount ?? '—'), 't-info');
          tRow('integrity',   r.integrity ? 'OK' : 'KO',    r.integrity ? 't-ok' : 't-err');
          for (const k of r.keys ?? []) {
            tRow(`  ${k.id} (${k.type})`, `KCV=${k.kcv}  terminal=${k.terminal || '—'}`, 't-muted');
          }
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      case 'LMK': {
        tLine('<span class="t-muted">→ GET /api/lmk/status</span>');
        try {
          const r = await PayHsmApi.lmkStatus();
          tRow('fragmented',    r.fragmented    ? 'OUI' : 'NON', r.fragmented    ? 't-ok'  : 't-err');
          tRow('integrityOk',   r.integrityOk   ? 'OK'  : 'KO',  r.integrityOk   ? 't-ok'  : 't-err');
          tRow('mutationCount', String(r.mutationCount ?? '—'), 't-info');
          tRow('hmacRefPrefix', r.hmacRefPrefix ?? '—',           't-warn');
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      case 'FRAGMENTS': {
        tLine('<span class="t-muted">→ GET /api/lmk/fragments</span>');
        try {
          const r = await PayHsmApi.lmkFragments();
          tRow('lmkRefPrefix', r.lmkRefPrefix ?? '—', 't-warn');
          tRow('integrityOk',  r.integrityOk ? 'OK' : 'KO', r.integrityOk ? 't-ok' : 't-err');
          tRow('mutations',    String(r.mutationCount ?? '—'), 't-info');
          for (const f of r.fragments ?? []) {
            tRow(`  ${f.id}`, `zone=${f.zone}  fingerprint=${f.fingerprint}`, 't-info');
          }
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      case 'VAULT': {
        tLine('<span class="t-muted">→ GET /api/vault</span>');
        try {
          const r = await PayHsmApi.vault();
          const keys = r.keys ?? [];
          if (!keys.length) { tLine('<span class="t-muted">Coffre vide.</span>'); break; }
          tLine(`  <span class="t-info">${keys.length} clé(s) dans le coffre :</span>`);
          for (const k of keys) {
            tRow(`  ${k.id}`, `type=${k.type}  terminal=${k.terminal || '—'}  KCV=${k.kcv}`, 't-info');
          }
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      case 'LOGS': {
        tLine('<span class="t-muted">→ GET /api/security/logs</span>');
        try {
          const r = await PayHsmApi.securityLogs();
          const entries = (r.logs ?? []).slice(-20).reverse();
          if (!entries.length) { tLine('<span class="t-muted">Aucun log.</span>'); break; }
          for (const e of entries) {
            const d = new Date(e.ts * 1000).toLocaleTimeString();
            tLine(`  <span class="t-muted">${d}</span>  <span class="t-info">${e.message}</span>`);
          }
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      case 'MUTATE': {
        tLine('<span class="t-muted">→ POST /api/lmk/mutate</span>');
        try {
          const r = await PayHsmApi.mutateFragments();
          tLine(r.rc === 0
            ? '<span class="t-ok">✓ Mutation fragments LMK OK</span>'
            : `<span class="t-err">✗ ${r.message}</span>`);
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ── A0 : Générer une clé ── */
      case 'A0': {
        const kt  = parts[1] ?? 'ZMK';
        const klRaw = parseInt(parts[2] ?? '16', 10);
        const kl  = [16, 24, 32].includes(klRaw) ? klRaw : 16;
        if (![16, 24, 32].includes(klRaw) && parts[2]) {
          tLine(`<span class="t-warn">⚠ Taille "${parts[2]}" invalide — utilisé 16 par défaut (valeurs: 16, 24, 32)</span>`);
        }
        tLine(`<span class="t-muted">→ POST /api/hsm/a0  { keyType: "${kt}", keyLen: ${kl} }</span>`);
        try {
          const r = await PayHsmApi.hsmA0(kt, kl);
          if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
          const k = storeVar(r.cryptogram, kt.toLowerCase());
          tRow('keyType',    r.keyType,                             't-info');
          tRow('keyLen',     `${r.keyLen ?? kl} octets (AES-${(r.keyLen ?? kl) * 8})`, 't-info');
          tRow('KCV',        r.kcv,                                 't-ok');
          tRow('cryptogram', r.cryptogram.slice(0, 44) + '…',      't-warn');
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span><span class="t-muted"> et </span><span class="t-cmd">$${kt.toLowerCase()}</span>`);
          tLine(`<span class="t-ok">✓ A0 OK — clé AES-${(r.keyLen ?? kl) * 8} générée sous LMK (${r.cryptogram.length} hex chars)</span>`);
          if (kl === 16) {
            await loadVault();
            tLine(`<span class="t-muted">  → coffre mis à jour (onglet Coffre)</span>`);
          }
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ── A6 : Importer une clé (ZMK → LMK) ── */
      case 'A6': {
        const rawZmk    = parts[1] ?? '';
        const rawKeyEnc = parts[2] ?? '';
        const kt        = parts[3] ?? 'ZPK';
        const zmkCrypt  = resolve(rawZmk);
        const keyEncHex = resolve(rawKeyEnc);

        if (!zmkCrypt || !keyEncHex) {
          tLine('<span class="t-err">Usage : A6 &lt;$zmk&gt; &lt;key32hex&gt; [type]</span>');
          tLine('<span class="t-muted">  $zmk      : cryptogramme ZMK (88 hex) — issu de A0 ZMK</span>');
          tLine('<span class="t-muted">  key32hex  : clé 16 octets chiffrée sous ZMK (32 hex) — issu de WRAP</span>');
          tLine('<span class="t-muted">Flux : <span class="t-cmd">A0 ZMK</span> → <span class="t-cmd">GEN</span> → <span class="t-cmd">WRAP $zmk $rawkey ZPK</span> → <span class="t-cmd">A6 $zmk $enc ZPK</span></span>');
          break;
        }

        tLine(`<span class="t-muted">→ POST /api/hsm/a6  { zmkCryptogram, keyUnderZmk, keyType: "${kt}" }</span>`);
        try {
          const r = await PayHsmApi.hsmA6(zmkCrypt, keyEncHex, kt);
          if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
          const k = storeVar(r.cryptogram, kt.toLowerCase());
          tRow('keyType',    r.keyType,                         't-info');
          tRow('schéma',     r.scheme ?? 'U',                   't-info');
          tRow('KCV',        r.kcv,                             't-ok');
          tRow('cryptogram', r.cryptogram.slice(0, 44) + '…',  't-warn');
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span><span class="t-muted"> et </span><span class="t-cmd">$${kt.toLowerCase()}</span>`);
          tLine('<span class="t-ok">✓ A6 OK — clé importée et rechiffrée sous LMK</span>');
          await loadVault();
          tLine(`<span class="t-muted">  → coffre mis à jour (onglet Coffre)</span>`);
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ── A8 : Consulter KCV d'une clé sous LMK ── */
      case 'A8': {
        const rawCle = parts[1] ?? '';
        const flag   = (parts[2] ?? 'H').toUpperCase();
        const kt     = parts[3] ?? 'ZPK';
        const keyCrypt = resolve(rawCle);

        if (!keyCrypt) {
          tLine('<span class="t-err">Usage : A8 &lt;$cle&gt; [H|V] [type]</span>');
          tLine('<span class="t-muted">  H (défaut) : KCV seulement (production)</span>');
          tLine('<span class="t-muted">  V          : clé en clair + KCV  ⚠ maintenance uniquement</span>');
          tLine('<span class="t-muted">Exemple : <span class="t-cmd">A8 $zpk H ZPK</span></span>');
          break;
        }

        tLine(`<span class="t-muted">→ POST /api/hsm/a8  { flag: "${flag}", keyType: "${kt}", … }</span>`);
        try {
          const r = await PayHsmApi.hsmA8(keyCrypt, flag, kt);
          if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
          tRow('keyType', r.keyType ?? kt,         't-info');
          tRow('flag',    r.flag    ?? flag,        't-info');
          tRow('KCV',     r.kcv,                   't-ok');
          if (r.keyLen) tRow('keyLen', `${r.keyLen} octets`, 't-info');
          if (r.keyClear) {
            tRow('keyClear ⚠', r.keyClear, 't-err');
            tLine('  <span class="t-warn">⚠ SENSIBLE — clé en clair (flag V)</span>');
          }
          tLine('<span class="t-ok">✓ A8 OK — consultation KCV</span>');
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ── GEN : Générer 16 octets aléatoires (clé en clair) ── */
      case 'GEN': {
        const buf = new Uint8Array(16);
        crypto.getRandomValues(buf);
        const hex = Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
        const k = storeVar(hex, 'rawkey');
        tRow('rawkey (32 hex)', hex, 't-warn');
        tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span><span class="t-muted"> et </span><span class="t-cmd">$rawkey</span>`);
        tLine('<span class="t-ok">✓ GEN OK — 16 octets aléatoires (à chiffrer sous ZMK via WRAP avant import)</span>');
        break;
      }

      /* ── WRAP : Chiffrer une clé 16 octets sous ZMK (AES-ECB) ── */
      case 'WRAP': {
        const rawZmk    = parts[1] ?? '';
        const rawKeyHex = parts[2] ?? '';
        const kt        = parts[3] ?? 'ZPK';
        const zmkCrypt  = resolve(rawZmk);
        const keyHex    = resolve(rawKeyHex);

        if (!zmkCrypt || !keyHex) {
          tLine('<span class="t-err">Usage : WRAP &lt;$zmk&gt; &lt;$rawkey&gt; [type]</span>');
          tLine('<span class="t-muted">  $zmk    : cryptogramme ZMK sous LMK (88 hex) — issu de A0 ZMK</span>');
          tLine('<span class="t-muted">  $rawkey : clé 16 octets en clair (32 hex) — issu de GEN</span>');
          tLine('<span class="t-muted">Retourne $enc (32 hex) à passer à A6</span>');
          break;
        }

        tLine(`<span class="t-muted">→ POST /api/switch/wrap-zpk  { zmkCryptogram, keyHex }</span>`);
        try {
          const r = await PayHsmApi.wrapZpk(zmkCrypt, keyHex);
          if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
          const k = storeVar(r.keyUnderZmk, 'enc');
          tRow('keyUnderZmk', r.keyUnderZmk, 't-warn');
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span><span class="t-muted"> et </span><span class="t-cmd">$enc</span>`);
          tLine(`<span class="t-ok">✓ WRAP OK — clé chiffrée sous ZMK, prête pour A6 $zmk $enc ${kt}</span>`);
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      default:
        tLine(`<span class="t-err">Commande inconnue : "${parts[0]}"</span>  →  tapez <span class="t-cmd">help</span>`);
    }

    tScroll();
  }

  /* ── Clavier ── */
  termIn.addEventListener('keydown', async (ev) => {
    if (ev.key === 'Enter') {
      const raw = termIn.value.trim();
      if (!raw) return;
      cmdHistory.unshift(raw);
      histIdx = -1;
      termIn.value = '';
      tEcho(raw);
      await runCmd(raw);
    } else if (ev.key === 'ArrowUp') {
      ev.preventDefault();
      if (histIdx < cmdHistory.length - 1) histIdx++;
      termIn.value = cmdHistory[histIdx] ?? '';
    } else if (ev.key === 'ArrowDown') {
      ev.preventDefault();
      if (histIdx > 0) { histIdx--; termIn.value = cmdHistory[histIdx]; }
      else { histIdx = -1; termIn.value = ''; }
    } else if (ev.key === 'Tab') {
      ev.preventDefault();
      /* Auto-complétion basique sur le verbe */
      const v = termIn.value.trim().toUpperCase();
      const all = ['HEALTH','STATUS','LMK','FRAGMENTS','VAULT','LOGS','MUTATE','A0','A6','A8','GEN','WRAP','VARS','CLEAR'];
      const match = all.filter(c => c.startsWith(v));
      if (match.length === 1) termIn.value = match[0] + ' ';
    }
  });

  /* ── Bouton Effacer ── */
  if (clearSel) $(clearSel).addEventListener('click', () => { termOut.innerHTML = ''; });

  /* ── Focus auto quand on clique dans la zone de sortie ── */
  termOut.addEventListener('click', () => termIn.focus());

  /* ── Message d'accueil ── */
  tLine('<span class="t-info">╔══ PayHSM Terminal ════════════════════════════════╗</span>');
  tLine('<span class="t-info">║  Thales-style HSM command interface              ║</span>');
  tLine('<span class="t-info">╚════════════════════════════════════════════════════╝</span>');
  tLine('<span class="t-muted">Tapez <span class="t-cmd">help</span> pour la liste · <span class="t-cmd">↑↓</span> historique · <span class="t-cmd">Tab</span> auto-complétion</span>');
  tLine('<span class="t-muted">Flux : <span class="t-cmd">A0 ZMK</span> → <span class="t-cmd">GEN</span> → <span class="t-cmd">WRAP $zmk $rawkey ZPK</span> → <span class="t-cmd">A6 $zmk $enc ZPK</span> → <span class="t-cmd">A8 $zpk H</span></span>');
  tLine('');
  termIn.focus();
}

/* ── Instances : onglet Terminal + fenêtre flottante ── */
createHsmTerminal('#float-term-output', '#float-term-input', '#btn-float-clr');

/* ════════════════════════════════════════════════
   Fenêtre flottante HSM Terminal
   ════════════════════════════════════════════════ */
(function initFloatWin() {
  const win  = $('#float-term');
  const bar  = $('#float-term-bar');
  const tBtn = $('#btn-open-float-term');
  if (!win) return;

  const showWin = () => {
    win.style.display = 'flex';
    win.classList.remove('minimized');
    $('#float-term-input').focus();
  };
  const hideWin = () => { win.style.display = 'none'; };

  /* Toggle affichage */
  if (tBtn) {
    tBtn.addEventListener('click', () => {
      win.style.display === 'none' ? showWin() : hideWin();
    });
  }

  /* Fermer */
  const btnClose = $('#btn-float-close');
  if (btnClose) btnClose.addEventListener('click', () => hideWin());

  /* Réduire / restaurer */
  const btnMin = $('#btn-float-min');
  if (btnMin) btnMin.addEventListener('click', () => win.classList.toggle('minimized'));

  /* Drag depuis la barre de titre */
  if (bar) {
    let dragging = false, ox = 0, oy = 0;
    bar.addEventListener('mousedown', (e) => {
      if (e.target.closest('button')) return;
      dragging = true;
      const r = win.getBoundingClientRect();
      ox = e.clientX - r.left;
      oy = e.clientY - r.top;
      e.preventDefault();
    });
    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      win.style.left   = (e.clientX - ox) + 'px';
      win.style.top    = (e.clientY - oy) + 'px';
      win.style.right  = 'auto';
      win.style.bottom = 'auto';
    });
    document.addEventListener('mouseup', () => { dragging = false; });
  }
})();
