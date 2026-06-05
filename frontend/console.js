/* Console technique HSM — LMK, fragments, logs */
const $ = (s, r = document) => r.querySelector(s);

const state = {
  api: localStorage.getItem('payhsm_api') || 'http://127.0.0.1:8765',
  pass: '',
  dataDir: localStorage.getItem('payhsm_data') || '',
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

  /* Répertoire HSM (mk.bin, coffre) — synchronisé entre ces champs uniquement */
  const hsmDataDirIds = ['provision-dir', 'startup-dir', 'mk-gen-dir', 'shamir-rec-dir'];
  const sssOutDirIds = ['shamir-gen-dir'];
  const savedSssDir = localStorage.getItem('payhsm_sss_dir') || '';

  hsmDataDirIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = state.dataDir;
  });
  sssOutDirIds.forEach(id => {
    const el = document.getElementById(id);
    if (el && savedSssDir) el.value = savedSssDir;
  });

  hsmDataDirIds.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', () => {
      state.dataDir = el.value.trim();
      hsmDataDirIds.forEach(otherId => {
        const other = document.getElementById(otherId);
        if (other && otherId !== id) other.value = state.dataDir;
      });
      localStorage.setItem('payhsm_data', state.dataDir);
    });
  });

  sssOutDirIds.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('input', () => {
      localStorage.setItem('payhsm_sss_dir', el.value.trim());
    });
  });

  /* ── Cycle de vie — Provisionnement ── */
  $('#btn-provision').onclick = async () => {
    state.dataDir = (document.getElementById('provision-dir')?.value || '').trim();
    saveCfg();
    if (!state.dataDir) { lcStatus('status-provision', 'lc-err', 'Répertoire données manquant'); return; }
    lcStatus('status-provision', 'lc-pending', 'Provisionnement en cours…');
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.provision(state.dataDir);
      lcStatus('status-provision', r.rc === 0 ? 'lc-ok' : 'lc-err', r.message);
      if (r.rc === 0) {
        await refreshHeader();
        try {
          const sim = localStorage.getItem('payhsm_sim_api') || 'http://127.0.0.1:4000';
          await fetch(sim.replace(/\/$/, '') + '/api/switch/reset', { method: 'POST' });
        } catch { /* simulateur non démarré */ }
      }
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
    const dataDir = (document.getElementById('mk-gen-dir')?.value || state.dataDir || '').trim();
    const shareDir = document.getElementById('shamir-gen-dir').value.trim();
    if (!pass) { log('#shamir-gen-log', 'Passphrase requise.', 'err'); return; }
    if (!dataDir) { log('#shamir-gen-log', 'Répertoire T0 (mk.bin) requis.', 'err'); return; }
    if (!shareDir) { log('#shamir-gen-log', 'Répertoire de sortie des parts SSS requis.', 'err'); return; }
    setLeds({ busy: true });
    try {
      const r = await PayHsmApi.shamirGenerate(pass, dataDir, shareDir);
      if (r.rc !== 0) {
        log('#shamir-gen-log', r.message + (r.hint ? ` — ${r.hint}` : ''), 'err');
        return;
      }
      document.getElementById('shamir-gen-files').style.display = 'block';
      const out = r.shareDir || shareDir;
      log('#shamir-gen-log',
        `Parts OK — mk.bin lu depuis ${dataDir} ; fichiers dans ${out}`, 'ok');
    } catch (e) {
      const msg = e.message || String(e);
      log('#shamir-gen-log',
        msg.includes('fetch') || msg.includes('Network')
          ? `${msg} — vérifiez que payhsm-httpd tourne (http://127.0.0.1:8765)`
          : msg,
        'err');
    }
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

  /** Remplace $zmk, $zpk_88… dans une trame wire concaténée (0001A8U…). */
  function expandWireString(cmd) {
    return String(cmd || '').replace(/\$([a-zA-Z0-9_]+)/g, (full, name) => {
      const v = vars[`$${name}`];
      return v != null && v !== '' ? String(v) : full;
    }).toUpperCase();
  }

  const TYPE_TO_NAME = { '001': 'ZPK', '002': 'TPK', '003': 'TAK', '008': 'PVK', '109': 'IMK' };

  /** Modèle A8 court → trame auto (ZMK/TMK depuis coffre HSM, 99 car.) */
  function tryBuildA8Wire(raw) {
    const u = String(raw || '').toUpperCase();
    if (!u.startsWith('0001A8') || u.length >= 187) return null;
    /* Trame déjà complète (99 car. A8/L, sans $) — ne pas réécrire */
    if (u.length >= 99 && u[6] === 'L' && !/\$[a-zA-Z0-9_]+/.test(u)) return null;
    /* TYPE explicite en 7-9 (0001A8L002U…) — ne pas matcher 001 dans l'en-tête 0001 */
    if (u.length >= 10 && u[6] === 'L') {
      const typeCode = u.slice(7, 10);
      const name = TYPE_TO_NAME[typeCode];
      if (!name) return null;
      const key = resolve(`$${name.toLowerCase()}_88`);
      if (key?.length === 88) {
        return PayHsmWire.buildA8VaultAuto('0001', name, key);
      }
      return null;
    }
    return null;
  }

  function wireVarHints(cmd) {
    const missing = [...String(cmd || '').matchAll(/\$([a-zA-Z0-9_]+)/g)].map((m) => `$${m[1]}`);
    return missing;
  }

  function a8TypeCodeFromWire(wire) {
    const u = String(wire || '').toUpperCase();
    if (u.length >= 10 && u.slice(4, 6) === 'A8' && u[6] === 'L') return u.slice(7, 10);
    if (u.length >= 98 && u.slice(4, 6) === 'A8') return u.slice(95, 98);
    return '001';
  }

  function hintSwitchPullAfterA8(wireOrParts) {
    const typeCode = typeof wireOrParts === 'string' ? a8TypeCodeFromWire(wireOrParts) : '001';
    const name = TYPE_TO_NAME[typeCode] || 'ZPK';
    let tr = 'ZMK';
    try { tr = PayHsmWire.transportKeyId(name); } catch { /* */ }
    tLine('<span class="t-ok">  Étape 3 — Switch (A6 auto) :</span>');
    tLine(`<span class="t-cmd">  SWITCH PULL ${name} ${name} $enc $kcv</span>`);
    tLine(`<span class="t-muted">  KEK transport : ${tr}</span>`);
  }

  async function postProcessWireCommand(wire, r) {
    const w = String(wire || '').toUpperCase();
    if (r.rc !== 0 || !r.rawResponse) return;
    try {
      if (w.length >= 11 && w.slice(4, 6) === 'A0' && w[6] === '0') {
        const p = PayHsmWire.parseA1Mode0(r.rawResponse);
        const typeCode = w.slice(7, 10);
        const name = TYPE_TO_NAME[typeCode];
        if (!name) return;
        if (r.cryptogram && r.cryptogram.length === 88) {
          storeVar(r.cryptogram, `${name.toLowerCase()}_88`);
        } else if (r.cryptogram) {
          tLine(`<span class="t-warn">  ⚠ cryptogram JSON ${r.cryptogram.length} hex (attendu 88) — export A8 impossible</span>`);
        }
        storeVar(p.keyUnderLmk, name.toLowerCase());
        storeVar(p.kcv, 'kcv');
        storeVar(p.kcv, `${name.toLowerCase()}_kcv`);
        tRow('bloc LMK (33)', p.keyUnderLmk, 't-warn');
        tRow('KCV', p.kcv, 't-ok');
        const spec = PayHsmWire.OPERATOR_COMMANDS[name];
        const kekVar = spec.transport === 'ZMK' ? '$zmk' : '$tmk';
        let key88 = resolve(`$${name.toLowerCase()}_88`);
        let kek88 = resolve(kekVar);
        if (!kek88?.length && spec.transport === 'ZMK') {
          try {
            const ve = await PayHsmApi.vaultExport();
            const zmkEntry = (ve.keys || []).filter((k) => (k.keyType || '').toUpperCase() === 'ZMK').pop();
            if (zmkEntry?.cryptogram?.length === 88) {
              storeVar(zmkEntry.cryptogram, 'zmk');
              kek88 = zmkEntry.cryptogram;
              tLine(`<span class="t-muted">  → ZMK coffre → </span><span class="t-cmd">$zmk</span><span class="t-muted"> (KCV ${zmkEntry.kcv})</span>`);
            }
          } catch { /* coffre indisponible */ }
        }
        tLine(`<span class="t-ok">✓ A0 OK — ${name} sous LMK</span>`);
        if (key88 && key88.length === 88) {
          const a8wire = PayHsmWire.buildA8VaultAuto('0001', name, key88);
          tLine('<span class="t-info">  Commande 2 (A8 — ZMK/TMK lue dans le coffre) :</span>');
          tLine(`<span class="t-cmd">  ${a8wire}</span>`);
          tLine(`<span class="t-muted">  ou : </span><span class="t-cmd">0001A8L${spec.type}U$${name.toLowerCase()}_88</span>`);
        }
      }
      if (w.length >= 99 && w.slice(4, 6) === 'A8' && w[6] === 'L') {
        const p = PayHsmWire.parseA9Export(r.rawResponse);
        const typeCode = a8TypeCodeFromWire(w);
        const name = TYPE_TO_NAME[typeCode] || 'KEY';
        let tr = 'ZMK';
        try { tr = PayHsmWire.transportKeyId(name); } catch { /* */ }
        storeVar(p.keyUnderZmk, 'enc');
        storeVar(p.kcv, 'kcv');
        storeVar(p.kcv, `${name.toLowerCase()}_kcv`);
        tRow('export bloc (33)', p.keyUnderZmk, 't-warn');
        tRow('KCV', p.kcv, 't-ok');
        const a0kcv = resolve(`$${name.toLowerCase()}_kcv`);
        if (a0kcv && a0kcv.length === 6 && a0kcv !== p.kcv) {
          tLine(`<span class="t-err">  ✗ KCV A8 (${p.kcv}) ≠ KCV A0 (${a0kcv}) — refaire A0 puis A8/L${typeCode}U$${name.toLowerCase()}_88</span>`);
        }
        tLine(`<span class="t-ok">✓ A8/L OK — ${tr} chargée depuis le coffre (ext_keys)</span>`);
        hintSwitchPullAfterA8(w);
      } else if (w.length >= 187 && w.slice(4, 6) === 'A8') {
        const p = PayHsmWire.parseA9Export(r.rawResponse);
        storeVar(p.keyUnderZmk, 'enc');
        storeVar(p.kcv, 'kcv');
        tRow('export bloc (33)', p.keyUnderZmk, 't-warn');
        tRow('KCV', p.kcv, 't-ok');
        tLine('<span class="t-ok">✓ A8/A9 OK</span>');
        hintSwitchPullAfterA8(w);
      }
    } catch (e) {
      tLine(`<span class="t-muted">  (décodage post-cmd : ${e.message})</span>`);
    }
  }

  /** Commande Thales saisie avec espaces → wire + réponse décodée */
  async function execThalesSpaced(parts) {
    let wire;
    try {
      wire = PayHsmWire.buildWireFromSpaced(parts, resolve);
    } catch (e) {
      tLine(`<span class="t-err">✗ ${e.message}</span>`);
      return;
    }
    if (!wire) {
      tLine('<span class="t-err">✗ Format Thales incomplet — voir help (A0 / A6 / A8)</span>');
      return;
    }
    tLine(`<span class="t-muted">→ trame wire (${wire.length} car.)</span>`);
    tLine(`  <span class="t-muted" style="user-select:none">wire         </span><span class="t-warn" style="word-break:break-all;font-size:0.85em">${wire}</span>`);
    try {
      await PayHsmWire.ensurePayshieldMode();
      const r = await PayHsmApi.hsmCmd(wire);
      if (r.rc !== 0) {
        tLine(`<span class="t-err">✗ [${r.errorCode ?? 'ERR'}] ${r.message}</span>`);
        tRow('rawResponse', r.rawResponse ?? '—', 't-err');
        return;
      }
      const dec = PayHsmWire.decodeThalesResponse(parts, r.rawResponse);
      if (!dec.ok) {
        tLine(`<span class="t-err">✗ Erreur HSM ${dec.err}</span>`);
        tRow('rawResponse', r.rawResponse ?? '—', 't-err');
        return;
      }
      tRow('rawResponse', r.rawResponse ?? '—', 't-muted');
      if (dec.verb === 'A0' && dec.mode === '1') {
        const i0 = /^[0-9A-Fa-f]{4}$/.test(parts[0]) ? 1 : 0;
        const typeTok = (parts[i0 + 2] || '001').toUpperCase();
        const aliasMap = { '001': 'zpk', '002': 'tpk', '003': 'tak', '007': 'tmk', '008': 'pvk', '109': 'imk', '00B': 'imk' };
        const alias = aliasMap[typeTok] || typeTok.toLowerCase();
        storeVar(dec.keyUnderLmk, alias);
        storeVar(dec.keyUnderZmk, 'enc');
        storeVar(dec.kcv, 'kcv');
        tRow('clé sous LMK (33)', dec.keyUnderLmk, 't-warn');
        tRow('clé sous ZMK (33)', dec.keyUnderZmk, 't-warn');
        tRow('KCV LMK', dec.kcv, 't-ok');
        tRow('KCV ZMK', dec.kcvZmk, dec.kcv === dec.kcvZmk ? 't-ok' : 't-err');
        tLine('<span class="t-ok">✓ A1 00 — §4.2 : envoyer bloc ZMK + KCV au partenaire</span>');
      } else if (dec.verb === 'A0' && dec.mode === '0') {
        const i0 = /^[0-9A-Fa-f]{4}$/.test(parts[0]) ? 1 : 0;
        const typeTok = (parts[i0 + 2] || '002').toUpperCase();
        const aliasMap = { '001': 'zpk', '002': 'tpk', '003': 'tak', '007': 'tmk', '008': 'pvk', '109': 'imk', '00B': 'imk' };
        const alias = aliasMap[typeTok] || typeTok.toLowerCase();
        storeVar(dec.keyUnderLmk, alias);
        if (r.cryptogram) storeVar(r.cryptogram, `${alias}_88`);
        storeVar(dec.kcv, 'kcv');
        tRow('clé sous LMK (33)', dec.keyUnderLmk, 't-warn');
        tRow('KCV', dec.kcv, 't-ok');
        tLine('<span class="t-ok">✓ A1 00 — génération sous LMK</span>');
        const name = TYPE_TO_NAME[typeTok];
        if (name && PayHsmWire.OPERATOR_COMMANDS[name]) {
          const spec = PayHsmWire.OPERATOR_COMMANDS[name];
          const kek = spec.transport === 'ZMK' ? '$zmk' : '$tmk';
          tLine(`<span class="t-info">  Commande 2 : 0001A8U${kek.slice(1)}${spec.type}U$${name.toLowerCase()}_88</span>`);
        }
      } else if (dec.verb === 'A6') {
        storeVar(dec.keyUnderLmk, 'imported');
        tRow('clé sous LMK (33)', dec.keyUnderLmk, 't-warn');
        tRow('KCV', dec.kcv, 't-ok');
        tLine('<span class="t-ok">✓ A7 00 — import OK</span>');
      } else if (dec.verb === 'A8') {
        storeVar(dec.keyUnderZmk, 'enc');
        storeVar(dec.kcv, 'kcv');
        tRow('clé sous enveloppe (33)', dec.keyUnderZmk, 't-warn');
        tRow('KCV', dec.kcv, 't-ok');
        tLine('<span class="t-ok">✓ A9 00 — export OK</span>');
        hintSwitchPullAfterA8(parts);
      } else {
        tLine('<span class="t-ok">✓ Commande OK</span>');
      }
    } catch (e) {
      tLine(`<span class="t-err">✗ ${e.message}</span>`);
    }
  }

  /* ── Commandes ── */
  function showHelp() {
    tLine('<span class="t-info">╔══ PayHSM Terminal — Thales payShield 10K ════════╗</span>');
    const cmds = [
      ['── Commandes HSM classiques ───────────', ''],
      ['health / status / lmk',           'Diagnostics HSM (connexion, LMK, statut)'],
      ['fragments / logs / mutate / vault','Fragments, audit, mutation LMK · vault en terminal'],
      ['MODE PAYSHIELD',                   'Avant toute commande Thales'],
      ['KEYEX ZPK',                        'Aide : 2 commandes A0+A8 + SWITCH PULL'],
      ['0001A00001U00',                    'ZPK étape 1 — génération (13 car.)'],
      ['0001A8L001U$zpk_88',               'ZPK étape 2 — ZMK lue dans le coffre (99 car.)'],
      ['0001A8|ZPK_00029',                 'ZPK étape 2 — par KEY_ID (coffre)'],
      ['A8 ZPK',                           'Raccourci export auto'],
      ['VAULT LOAD ZMK',                   'Charger ZMK 88 hex depuis coffre → $zmk'],
      ['0001A00002U00 / 0001A00003U00',     'TPK / TAK étape 1'],
      ['0001A8L002U$tpk_88',               'TPK étape 2 — TMK lue dans le coffre (99 car.)'],
      ['0001A8L003U$tak_88',               'TAK étape 2 — TMK coffre'],
      ['0001A8U$tmk002U$tpk_88',           'TPK étape 2 — TMK explicite (187 car.)'],
      ['0001A00008U00 / 0001A00109U00',     'PVK / IMK étape 1'],
      ['SWITCH PULL ZPK ZPK $enc $kcv',    'Étape 3 — A6 auto Switch'],
      ['── Gestion des clés payShield 10K ─────', ''],
      ['0001A0|TYPE|LEN|SCHEME|EXPORT',   'Générer clé → KEY_ID stocké dans coffre'],
      ['0001A4|TYPE|SCHEME|NC|C1|C2|…',   'Former clé depuis composants (cérémonie)'],
      ['0001A6|TTYPE|TID|KTYPE|SCH|ENC',  'Importer clé sous transport → LMK'],
      ['0001A8|KEY_ID|TTYPE|TID|SCHEME',  'Exporter clé sous transport'],
      ['0001B0|KEY_ID|SCHEME',            'Changer schéma de clé'],
      ['0001BS',                           'Effacer stockage temporaire'],
      ['0001BW',                           'Re-envelopper vault sous LMK courante'],
      ['0001CS|KEY_ID|FIELD|VALUE',       'Modifier header clé (SCHEME/ACTIVE/EXPORT)'],
      ['0001K8|KEY_ID|KEK_ID|SCHEME',     'Exporter clé sous KEK'],
      ['0001KA|KEY_ID',                   'KCV d\'une clé du coffre'],
      ['0001KA10U<88hex>',                'KCV depuis cryptogramme LMK (wire format)'],
      ['0001KA|RAW|AES|<32hex>',          'KCV depuis clé brute (RAW)'],
      ['0001NE|TYPE|LEN|NC|STORE',        'Générer composants (cérémonie de clés)'],
      ['── Switch bancaire ────────────────────', ''],
      ['── Échange clés (manuel HSM → Switch) ─', ''],
      ['0001NE|ZMK|16|3|Y',                'A2 : composantes ZMK (terminal HSM)'],
      ['0001A4|ZMK|U|3|C1|C2|C3',          'A4 : former ZMK → SWITCH STORE ZMK …'],
      ['NE+A4 ZMK/TMK puis STORE',         'Cérémonie ZMK/TMK → SWITCH STORE …'],
      ['SWITCH PULL …',                    'A6 auto côté Switch (partenaire)'],
      ['SWITCH PULL <id> <type> $enc KCV','A6 automatique + log simulateur'],
      ['SWITCH STORE <id> <type> $blk KCV','ZMK/TMK après A4 (KEY_BLOCK 88 hex)'],
      ['SWITCH DERIVE-GAB',                'TPK/TAK dérivés depuis TMK (auto HSM)'],
      ['SWITCH INIT / STATUS / LOGS-A6',   'Simulateur (:4000)'],
      ['SWITCH PROVISION',                 'Sauvegarder coffre (sans générer clés)'],
      ['SWITCH LOGS',                      'Journal audit HSM admin'],
      ['── GAB / ATM ──────────────────────────', ''],
      ['ATM ADD <id> "<nom>" "<lieu>"',    'Enregistrer un GAB'],
      ['ATM LIST',                         'Lister tous les GAB'],
      ['ATM STATUS <id>',                  'Statut et KCV d\'un GAB'],
      ['ATM PROVISION <id>',               'Générer TMK/TPK/TAK via HSM (A0)'],
      ['ATM ENABLE / DISABLE / BLOCK <id>','Activer / Désactiver / Bloquer un GAB'],
      ['ATM REMOVE <id>',                  'Supprimer un GAB (clés archivées)'],
      ['ATM KCV <id>',                     'Afficher uniquement les KCV'],
      ['ATM CONNECT / DISCONNECT <id>',    'Simuler connexion / déconnexion GAB'],
      ['ATM ROTATE-KEYS <id>',             'Renouveler TPK/TAK via HSM'],
      ['── Utilitaires ────────────────────────', ''],
      ['vars / clear',                     'Variables stockées / effacer terminal'],
    ];
    for (const [cmd, desc] of cmds) {
      if (cmd.startsWith('──')) {
        tLine(`  <span class="t-info">${cmd}</span>`);
      } else {
        tLine(`  <span class="t-cmd">${cmd.padEnd(36)}</span><span class="t-muted">${desc}</span>`);
      }
    }
    tLine('<span class="t-info">╚════════════════════════════════════════════════════╝</span>');
  }

  /* Tokeniseur qui respecte les guillemets : ATM ADD id "nom avec espaces" "lieu" */
  function tokenize(str) {
    const tokens = [];
    let i = 0;
    while (i < str.length) {
      while (i < str.length && str[i] === ' ') i++;
      if (i >= str.length) break;
      if (str[i] === '"') {
        i++;
        let tok = '';
        while (i < str.length && str[i] !== '"') tok += str[i++];
        if (str[i] === '"') i++;
        tokens.push(tok);
      } else {
        let tok = '';
        while (i < str.length && str[i] !== ' ') tok += str[i++];
        tokens.push(tok);
      }
    }
    return tokens;
  }

  async function runCmd(raw) {
    const parts = raw.trim().split(/\s+/);
    const verb  = parts[0].toUpperCase();

    /* ── Protocole wire payShield — toutes commandes : 4 hex + 2 alphanum ── */
    if (/^[0-9A-Fa-f]{4}[A-Za-z0-9]{2}/.test(parts[0])) {
      let wire = expandWireString(parts[0]);
      const built = tryBuildA8Wire(parts[0]);
      if (built) wire = built;
      if (wireVarHints(wire).length) {
        const rebuilt = tryBuildA8Wire(parts[0]);
        if (rebuilt) wire = rebuilt;
      }
      if (wireVarHints(wire).length) {
        tLine(`<span class="t-err">✗ Variable(s) non définie(s) : ${wireVarHints(wire).join(', ')}</span>`);
        if (wire.slice(4, 6) === 'A8') {
          tLine('<span class="t-muted">  Lancez A0 ZPK — puis </span><span class="t-cmd">0001A8L001U$zpk_88</span>');
        }
        return;
      }
      if (wire.slice(4, 6) === 'A8' && wire.length < 99) {
        tLine(`<span class="t-err">✗ Trame A8 trop courte (${wire.length} car.)</span>`);
        tLine('<span class="t-muted">  Après A0 : </span><span class="t-cmd">0001A8L001U$zpk_88</span><span class="t-muted"> ou </span><span class="t-cmd">A8 ZPK</span>');
        return;
      }
      tLine(`<span class="t-muted">→ POST /api/hsm/cmd  (${wire.length} car.)</span>`);
      if (wire !== parts[0].toUpperCase()) {
        tLine(`<span class="t-muted">  (variables développées depuis modèle)</span>`);
      }
      try {
        await PayHsmWire.ensurePayshieldMode();
        const r = await PayHsmApi.hsmCmd(wire);
        if (r.rc !== 0) {
          tLine(`<span class="t-err">✗ [${r.errorCode ?? 'ERR'}] ${r.message}</span>`);
          if (r.errorCode === '04' && wire.slice(4, 6) === 'A0') {
            tLine('<span class="t-warn">  → Mode INTERNAL actif : tapez </span><span class="t-cmd">MODE PAYSHIELD</span><span class="t-warn"> puis relancez A0</span>');
          }
          tRow('rawResponse', r.rawResponse ?? '—', 't-err');
          return;
        }

        /* ── Réponse brute complète ── */
        tLine(`  <span class="t-muted" style="user-select:none">rawResponse  </span><span class="t-warn" style="word-break:break-all">${r.rawResponse ?? '—'}</span>`);

        /* ── Champs communs ── */
        if (r.kcv)     tRow('KCV',     r.kcv,               't-ok');
        if (r.message) tRow('message', r.message,            't-muted');
        if (r.keyLen)  tRow('keyLen',  `${r.keyLen} octets (AES-${r.keyLen*8})`, 't-info');
        if (r.scheme)  tRow('schéma',  r.scheme,             't-info');

        /* ── A0 étendu : clé générée avec KEY_ID ── */
        if (r.keyId) {
          tRow('keyId',       r.keyId,                       't-cmd');
          tRow('type',        r.keyType ?? '—',              't-info');
          tRow('exportable',  r.exportable ? 'OUI' : 'NON',  r.exportable ? 't-ok' : 't-warn');
          const kv = storeVar(r.keyId, (r.keyType ?? 'key').toLowerCase() + '_id');
          tLine(`  <span class="t-muted">→ KEY_ID stocké dans </span><span class="t-cmd">${kv}</span>`);
        }

        /* ── Cryptogramme complet (A0 wire / A6) — 88 hex pour A8, pas le bloc 33 ── */
        if (r.cryptogram) {
          const alias = r.keyType ? r.keyType.toLowerCase() : undefined;
          const k = storeVar(r.cryptogram, alias);
          if (r.cryptogram.length === 88 && alias) {
            storeVar(r.cryptogram, `${alias}_88`);
          }
          tLine(`  <span class="t-muted" style="user-select:none">cryptogram   </span><span class="t-warn" style="word-break:break-all">${r.cryptogram}</span>`);
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span>`);
          if (alias && r.cryptogram.length === 88) {
            tLine(`  <span class="t-muted">→ A8 utilise </span><span class="t-cmd">$${alias}_88</span><span class="t-muted"> (88 hex), pas le bloc LMK 33</span>`);
          }
        }

        /* ── A8 export / K8 KEK ── */
        if (r.exportedKey) {
          const k = storeVar(r.exportedKey, 'enc');
          tLine(`  <span class="t-muted" style="user-select:none">exportedKey  </span><span class="t-warn" style="word-break:break-all">${r.exportedKey}</span>`);
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span>`);
          if (r.exportedVia) tRow('via', r.exportedVia, 't-muted');
        }
        if (r.keyUnderKek) {
          const k = storeVar(r.keyUnderKek, 'kek_enc');
          tLine(`  <span class="t-muted" style="user-select:none">keyUnderKek  </span><span class="t-warn" style="word-break:break-all">${r.keyUnderKek}</span>`);
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span>`);
        }

        /* ── BW migration LMK ── */
        if (r.migrated !== undefined) {
          tRow('migrated', String(r.migrated), 't-ok');
          tRow('failed',   String(r.failed),   r.failed > 0 ? 't-err' : 't-muted');
        }

        /* ── NE composants ── */
        if (r.components !== undefined) {
          tRow('composants', `${r.components} composant(s) générés`, 't-info');
          /* Extraire COMP1, COMP2… depuis rawResponse */
          const raw = r.rawResponse ?? '';
          const comps = [...raw.matchAll(/COMP(\d+)=([A-F0-9]{32})/g)];
          for (const [, n, hex] of comps) {
            const k = storeVar(hex, `comp${n}`);
            tRow(`COMP${n}`, hex, 't-warn');
            tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span>`);
          }
        }

        /* ── Clé claire (A8 flag V) — avertissement rouge ── */
        if (r.keyClear) {
          tRow('keyClear ⚠', r.keyClear, 't-err');
          tLine('  <span class="t-warn">⚠ SENSIBLE — clé en clair (flag V) — ne pas logger</span>');
        }

        if (r.rawResponse && r.rawResponse.includes('KEY_BLOCK=')) {
          const m = r.rawResponse.match(/KEY_BLOCK=([A-F0-9]{88})/i);
          if (m) {
            const t = (r.keyType || '').toUpperCase();
            const alias = t === 'ZMK' ? 'zmk' : t === 'TMK' ? 'tmk' : t.toLowerCase();
            storeVar(m[1], alias);
            tLine(`<span class="t-ok">  → KEY_BLOCK stocké dans </span><span class="t-cmd">$${alias}</span><span class="t-muted"> (${m[1].length} hex)</span>`);
          }
        }

        tLine('<span class="t-ok">✓ Commande wire OK</span>');
        await postProcessWireCommand(wire, r);
      } catch (e) {
        tLine(`<span class="t-err">✗ ${e.message}</span>`);
      }
      tScroll();
      return;
    }

    switch (verb) {

      case 'KEYEX': case 'ECHANGE': {
        const kt = (parts[1] || 'ZPK').toUpperCase();
        const spec = PayHsmWire.OPERATOR_COMMANDS[kt];
        if (!spec) {
          tLine('<span class="t-err">Types : TMK ZPK TPK TAK PVK IMK</span>');
          break;
        }
        if (spec.storeOnly) {
          tLine(`<span class="t-info">══ ${kt} (clé transport — pas d\'A8/PULL) ══</span>`);
          tLine(`<span class="t-ok">1. Génération :</span> <span class="t-cmd">${spec.a0}</span>`);
          tLine('<span class="t-ok">2. Coffre Switch :</span> <span class="t-cmd">SWITCH STORE TMK TMK $tmk_88 $kcv</span>');
          tLine('<span class="t-muted">   (ou gardez votre TMK actuelle si KCV identique)</span>');
          break;
        }
        tLine(`<span class="t-info">══ Échange ${kt} (A0 → A8 → SWITCH PULL) ══</span>`);
        tLine('<span class="t-muted">Prérequis : MODE PAYSHIELD · ZMK/TMK en coffre (cérémonie A4)</span>');
        tLine(`<span class="t-ok">1. Génération (tapez) :</span>`);
        tLine(`<span class="t-cmd">   ${spec.a0}</span>`);
        tLine(`<span class="t-ok">2. Export (ZMK coffre — sans taper la ZMK) :</span>`);
        tLine(`<span class="t-cmd">   0001A8L${spec.type}U$${kt.toLowerCase()}_88</span>`);
        tLine('<span class="t-muted">   ou </span><span class="t-cmd">A8 ZPK</span>');
        const key88 = resolve(`$${kt.toLowerCase()}_88`);
        if (key88?.length === 88) {
          tLine(`<span class="t-cmd">   ${PayHsmWire.buildA8VaultAuto('0001', kt, key88)}</span>`);
        }
        tLine('<span class="t-ok">3. Import Switch (auto) :</span>');
        tLine(`<span class="t-cmd">   SWITCH PULL ${kt} ${kt} $enc $kcv</span>`);
        break;
      }

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
        if ((parts[1] || '').toUpperCase() === 'LOAD') {
          const want = (parts[2] || 'ZMK').toUpperCase();
          tLine('<span class="t-muted">→ GET /api/vault/export (cryptogrammes 88 hex)</span>');
          try {
            const r = await PayHsmApi.vaultExport();
            const keys = (r.keys || []).filter((k) => (k.keyType || '').toUpperCase() === want);
            if (!keys.length) {
              tLine(`<span class="t-err">✗ Aucune clé ${want} dans le coffre — A4 ou A0 ${want} d\'abord</span>`);
              break;
            }
            const k = keys[keys.length - 1];
            const alias = want === 'ZMK' ? 'zmk' : want === 'TMK' ? 'tmk' : want.toLowerCase();
            storeVar(k.cryptogram, alias);
            tRow('keyId', k.keyId, 't-cmd');
            tRow('KCV', k.kcv, 't-ok');
            tLine(`<span class="t-ok">✓ $${alias} chargé (${k.cryptogram.length} hex) — prêt pour A8</span>`);
            const zpk88 = resolve('$zpk_88');
            if (want === 'ZMK' && zpk88?.length === 88) {
              tLine('<span class="t-info">  A8 ZPK prêt :</span>');
              tLine(`<span class="t-cmd">  ${PayHsmWire.buildA8Wire('ZPK', k.cryptogram, zpk88)}</span>`);
            }
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }
          break;
        }
        if ((parts[1] || '').toUpperCase() === 'CLEAR') {
          try {
            const r = await PayHsmApi.vaultClear();
            const nExt = r.removedExt ?? 0;
            const nCls = r.removedClassic ?? (r.removed ?? 0) - nExt;
            tLine(`<span class="t-ok">✓ Coffre HSM vidé — keys.vault=${nCls} · ext_keys.vault=${nExt}</span>`);
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }
          break;
        }
        tLine('<span class="t-muted">→ GET /api/vault</span>');
        if (parts[1]) tLine(`<span class="t-muted">  (vider : VAULT CLEAR)</span>`);
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

      case 'MODE': {
        const m = (parts[1] || 'PAYSHIELD').toUpperCase();
        const mode = m.includes('PAY') || m === 'PS' ? 'PAYSHIELD_COMPAT' : m;
        tLine(`<span class="t-muted">→ POST /api/hsm/mode { mode: "${mode}" }</span>`);
        try {
          const r = await PayHsmApi.hsmModeSet(mode);
          tLine(`<span class="t-ok">✓ Mode HSM : ${r.mode || mode}</span>`);
        } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }
        break;
      }

      /* ── A0 — format Thales complet ou REST legacy ── */
      case 'A0': {
        if (PayHsmWire.isThalesSpaced(parts)) {
          await execThalesSpaced(parts);
          break;
        }

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
          tLine(`  <span class="t-muted" style="user-select:none">cryptogram   </span><span class="t-warn" style="word-break:break-all">${r.cryptogram}</span>`);
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span><span class="t-muted"> et </span><span class="t-cmd">$${kt.toLowerCase()}</span>`);
          tLine(`<span class="t-ok">✓ A0 OK — clé AES-${(r.keyLen ?? kl) * 8} générée sous LMK (${r.cryptogram.length} hex chars)</span>`);
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ── A6 — format Thales complet ou REST legacy ── */
      case 'A6': {
        if (PayHsmWire.isThalesSpaced(parts)) {
          await execThalesSpaced(parts);
          break;
        }

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
          tLine(`  <span class="t-muted" style="user-select:none">cryptogram   </span><span class="t-warn" style="word-break:break-all">${r.cryptogram}</span>`);
          tLine(`  <span class="t-muted">→ stocké dans </span><span class="t-cmd">${k}</span><span class="t-muted"> et </span><span class="t-cmd">$${kt.toLowerCase()}</span>`);
          tLine('<span class="t-ok">✓ A6 OK — clé importée et rechiffrée sous LMK</span>');
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ── A8 — format Thales complet ou consultation KCV (REST) ── */
      case 'A8': {
        if (PayHsmWire.isThalesSpaced(parts)) {
          await execThalesSpaced(parts);
          break;
        }

        const ktOnly = (parts[1] || '').toUpperCase();
        if (parts.length === 2 && PayHsmWire.OPERATOR_COMMANDS[ktOnly] && PayHsmWire.OPERATOR_COMMANDS[ktOnly].transport) {
          const spec = PayHsmWire.OPERATOR_COMMANDS[ktOnly];
          const key = resolve(`$${ktOnly.toLowerCase()}_88`);
          if (!key || key.length !== 88) {
            tLine(`<span class="t-err">✗ $${ktOnly.toLowerCase()}_88 manquant — lancez A0 ${ktOnly} d\'abord</span>`);
            break;
          }
          const wire = PayHsmWire.buildA8VaultAuto('0001', ktOnly, key);
          tLine(`<span class="t-muted">→ export ${ktOnly} sous ${spec.transport} (${wire.length} car.)</span>`);
          try {
            await PayHsmWire.ensurePayshieldMode();
            const r = await PayHsmApi.hsmCmd(wire);
            if (r.rc !== 0) {
              tLine(`<span class="t-err">✗ [${r.errorCode ?? 'ERR'}] ${r.message}</span>`);
              tRow('rawResponse', r.rawResponse ?? '—', 't-err');
              break;
            }
            tRow('rawResponse', r.rawResponse ?? '—', 't-muted');
            await postProcessWireCommand(wire, r);
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }
          break;
        }

        const rawCle = parts[1] ?? '';
        const flag   = (parts[2] ?? 'H').toUpperCase();
        const kt     = parts[3] ?? 'ZPK';
        const keyCrypt = resolve(rawCle);

        if (!keyCrypt) {
          tLine('<span class="t-err">Usage : A8 U $tmk 002 U $tpk</span>');
          tLine('<span class="t-muted">       A8 &lt;$cle_88&gt; [H|V] [type] — consultation KCV (REST legacy)</span>');
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

      /* ══════════════════════════════════════════════════════════════
         SWITCH — Administration Switch bancaire style payShield 10K
         ══════════════════════════════════════════════════════════════ */
      case 'SWITCH': {
        const sub = (parts[1] || '').toUpperCase();

        if (sub === 'INIT') {
          tLine('<span class="t-muted">→ POST simulateur /api/switch/init (restaure coffre si même LMK)</span>');
          try {
            const r = await PayHsmSimApi.switchInit();
            if (r.restored) {
              tLine(`<span class="t-ok">✓ ${r.message}</span>`);
              tRow('clés restaurées', String(r.vaultKeys ?? 0), 't-ok');
              tRow('LMK ref', r.lmkRef || '—', 't-muted');
            } else {
              tLine(`<span class="t-ok">✓ ${r.message || 'Switch prêt'}</span>`);
              tLine('<span class="t-muted">  Coffre vide ou première session — établir ZMK/TMK puis clés métier</span>');
            }
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'RESET') {
          tLine('<span class="t-warn">→ Efface coffre Switch (disque + OpenBao) — nouvelle génération complète</span>');
          try {
            await PayHsmSimApi.switchReset();
            tLine('<span class="t-ok">✓ Coffre Switch réinitialisé</span>');
            tLine('<span class="t-muted">  Côté PayHSM : </span><span class="t-cmd">VAULT CLEAR</span><span class="t-muted"> (keys.vault + ext_keys.vault)</span>');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'STATUS') {
          tLine('<span class="t-muted">→ POST /api/admin/switch/status</span>');
          try {
            const r = await PayHsmApi.adminSwitchStatus();
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            const ts = r.lastUpdated ? new Date(r.lastUpdated * 1000).toLocaleString() : '—';
            tLine('<span class="t-info">SWITCH STATUS</span>');
            tLine('  ─────────────────────────────────────');
            tRow('État',               r.state ?? '—',                      'bold' in r ? 't-ok' : 't-info');
            tRow('Initialisé',         r.initialized ? 'OUI' : 'NON',       r.initialized ? 't-ok' : 't-warn');
            tRow('Clés principales',   `${r.keyCount ?? 0} clé(s)`,         't-info');
            tRow('GAB enregistrés',    `${r.atmCount ?? 0}`,                 't-info');
            tRow('Dernière MAJ',       ts,                                   't-muted');
            if (r.keys && r.keys.length) {
              tLine('  <span class="t-muted">Clés Switch :</span>');
              for (const k of r.keys)
                tLine(`    <span class="t-cmd">${k.name}</span>  KCV:<span class="t-ok">${k.kcv}</span>`);
            }
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'PROVISION') {
          tLine('<span class="t-muted">→ POST simulateur /api/switch/provision-keys (sauvegarde coffre uniquement)</span>');
          try {
            await PayHsmSimApi.switchInit();
            const r = await fetch((localStorage.getItem('payhsm_sim_api') || 'http://127.0.0.1:4000') + '/api/switch/provision-keys', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: '{}',
            }).then((x) => x.json());
            tLine(`<span class="t-ok">✓ ${r.hint || r.count + ' clé(s) en coffre'}</span>`);
            tLine('<span class="t-warn">Mode manuel — les clés se créent dans CE terminal (NE/A0/EXPORT), pas en auto.</span>');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'PULL') {
          const keyId = parts[2] || 'ZPK';
          const keyType = (parts[3] || keyId).toUpperCase();
          const enc = resolve(parts[4] || '$enc');
          const kcv = resolve(parts[5] || '$kcv');
          if (!enc || (enc.length !== 32 && enc.length !== 33)) {
            tLine('<span class="t-err">Usage : SWITCH PULL &lt;id&gt; &lt;type&gt; [$enc] [$kcv]</span>');
            tLine('<span class="t-muted">  Après A8 PS — $enc = bloc 33 (U+32hex) ou 32 hex sous ZMK</span>');
            break;
          }
          tLine('<span class="t-muted">→ Switch A6 automatique (simulateur :4000)</span>');
          try {
            let transportKeyId;
            try { transportKeyId = PayHsmWire.transportKeyId(keyType); } catch { transportKeyId = 'ZMK'; }
            const r = await PayHsmSimApi.importA6({
              keyId,
              keyType,
              keyUnderZmk: enc,
              kcvExpected: kcv || undefined,
              transportKeyId,
            });
            tLine(`<span class="t-ok">✓ A6 OK — ${keyType} importée dans coffre Switch · KCV ${r.kcv}</span>`);
            if (r.persisted && !r.persisted.disk && !r.persisted.openbao) {
              tLine('<span class="t-warn">  ⚠ Coffre non sauvegardé sur disque — lancez </span><span class="t-cmd">SWITCH PROVISION</span>');
            } else if (r.persisted?.disk || r.persisted?.openbao) {
              tLine('<span class="t-muted">  → coffre persisté (disque/OpenBao)</span>');
            }
            tLine('<span class="t-info">  → voir logs : SWITCH LOGS-A6</span>');
          } catch (e) {
            tLine(`<span class="t-err">✗ ${e.message}</span>`);
            if (String(e.message).includes('07') || String(e.message).includes('KCV')) {
              const tr = (() => { try { return PayHsmWire.transportKeyId(keyType); } catch { return 'ZMK'; } })();
              tLine(`<span class="t-warn">  Cause fréquente : export A8 sous mauvaise KEK (attendu ${tr}) ou $enc/$kcv d'une autre clé (ZPK vs TPK).</span>`);
              if (tr === 'TMK') {
                tLine('<span class="t-muted">  Vérifier : </span><span class="t-cmd">0001A8L002U$tpk_88</span><span class="t-muted"> (pas L001) · TMK en coffre après A4 TMK</span>');
                tLine('<span class="t-muted">  Puis </span><span class="t-cmd">SWITCH PULL TPK TPK $enc $kcv</span>');
              } else {
                tLine('<span class="t-muted">  Refaire après A4 : </span><span class="t-cmd">SWITCH STORE ZMK ZMK $zmk $kcv</span>');
                tLine('<span class="t-muted">  Puis </span><span class="t-cmd">SWITCH PULL ZPK ZPK $enc $kcv</span>');
              }
            }
          }

        } else if (sub === 'STORE') {
          const keyId = parts[2] || 'ZMK';
          const keyType = (parts[3] || keyId).toUpperCase();
          const crypt = resolve(parts[4] || '$zmk' || parts[2]);
          const kcv = resolve(parts[5] || '');
          if (!crypt || crypt.length !== 88) {
            tLine('<span class="t-err">Usage : SWITCH STORE &lt;id&gt; &lt;type&gt; &lt;KEY_BLOCK 88hex&gt; [kcv]</span>');
            tLine('<span class="t-muted">  Après 0001A4|…| dans ce terminal (ZMK ou TMK cérémonie)</span>');
            break;
          }
          try {
            const r = await PayHsmSimApi.storeKey({ keyId, keyType, cryptogram: crypt, kcv });
            const alias = keyType === 'ZMK' ? 'zmk' : keyType === 'TMK' ? 'tmk' : keyType.toLowerCase();
            storeVar(crypt, alias);
            tLine(`<span class="t-ok">✓ ${keyType} stockée Switch · KCV ${r.kcv || kcv}</span>`);
            tLine(`<span class="t-muted">  → aussi dans </span><span class="t-cmd">$${alias}</span><span class="t-muted"> (doit être le KEY_BLOCK A4 — même valeur que le coffre PayHSM pour A8/L)</span>`);
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'DERIVE-GAB' || sub === 'DERIVE') {
          try {
            const r = await PayHsmSimApi.deriveGab();
            tLine(`<span class="t-ok">✓ TPK/TAK dérivés pour ${r.terminal}</span>`);
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'LOGS-A6') {
          try {
            const r = await PayHsmSimApi.exchangeLogs();
            tLine('<span class="t-info">── Journal A6 Switch ──</span>');
            for (const e of (r.logs || [])) {
              const d = new Date(e.ts).toLocaleTimeString();
              tLine(`  <span class="t-muted">[${d}]</span> <span class="t-ok">${e.message}</span>`);
            }
            if (!r.logs?.length) tLine('<span class="t-muted">  (vide — lancez SWITCH PULL après EXPORT)</span>');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'LOGS') {
          tLine('<span class="t-muted">→ GET /api/admin/switch/logs</span>');
          try {
            const r = await PayHsmApi.adminSwitchLogs();
            tLine('<span class="t-info">SWITCH LOGS</span>');
            tLine('  ─────────────────────────────────────');
            for (const e of (r.logs || []).slice(-20).reverse()) {
              const d = new Date(e.ts * 1000).toLocaleTimeString();
              tLine(`  <span class="t-muted">[${d}]</span> ${e.message}`);
            }
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else {
          tLine('<span class="t-err">SWITCH : sous-commande inconnue</span>');
          tLine('  <span class="t-muted">Sous-commandes : INIT · STORE · PULL · EXPORT · DERIVE-GAB · LOGS-A6 · PROVISION</span>');
        }
        break;
      }

      /* ── EXPORT : raccourci (préférer A0 1 … complet) ── */
      case 'EXPORT': {
        const kt = (parts[1] || 'ZPK').toUpperCase();
        const rawZmk = resolve(parts[2] || '$zmk');
        if (!rawZmk || rawZmk.length !== 88) {
          tLine('<span class="t-err">Préférez : A0 1 001 U $zmk U 0  puis SWITCH PULL</span>');
          break;
        }
        const code = PayHsmWire.keyTypeCode(kt);
        tLine(`<span class="t-muted">→ raccourci EXPORT — équivalent A0 1 ${code} U $zmk U 0</span>`);
        try {
          await PayHsmWire.ensurePayshieldMode();
          const wire = PayHsmWire.buildA0GenExport('0001', kt, rawZmk);
          const r = await PayHsmApi.hsmCmd(wire);
          if (r.rc !== 0) {
            tLine(`<span class="t-err">✗ [${r.errorCode}] ${r.message}</span>`);
            tRow('rawResponse', r.rawResponse || '—', 't-err');
            break;
          }
          const p = PayHsmWire.parseA1GenExport(r.rawResponse);
          storeVar(r.cryptogram || p.keyUnderLmk, kt.toLowerCase());
          storeVar(p.keyUnderZmk, 'enc');
          tRow('ZPK sous LMK (bloc)', p.keyUnderLmk, 't-warn');
          tRow('ZPK sous ZMK (bloc)', p.keyUnderZmk, 't-warn');
          tRow('KCV LMK / ZMK', `${p.kcv} / ${p.kcvZmk}`, p.kcv === p.kcvZmk ? 't-ok' : 't-err');
          tLine('<span class="t-muted">→ Switch A6 wire Thales…</span>');
          await PayHsmSimApi.switchInit().catch(() => {});
          const imp = await PayHsmSimApi.importA6({
            keyId: kt,
            keyType: kt,
            keyUnderZmk: p.keyUnderZmk,
            kcvExpected: p.kcv,
          });
          tLine(`<span class="t-ok">✓ A0/1+A6 OK — ${kt} · KCV ${imp.kcv}</span>`);
          tLine('<span class="t-info">  Journal : SWITCH LOGS-A6</span>');
        } catch (e) {
          tLine(`<span class="t-err">✗ ${e.message}</span>`);
        }
        break;
      }

      /* ══════════════════════════════════════════════════════════════
         ATM — Gestion GAB/ATM style payShield 10K
         ══════════════════════════════════════════════════════════════ */
      case 'ATM': {
        const tkns = tokenize(raw);
        const sub  = (tkns[1] || '').toUpperCase();
        const atmId = tkns[2] || '';

        if (sub === 'ADD') {
          const id  = tkns[2] || '';
          const nm  = tkns[3] || id;
          const loc = tkns[4] || '—';
          if (!id) { tLine('<span class="t-err">Usage : ATM ADD &lt;id&gt; "&lt;nom&gt;" "&lt;localisation&gt;"</span>'); break; }
          tLine(`<span class="t-muted">[ATM] Ajout du GAB ${id}</span>`);
          tLine(`<span class="t-muted">→ POST /api/admin/atm/add</span>`);
          try {
            const r = await PayHsmApi.adminAtmAdd(id, nm, loc);
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            tLine(`<span class="t-ok">✓ ${r.message}</span>`);
            tRow('Nom',          nm,             't-info');
            tRow('Localisation', loc,            't-info');
            tRow('État',         r.status ?? 'INACTIVE', 't-warn');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'LIST') {
          tLine('<span class="t-muted">→ POST /api/admin/atm/list</span>');
          try {
            const r = await PayHsmApi.adminAtmList();
            const atms = r.atms || [];
            if (!atms.length) { tLine('<span class="t-muted">Aucun GAB enregistré.</span>'); break; }
            tLine(`<span class="t-info">${atms.length} GAB enregistré(s) :</span>`);
            tLine(`  <span class="t-muted">${'ID'.padEnd(10)} ${'Nom'.padEnd(28)} ${'Localisation'.padEnd(20)} État</span>`);
            tLine('  <span class="t-muted">────────────────────────────────────────────────────────────────</span>');
            for (const a of atms) {
              const cls = a.status === 'ACTIVE' ? 't-ok' : a.status === 'BLOCKED' ? 't-err' : 't-warn';
              tLine(`  ${a.id.padEnd(10)} ${a.name.slice(0,28).padEnd(28)} ${(a.location||'—').slice(0,20).padEnd(20)} <span class="${cls}">${a.status}</span>`);
            }
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'STATUS') {
          if (!atmId) { tLine('<span class="t-err">Usage : ATM STATUS &lt;id&gt;</span>'); break; }
          tLine(`<span class="t-muted">→ POST /api/admin/atm/status  { id: "${atmId}" }</span>`);
          try {
            const r = await PayHsmApi.adminAtmStatus(atmId);
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            const cls = r.status === 'ACTIVE' ? 't-ok' : r.status === 'BLOCKED' ? 't-err' : 't-warn';
            tLine(`<span class="t-info">ATM STATUS — ${atmId}</span>`);
            tLine('  ──────────────────────────────────────');
            tRow('ID',           r.id ?? atmId,       't-cmd');
            tRow('Nom',          r.name ?? '—',       't-info');
            tRow('Localisation', r.location ?? '—',   't-info');
            tRow('État',         r.status ?? '—',     cls);
            tRow('TMK KCV',      r.tmk?.kcv || '—',  r.tmk?.present ? 't-ok' : 't-warn');
            tRow('TPK KCV',      r.tpk?.kcv || '—',  r.tpk?.present ? 't-ok' : 't-warn');
            tRow('TAK KCV',      r.tak?.kcv || '—',  r.tak?.present ? 't-ok' : 't-warn');
            if (r.createdAt) tRow('Créé le', new Date(r.createdAt*1000).toLocaleString(), 't-muted');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'PROVISION') {
          if (!atmId) { tLine('<span class="t-err">Usage : ATM PROVISION &lt;id&gt;</span>'); break; }
          tLine('');
          tLine(`<span class="t-info">[ATM] Provisionnement des clés pour ${atmId} via commandes HSM...</span>`);
          tLine('');
          try {
            const r = await PayHsmApi.adminAtmProvision(atmId);
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            const codes = { TMK:'01', TPK:'06', TAK:'07' };
            for (const k of (r.keys || [])) {
              const code = codes[k.key] ?? '??';
              tLine(`  <span class="t-cmd">[HSM CMD]</span> <span class="t-muted">Génération ${k.key} pour ${atmId}  (code=${code}, 0001A0${code}10U)</span>`);
              if (k.rc === 0) {
                tLine(`  <span class="t-ok">✓ ${k.key} protégée sous LMK</span>`);
                tLine(`         KCV : <span class="t-ok">${k.kcv}</span>`);
              } else {
                tLine(`  <span class="t-err">✗ ${k.key} — échec HSM</span>`);
              }
              tLine('');
            }
            tLine(`<span class="t-ok">✓ ${r.message}</span>`);
            tLine('<span class="t-ok">✓ Aucune clé claire n\'a été affichée ou stockée</span>');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (['ENABLE','DISABLE','BLOCK','REMOVE','CONNECT','DISCONNECT'].includes(sub)) {
          if (!atmId) { tLine(`<span class="t-err">Usage : ATM ${sub} &lt;id&gt;</span>`); break; }
          const apiMap = {
            ENABLE: PayHsmApi.adminAtmEnable,     DISABLE: PayHsmApi.adminAtmDisable,
            BLOCK:  PayHsmApi.adminAtmBlock,       REMOVE:  PayHsmApi.adminAtmRemove,
            CONNECT: PayHsmApi.adminAtmConnect,    DISCONNECT: PayHsmApi.adminAtmDisconnect,
          };
          const verbs = {
            ENABLE:'Activation', DISABLE:'Désactivation', BLOCK:'Blocage',
            REMOVE:'Suppression', CONNECT:'Connexion', DISCONNECT:'Déconnexion',
          };
          tLine(`<span class="t-muted">[ATM] ${verbs[sub]} du GAB ${atmId}</span>`);
          try {
            const r = await apiMap[sub](atmId);
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            tLine(`<span class="t-ok">✓ ${r.message}</span>`);
            if (r.status) tRow('État', r.status, r.status === 'ACTIVE' ? 't-ok' : r.status === 'BLOCKED' ? 't-err' : 't-warn');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'KCV') {
          if (!atmId) { tLine('<span class="t-err">Usage : ATM KCV &lt;id&gt;</span>'); break; }
          try {
            const r = await PayHsmApi.adminAtmKcv(atmId);
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            tLine(`<span class="t-info">${atmId} KEY CHECK VALUES</span>`);
            tLine('  ─────────────────────────');
            tRow('TMK KCV', r.tmk_kcv || '—', r.tmk_present ? 't-ok' : 't-warn');
            tRow('TPK KCV', r.tpk_kcv || '—', r.tpk_present ? 't-ok' : 't-warn');
            tRow('TAK KCV', r.tak_kcv || '—', r.tak_present ? 't-ok' : 't-warn');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else if (sub === 'ROTATE-KEYS') {
          if (!atmId) { tLine('<span class="t-err">Usage : ATM ROTATE-KEYS &lt;id&gt;</span>'); break; }
          tLine(`<span class="t-info">[ATM] Rotation des clés pour ${atmId} via commandes HSM</span>`);
          try {
            const r = await PayHsmApi.adminAtmRotate(atmId);
            if (r.rc !== 0) { tLine(`<span class="t-err">✗ ${r.message}</span>`); break; }
            for (const k of (r.keys || [])) {
              if (k.rc === 0) {
                tLine(`  <span class="t-ok">✓ Nouvelle ${k.key} générée et protégée sous LMK</span>`);
                tLine(`         KCV : <span class="t-ok">${k.kcv}</span>`);
              }
            }
            tLine(`<span class="t-ok">✓ ${r.message}</span>`);
            tLine('<span class="t-ok">✓ Anciennes clés archivées dans le coffre</span>');
          } catch (e) { tLine(`<span class="t-err">✗ ${e.message}</span>`); }

        } else {
          tLine('<span class="t-err">ATM : sous-commande inconnue</span>');
          tLine('  <span class="t-muted">Voir <span class="t-cmd">HELP</span> pour la liste complète</span>');
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
      const all = [
        'HEALTH','STATUS','LMK','FRAGMENTS','VAULT','LOGS','MUTATE','VARS','CLEAR',
        'MODE PAYSHIELD','KEYEX ZPK','0001A00001U00','SWITCH PULL','A0','A6','A8',
        /* Nouvelles commandes gestion des clés */
        '0001A0|','0001A4|','0001A6|','0001A8|',
        '0001B0|','0001BS','0001BW','0001CS|',
        '0001K8|','0001KA|','0001NE|',
        /* Switch/ATM */
        'SWITCH INIT','SWITCH STATUS','SWITCH PROVISION','SWITCH LOGS',
        'ATM ADD','ATM LIST','ATM STATUS','ATM PROVISION',
        'ATM ENABLE','ATM DISABLE','ATM BLOCK','ATM REMOVE',
        'ATM KCV','ATM CONNECT','ATM DISCONNECT','ATM ROTATE-KEYS',
      ];
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
  tLine('<span class="t-muted">Tapez <span class="t-cmd">help</span> · commandes Thales complètes avec espaces</span>');
  tLine('<span class="t-muted">Ex. <span class="t-cmd">KEYEX ZPK</span> · <span class="t-cmd">0001A00001U00</span> (13 car.) · <span class="t-cmd">SWITCH PULL</span></span>');
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

