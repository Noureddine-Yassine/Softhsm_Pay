/** Client API — console technique HSM (payhsm-httpd) */
const PayHsmApi = (() => {
  let base = localStorage.getItem('payhsm_api') || 'http://127.0.0.1:8765';

  function setBase(url) {
    base = url.replace(/\/$/, '');
    localStorage.setItem('payhsm_api', base);
  }

  async function request(path, body, timeoutMs = 8000) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(base + path, {
        method: body ? 'POST' : 'GET',
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 120)); }
      if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
      return data;
    } catch (e) {
      if (e.name === 'AbortError') {
        throw new Error(`Délai dépassé (${timeoutMs}ms) — payhsm-httpd occupé ou injoignable ?`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    setBase,
    getBase: () => base,
    health: () => request('/api/health'),
    status: () => request('/api/status'),
    provision: (dataDir) =>
      request('/api/provision', { dataDir }),
    startup: () =>
      request('/api/startup', {}),
    shutdown: () => request('/api/shutdown', {}),
    lmkStatus: () => request('/api/lmk/status'),
    lmkFragments: () => request('/api/lmk/fragments'),
    securityLogs: () => request('/api/security/logs'),
    vault: () => request('/api/vault'),
    vaultExport: () => request('/api/vault/export'),
    vaultClear: () => request('/api/vault/clear', {}),
    mutateFragments: () => request('/api/lmk/mutate', {}),

    /* Commandes HSM standard (style Thales payShield) */

    /* A0 : générer une clé aléatoire protégée sous LMK
     *   keyType : type de clé (ZMK, ZPK, TMK…)
     *   keyLen  : taille en octets — 16 (AES-128), 24 (AES-192), 32 (AES-256) */
    hsmA0: (keyType, keyLen) =>
      request('/api/hsm/a0', { keyType, ...(keyLen ? { keyLen } : {}) }),

    /* A6 : importer une clé externe (sous ZMK) → rechiffrer sous LMK
     *   zmkCryptogram  : ZMK protégée sous LMK (88 hex, AES-256-GCM)
     *   keyUnderZmk    : clé importée chiffrée sous ZMK (32 hex, AES-ECB)
     *   keyType        : type de la clé (ZPK, TPK, TAK…) */
    hsmA6: (zmkCryptogram, keyUnderZmk, keyType) =>
      request('/api/hsm/a6', { zmkCryptogram, keyUnderZmk, keyType }),

    /* A8 : consultation temporaire d'une clé sous LMK → KCV (ou clair si flag V)
     *   keyCryptogram  : clé sous LMK (88 hex, AES-256-GCM)
     *   flag           : "H" = KCV seulement (défaut) | "V" = clé claire + KCV
     *   keyType        : type de la clé (informatif) */
    hsmA8: (keyCryptogram, flag, keyType) =>
      request('/api/hsm/a8', { keyCryptogram, flag, keyType }),

    /* Protocole wire brut Thales (A0/A6/A8 en hex) : ex. "0001A01001U" */
    hsmCmd: (cmd) =>
      request('/api/hsm/cmd', { cmd }),

    hsmModeSet: (mode) =>
      request('/api/hsm/mode', { mode }),

    /* Chiffrer une clé 16 octets (32 hex) sous ZMK (AES-ECB) → résultat pour A6 */
    wrapZpk: (zmkCryptogram, keyHex) =>
      request('/api/switch/wrap-zpk', { zmkCryptogram, keyHex }),

    exportUnderZmk: (zmkCryptogram, keyCryptogram) =>
      request('/api/key-exchange/export-under-zmk', { zmkCryptogram, keyCryptogram }),

    /* Étape 0 : génère une MK aléatoire et la stocke chiffrée dans mk.bin */
    lmkInitTrng: (passphrase, dataDir) =>
      request('/api/lmk/init-trng', { passphrase, dataDir }),
    mkGenerate: (passphrase, dataDir) =>
      request('/api/lmk/mk-generate', { passphrase, dataDir }),

    /* Statut mk.bin + fichiers parts admin*_share.sss */
    mkStatus: (dataDir) =>
      request('/api/lmk/mk-status', { dataDir }),

    /* Étape 1 : génère les 3 parts SSS depuis mk.bin → admin1/2/3_share.sss (MK requise) */
    shamirGenerate: (passphrase, dataDir, shareDir) =>
      request('/api/lmk/shamir-generate', {
        passphrase,
        dataDir,
        ...(shareDir && shareDir !== dataDir ? { shareDir } : {}),
      }),

    /* Étape 2 : reconstruit MK depuis fichiers (ou parts manuelles) → initialise HSM */
    shamirReconstruct: (dataDir, share1, share2, share3) =>
      request('/api/lmk/shamir-reconstruct', {
        dataDir,
        ...(share1 ? { share1, share2, share3 } : {}),
      }),

    /* ── Admin Switch style payShield 10K ── */
    adminSwitchInit:      ()  => request('/api/admin/switch/init',      {}),
    adminSwitchStatus:    ()  => request('/api/admin/switch/status',     {}),
    adminSwitchProvision: ()  => request('/api/admin/switch/provision',  {}),
    adminSwitchLogs:      ()  => request('/api/admin/switch/logs'),

    /* ── Admin ATM/GAB ── */
    adminAtmAdd:        (id, name, location) => request('/api/admin/atm/add',         { id, name, location }),
    adminAtmList:       ()   => request('/api/admin/atm/list',        {}),
    adminAtmStatus:     (id) => request('/api/admin/atm/status',      { id }),
    adminAtmProvision:  (id) => request('/api/admin/atm/provision',   { id }),
    adminAtmEnable:     (id) => request('/api/admin/atm/enable',      { id }),
    adminAtmDisable:    (id) => request('/api/admin/atm/disable',     { id }),
    adminAtmBlock:      (id) => request('/api/admin/atm/block',       { id }),
    adminAtmRemove:     (id) => request('/api/admin/atm/remove',      { id }),
    adminAtmKcv:        (id) => request('/api/admin/atm/kcv',         { id }),
    adminAtmConnect:    (id) => request('/api/admin/atm/connect',     { id }),
    adminAtmDisconnect: (id) => request('/api/admin/atm/disconnect',  { id }),
    adminAtmRotate:     (id) => request('/api/admin/atm/rotate-keys', { id }),
  };
})();

/** Trames payShield / Thales (A0 mode 1, A6 import) */
const PayHsmWire = (() => {
  const PS_KEY_TYPE = {
    ZMK: '000', ZPK: '001', TPK: '002', TAK: '003', TMK: '007',
    PVK: '008', IMK: '109', ZAK: '009', IMK_ALT: '00B',
  };

  const OPERATOR_COMMANDS = {
    TMK: { a0: '0001A00007U00', transport: null, type: '007', storeOnly: true },
    ZPK: { a0: '0001A00001U00', transport: 'ZMK', type: '001' },
    TPK: { a0: '0001A00002U00', transport: 'TMK', type: '002' },
    TAK: { a0: '0001A00003U00', transport: 'TMK', type: '003' },
    PVK: { a0: '0001A00008U00', transport: 'ZMK', type: '008' },
    IMK: { a0: '0001A00109U00', transport: 'ZMK', type: '109' },
  };

  function keyTypeCode(name) {
    const n = String(name || '').toUpperCase();
    const c = PS_KEY_TYPE[n];
    if (!c) throw new Error(`KEY_TYPE inconnu: ${name}`);
    return c;
  }

  function transportKeyId(keyTypeName) {
    const n = String(keyTypeName || '').toUpperCase();
    if (n === 'TPK' || n === 'TAK') return 'TMK';
    if (n === 'ZPK' || n === 'PVK' || n === 'IMK') return 'ZMK';
    throw new Error(`Transport inconnu pour ${n}`);
  }

  function buildA8Wire(keyTypeName, kek88, key88) {
    return buildA8Export('0001', keyTypeName, kek88, key88);
  }

  /** A8 auto — ZMK/TMK lue dans le coffre HSM (99 car., sans ZMK dans la trame) */
  function buildA8VaultAuto(hdr, keyTypeName, keyGcm88, opts = {}) {
    const key = String(keyGcm88 || '').toUpperCase();
    if (key.length !== 88) throw new Error('Clé source : 88 hex');
    const sch = (opts.keyScheme || 'U').charAt(0);
    return `${hdr || '0001'}A8L${keyTypeCode(keyTypeName)}${sch}${key}`;
  }

  function toThalesBlock(scheme, value) {
    const v = String(value || '').toUpperCase();
    if (v.length === 33) return v;
    if (v.length === 32) return `${scheme || 'U'}${v}`;
    throw new Error('32 hex ou bloc 33 requis');
  }

  /** A0 mode 0 — génération seule (doc Thales §6.4.2 / §7.4.1) */
  function buildA0Mode0(hdr, keyTypeName, scheme = 'U', lmkId = '00') {
    return `${hdr || '0001'}A00${keyTypeCode(keyTypeName)}${scheme}${lmkId}`;
  }

  function parseA1Mode0(raw) {
    const s = String(raw || '');
    if (s.slice(6, 8) !== '00') throw new Error(`A1 erreur ${s.slice(6, 8)}`);
    const d = s.slice(8);
    if (d.length < 39) throw new Error('A1 mode 0 data trop courte');
    return { keyUnderLmk: d.slice(0, 33), kcv: d.slice(33, 39) };
  }

  function parseA1Generate(raw) {
    const s = String(raw || '');
    if (s.slice(6, 8) !== '00') throw new Error(`A1 erreur ${s.slice(6, 8)}`);
    const d = s.slice(8);
    if (d.length < 95) throw new Error('A1 data trop courte');
    return {
      scheme: d.slice(0, 1),
      cryptogram: d.slice(1, 89),
      kcv: d.slice(89, 95),
    };
  }

  /** A8 — export clé sous LMK vers ZMK (187 car.) */
  function buildA8Export(hdr, keyTypeName, zmkGcm88, keyGcm88, opts = {}) {
    const zmk = String(zmkGcm88 || '').toUpperCase();
    const key = String(keyGcm88 || '').toUpperCase();
    if (zmk.length !== 88 || key.length !== 88) throw new Error('ZMK et clé : 88 hex chacun');
    return `${hdr || '0001'}A8${opts.zmkScheme || 'U'}${zmk}${keyTypeCode(keyTypeName)}${opts.keyScheme || 'U'}${key}`;
  }

  function parseA9Export(raw) {
    const s = String(raw || '');
    if (s.slice(6, 8) !== '00') throw new Error(`A9 erreur ${s.slice(6, 8)}`);
    const d = s.slice(8);
    if (d.length < 39) throw new Error('A9 data trop courte');
    return {
      keyUnderZmk: d.slice(0, 33),
      kcv: d.slice(33, 39),
      keyUnderZmk32: d.length >= 34 ? d.slice(1, 33) : d.slice(0, 32),
    };
  }

  function buildA0GenExport(hdr, keyTypeName, zmkGcm88, opts = {}) {
    const type = keyTypeCode(keyTypeName);
    const zmk = String(zmkGcm88 || '').toUpperCase();
    if (zmk.length !== 88) throw new Error('ZMK : 88 hex');
    return `${hdr || '0001'}A01${type}${opts.lmkScheme || 'U'}${zmk}${opts.zmkScheme || 'U'}${opts.exportable ?? '0'}`;
  }

  function parseA1GenExport(raw) {
    const s = String(raw || '');
    if (s.slice(6, 8) !== '00') throw new Error(`A1 erreur ${s.slice(6, 8)}`);
    const d = s.slice(8);
    return {
      keyUnderLmk: d.slice(0, 33),
      keyUnderZmk: d.slice(33, 66),
      kcv: d.slice(66, 72),
      kcvZmk: d.slice(72, 78),
      keyUnderZmk32: d.slice(34, 66),
    };
  }

  function buildA6Import(hdr, keyTypeName, zmkGcm88, keyUnderZmk, kcvExpected) {
    const kcv = String(kcvExpected || '').toUpperCase().slice(0, 6);
    return `${hdr || '0001'}A6${keyTypeCode(keyTypeName)}${String(zmkGcm88).toUpperCase()}${toThalesBlock('U', keyUnderZmk)}UU${kcv}`;
  }

  function parseA7Import(raw) {
    const s = String(raw || '');
    if (s.slice(6, 8) !== '00') throw new Error(`A7 erreur ${s.slice(6, 8)}`);
    const d = s.slice(8);
    return { keyUnderLmk: d.slice(0, 33), kcv: d.slice(33, 39) };
  }

  async function ensurePayshieldMode() {
    await PayHsmApi.hsmModeSet('PAYSHIELD_COMPAT');
  }

  function resolvePart(tok, resolve) {
    if (!tok) return '';
    const r = resolve(tok);
    return String(r ?? tok).trim().toUpperCase();
  }

  function toTypeCode(tok) {
    const t = String(tok || '').toUpperCase();
    if (/^\d{3}$/.test(t)) return t;
    return keyTypeCode(t);
  }

  function toGcm88(tok, resolve) {
    const v = resolvePart(tok, resolve);
    if (v.length === 88) return v;
    throw new Error(`Cryptogramme sous LMK : 88 hex attendus (${v.length} reçus)`);
  }

  /** Ligne console → trame wire (0001 + A0/A6/A8 + paramètres concaténés). */
  function buildWireFromSpaced(parts, resolve) {
    let i = 0;
    let hdr = '0001';
    if (/^[0-9A-Fa-f]{4}$/.test(parts[0])) {
      hdr = parts[0].toUpperCase();
      i = 1;
    }
    const verb = (parts[i] || '').toUpperCase();
    const tail = parts.slice(i + 1);
    if (verb !== 'A0' && verb !== 'A6' && verb !== 'A8') return null;

    if (verb === 'A0') {
      const mode = resolvePart(tail[0], resolve);
      if (mode !== '0' && mode !== '1') return null;
      if (mode === '1') {
        if (tail.length < 6) throw new Error('A0 1 : A0 1 <TYPE> <SCH_LMK> <ZMK_88> <SCH_ZMK> <EXPORT>');
        const type = toTypeCode(tail[1]);
        const lmkSch = resolvePart(tail[2], resolve).charAt(0) || 'U';
        const zmk = toGcm88(tail[3], resolve);
        const zmkSch = resolvePart(tail[4], resolve).charAt(0) || 'U';
        const exp = resolvePart(tail[5], resolve).charAt(0) || '0';
        return `${hdr}A01${type}${lmkSch}${zmk}${zmkSch}${exp}`;
      }
      if (tail.length < 3) throw new Error('A0 0 : A0 0 <TYPE> <SCHEME>');
      const type = toTypeCode(tail[1]);
      const sch = resolvePart(tail[2], resolve).charAt(0) || 'U';
      const lmkId = tail[3] ? resolvePart(tail[3], resolve).slice(0, 2) : '00';
      return `${hdr}A00${type}${sch}${lmkId}`;
    }

    if (verb === 'A6') {
      const t0 = resolvePart(tail[0], resolve);
      if (!/^\d{3}$/.test(t0) && !PS_KEY_TYPE[t0]) return null;
      if (tail.length < 6) throw new Error('A6 : A6 <TYPE> <ZMK_88> <KEY_33> <SCH_KEY> <SCH_ZMK> <KCV>');
      const type = toTypeCode(tail[0]);
      const zmk = toGcm88(tail[1], resolve);
      const blkRaw = resolvePart(tail[2], resolve);
      const keySch = resolvePart(tail[3], resolve).charAt(0) || 'U';
      const zmkSch = resolvePart(tail[4], resolve).charAt(0) || 'U';
      const kcv = resolvePart(tail[5], resolve).replace(/[^0-9A-F]/gi, '').slice(0, 6);
      const blk = blkRaw.length === 33 ? blkRaw : toThalesBlock(keySch, blkRaw);
      return `${hdr}A6${type}${zmk}${blk}${keySch}${zmkSch}${kcv}`;
    }

    if (verb === 'A8') {
      const sch0 = resolvePart(tail[0], resolve);
      if (sch0.length !== 1 || !/^[UXYZT]$/i.test(sch0)) return null;
      if (tail.length < 5) throw new Error('A8 : A8 <SCH_ZMK> <ZMK_88> <TYPE> <SCH_KEY> <KEY_88>');
      const zmkSch = sch0.charAt(0);
      const zmk = toGcm88(tail[1], resolve);
      const type = toTypeCode(tail[2]);
      const keySch = resolvePart(tail[3], resolve).charAt(0) || 'U';
      const key = toGcm88(tail[4], resolve);
      return `${hdr}A8${zmkSch}${zmk}${type}${keySch}${key}`;
    }

    return null;
  }

  function isThalesSpaced(parts) {
    let i = 0;
    if (/^[0-9A-Fa-f]{4}$/.test(parts[0])) i = 1;
    const verb = (parts[i] || '').toUpperCase();
    if (verb === 'A0') return parts[i + 1] === '0' || parts[i + 1] === '1';
    if (verb === 'A6') {
      const t = String(parts[i + 1] || '').toUpperCase();
      return /^\d{3}$/.test(t) || !!PS_KEY_TYPE[t];
    }
    if (verb === 'A8') {
      const s = (parts[i + 1] || '').toUpperCase();
      return s.length === 1 && /^[UXYZT]$/.test(s);
    }
    return false;
  }

  /** Décodage affichage terminal selon commande. */
  function decodeThalesResponse(parts, rawResponse) {
    const s = String(rawResponse || '');
    let i = 0;
    if (/^[0-9A-Fa-f]{4}$/.test(parts[0])) i = 1;
    const verb = (parts[i] || '').toUpperCase();
    const err = s.slice(6, 8);
    if (err !== '00') return { ok: false, err, verb };
    if (verb === 'A0') {
      const mode = parts[i + 1];
      if (mode === '1') return { ok: true, verb, mode: '1', ...parseA1GenExport(s) };
      return { ok: true, verb, mode: '0', ...parseA1Mode0(s) };
    }
    if (verb === 'A6') return { ok: true, verb, ...parseA7Import(s) };
    if (verb === 'A8') return { ok: true, verb, ...parseA9Export(s) };
    return { ok: true, verb, raw: s };
  }

  return {
    PS_KEY_TYPE, OPERATOR_COMMANDS,
    buildA0Mode0, parseA1Mode0,
    buildA8Export, parseA9Export, buildA8Wire, buildA8VaultAuto,
    buildA0GenExport, parseA1GenExport,
    buildA6Import, parseA7Import,
    ensurePayshieldMode, toThalesBlock, keyTypeCode, transportKeyId,
    buildWireFromSpaced, isThalesSpaced, decodeThalesResponse, resolvePart,
  };
})();

/** Simulateur Switch (port 4000) — A6 auto + coffre */
const PayHsmSimApi = (() => {
  let base = localStorage.getItem('payhsm_sim_api') || 'http://127.0.0.1:4000';

  function setBase(url) {
    base = url.replace(/\/$/, '');
    localStorage.setItem('payhsm_sim_api', base);
  }

  async function request(path, body) {
    const res = await fetch(base + path, {
      method: body ? 'POST' : 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 120)); }
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
    return data;
  }

  return {
    setBase,
    switchInit: () => request('/api/switch/init', {}),
    switchReset: () => request('/api/switch/reset', {}),
    storeKey: (p) => request('/api/switch/store-key', p),
    importA6: (p) => request('/api/switch/import-a6', p),
    deriveGab: () => request('/api/switch/derive-gab-keys', {}),
    exchangeLogs: () => request('/api/switch/exchange-logs'),
    vault: () => request('/api/vault'),
  };
})();
