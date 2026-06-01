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

    /* Chiffrer une clé 16 octets (32 hex) sous ZMK (AES-ECB) → résultat pour A6 */
    wrapZpk: (zmkCryptogram, keyHex) =>
      request('/api/switch/wrap-zpk', { zmkCryptogram, keyHex }),

    /* Étape 0 : génère une MK aléatoire et la stocke chiffrée dans mk.bin */
    lmkInitTrng: (passphrase, dataDir) =>
      request('/api/lmk/init-trng', { passphrase, dataDir }),
    mkGenerate: (passphrase, dataDir) =>
      request('/api/lmk/mk-generate', { passphrase, dataDir }),

    /* Statut mk.bin + fichiers parts admin*_share.sss */
    mkStatus: (dataDir) =>
      request('/api/lmk/mk-status', { dataDir }),

    /* Étape 1 : génère les 3 parts SSS depuis mk.bin → admin1/2/3_share.sss (MK requise) */
    shamirGenerate: (passphrase, dataDir) =>
      request('/api/lmk/shamir-generate', { passphrase, dataDir }),

    /* Étape 2 : reconstruit MK depuis fichiers (ou parts manuelles) → initialise HSM */
    shamirReconstruct: (dataDir, share1, share2, share3) =>
      request('/api/lmk/shamir-reconstruct', {
        dataDir,
        ...(share1 ? { share1, share2, share3 } : {}),
      }),
  };
})();
