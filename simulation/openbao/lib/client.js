/**
 * Client HTTP OpenBao KV v2 — lecture/écriture du coffre Switch.
 * PayHSM garde la LMK ; OpenBao ne reçoit que des cryptogrammes + lmkRef (empreinte).
 */
import { OPENBAO } from './config.js';

function fetchWithTimeout(url, opts = {}, ms = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(t));
}

function enabled() {
  return OPENBAO.enabled;
}

function baseUrl() {
  return OPENBAO.addr.replace(/\/$/, '');
}

function dataUrl() {
  const mount = OPENBAO.kvMount.replace(/^\//, '').replace(/\/$/, '');
  const p = OPENBAO.kvPath.replace(/^\//, '').replace(/\/$/, '');
  return `${baseUrl()}/v1/${mount}/data/${p}`;
}

function metaUrl() {
  const mount = OPENBAO.kvMount.replace(/^\//, '').replace(/\/$/, '');
  const p = OPENBAO.kvPath.replace(/^\//, '').replace(/\/$/, '');
  return `${baseUrl()}/v1/${mount}/metadata/${p}`;
}

function headers() {
  const h = { 'Content-Type': 'application/json' };
  if (OPENBAO.token) h['X-Vault-Token'] = OPENBAO.token;
  return h;
}

export function isOpenBaoEnabled() {
  return enabled();
}

export async function openBaoHealth() {
  if (!enabled()) {
    return { ok: false, error: 'OPENBAO_ADDR non configuré' };
  }
  try {
    const res = await fetchWithTimeout(`${baseUrl()}/v1/sys/health`, {
      headers: headers(),
    }, 4000);
    const sealed = res.headers.get('x-vault-sealed') === 'true';
    return {
      ok: res.ok && !sealed,
      sealed,
      httpStatus: res.status,
      addr: OPENBAO.addr,
      kvPath: OPENBAO.kvPath,
    };
  } catch (e) {
    return { ok: false, error: e.message, addr: OPENBAO.addr };
  }
}

/** @param {{ lmkRef: string, dataDir?: string|null, savedAt: string, keys: object[] }} payload */
export async function saveSwitchVaultToOpenBao(payload) {
  if (!enabled()) return { saved: false, reason: 'disabled' };
  const res = await fetchWithTimeout(dataUrl(), {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ data: payload }),
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { message: text.slice(0, 200) }; }
  if (!res.ok) {
    throw new Error(body.errors?.[0] || body.message || `OpenBao write HTTP ${res.status}`);
  }
  return {
    saved: true,
    path: OPENBAO.kvPath,
    version: body?.data?.metadata?.version,
  };
}

/** @param {string} expectedLmkRef */
export async function loadSwitchVaultFromOpenBao(expectedLmkRef) {
  if (!enabled()) return null;
  const res = await fetchWithTimeout(dataUrl(), {
    method: 'GET',
    headers: headers(),
  });
  if (res.status === 404) return null;
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch {
    throw new Error('OpenBao : réponse invalide');
  }
  if (!res.ok) {
    throw new Error(body.errors?.[0] || body.message || `OpenBao read HTTP ${res.status}`);
  }
  const payload = body?.data?.data;
  if (!payload || payload.lmkRef !== expectedLmkRef || !Array.isArray(payload.keys)) {
    return null;
  }
  return payload;
}

export async function clearSwitchVaultInOpenBao() {
  if (!enabled()) return;
  try {
    await fetchWithTimeout(metaUrl(), {
      method: 'DELETE',
      headers: headers(),
    }, 8000);
  } catch (e) {
    console.log('[OpenBao] Suppression métadonnées coffre:', e.message);
  }
}

export async function readSwitchVaultRawFromOpenBao() {
  if (!enabled()) {
    return { found: false, reason: 'OPENBAO_ADDR non configuré' };
  }
  const res = await fetchWithTimeout(dataUrl(), {
    method: 'GET',
    headers: headers(),
  });
  if (res.status === 404) return { found: false };
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch {
    throw new Error('OpenBao : réponse invalide');
  }
  if (!res.ok) {
    throw new Error(body.errors?.[0] || body.message || `OpenBao read HTTP ${res.status}`);
  }
  const payload = body?.data?.data;
  const meta = body?.data?.metadata;
  return {
    found: Boolean(payload),
    version: meta?.version,
    createdTime: meta?.created_time,
    updatedTime: meta?.updated_time,
    payload: payload || null,
  };
}
