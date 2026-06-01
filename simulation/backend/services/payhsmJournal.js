/**
 * Journal simulateur ↔ appels HTTP réels vers payhsm-httpd (Banque A).
 */
import { bus } from '../bus.js';
import { CONFIG } from '../config.js';
import { HsmA } from '../hsm/hsmReal.js';

export const PAYHSM = 'PayHSM (Banque A)';
export const GAP_ACTOR = 'EPP-A (GAP)';

async function lastPayhsmAuditLine() {
  try {
    const logs = await HsmA.securityLogs();
    const arr = logs.logs || [];
    if (!arr.length) return null;
    return arr[arr.length - 1].message;
  } catch {
    return null;
  }
}

/**
 * @param {object} p
 * @param {string} p.from — qui envoie la demande (ex. SWITCH-A, EPP-A GAP)
 * @param {string} [p.replyTo] — destinataire de la réponse PayHSM
 */
export async function payhsmCall({
  txId,
  stage,
  from,
  replyTo,
  api,
  label,
  responseLabel,
  keysHint,
  callFn,
}) {
  const dest = replyTo || from;
  bus.publish({
    txId,
    stage,
    from,
    to: PAYHSM,
    kind: 'request',
    label: keysHint ? `${label} → POST ${api} · ${keysHint}` : `${label} → POST ${api}`,
    payload: { api, url: CONFIG.HSM_A_URL, keys: keysHint },
  });

  const r = await callFn();
  const audit = await lastPayhsmAuditLine();
  const ok = r.rc === 0 || r.rc === undefined || r.pinBlock || r.pinBlockZpk;

  bus.publish({
    txId,
    stage: stage + 1,
    from: PAYHSM,
    to: dest,
    kind: ok ? 'response' : 'error',
    label:
      responseLabel ||
      (audit ? `PayHSM : ${audit}` : `${label} — réponse (rc=${r.rc ?? '?'})`),
    payload: { api, rc: r.rc, audit },
  });

  return r;
}
