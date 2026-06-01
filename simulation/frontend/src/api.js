const BASE = '';

async function req(path, body) {
  const res = await fetch(BASE + path, {
    method: body ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const txt = await res.text();
  const isHtml = txt.trimStart().startsWith('<!');
  if (isHtml) {
    if (res.status === 404) {
      throw new Error(
        'Backend obsolète (route ' + path + ' introuvable). '
        + 'Arrêtez le processus sur :4000 puis relancez : cd simulation/backend && npm start '
        + '(ou ./simulation/start.sh)',
      );
    }
    throw new Error('Réponse HTML au lieu de JSON — backend simulation arrêté ou mauvais port ?');
  }
  let data;
  try { data = JSON.parse(txt); } catch {
    throw new Error('Réponse invalide: ' + txt.slice(0, 120));
  }
  if (!res.ok) throw new Error(data.error || data.message || 'HTTP ' + res.status);
  return data;
}

export const Api = {
  health: () => req('/api/health'),
  info: () => req('/api/info'),
  cards: () => req('/api/cards'),
  createCard: (body) => req('/api/cards/create', body),
  cardEmvProfile: (pan) =>
    req('/api/cards/' + encodeURIComponent(String(pan).replace(/\s/g, '')) + '/emv'),
  vault: () => req('/api/vault'),
  openbaoStatus: () => req('/api/openbao/status'),
  openbaoCoffre: () => req('/api/openbao/coffre'),
  switchProvision: (body = {}) => req('/api/switch/provision-keys', body),
  emvPurchase: (body) => req('/api/emv/purchase', body),
  macSign: (body) => req('/api/mac/sign', body),
  macVerify: (body) => req('/api/mac/verify', body),
  reset: () => req('/api/reset', {}),
  runIntra: (pan, pin, amount) => req('/api/scenario/intra', { pan, pin, amount }),
  runInter: (pan, pin, amount) => req('/api/scenario/inter', { pan, pin, amount }),
  issuePvv: (pan, pin, bank) => req('/api/issue-pvv', { pan, pin, bank }),
};

export function subscribeStream(onEvent, onReset) {
  const es = new EventSource('/api/stream');
  es.onmessage = (e) => {
    try { onEvent(JSON.parse(e.data)); } catch { /* ignore */ }
  };
  es.addEventListener('reset', () => onReset && onReset());
  es.onerror = () => {};
  return () => es.close();
}
