import React, { useEffect, useState } from 'react';
import { Api } from '../api.js';

/** Alerte si le backend sur :4000 est une ancienne version (routes manquantes). */
export default function BackendBanner() {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    Api.health()
      .then(setHealth)
      .catch((e) => setHealth({ error: e.message }));
    const t = setInterval(() => {
      Api.health().then(setHealth).catch((e) => setHealth({ error: e.message }));
    }, 8000);
    return () => clearInterval(t);
  }, []);

  if (!health) return null;

  if (health.error) {
    return (
      <div className="mb-4 text-sm bg-rose-950/80 text-rose-200 ring-1 ring-rose-700/50 rounded-lg p-3">
        <strong>Backend simulation injoignable.</strong>{' '}
        Lancez : <code className="font-mono text-xs">cd simulation/backend && npm start</code>
        {' '}ou <code className="font-mono text-xs">./simulation/start.sh</code>
        <div className="text-xs mt-1 opacity-80">{health.error}</div>
      </div>
    );
  }

  if (health.hsmA?.reachable && health.hsmA?.initialized && health.vaultKeys === 0) {
    return (
      <div className="mb-4 text-sm bg-sky-950/80 text-sky-100 ring-1 ring-sky-600/50 rounded-lg p-3">
        <strong>HSM démarré — coffre Switch vide.</strong> Cliquez « Initialiser coffre Switch »,
        puis émettez vos cartes Core Banking (PVV).
      </div>
    );
  }

  if (Number(health.apiVersion) < 2) {
    return (
      <div className="mb-4 text-sm bg-amber-950/80 text-amber-100 ring-1 ring-amber-600/50 rounded-lg p-3">
        <strong>Backend obsolète sur le port 4000</strong> — les routes Core Banking / coffre / EMV / MAC
        sont absentes. Arrêtez l&apos;ancien processus Node puis relancez{' '}
        <code className="font-mono text-xs">./simulation/start.sh</code>
      </div>
    );
  }

  return null;
}
