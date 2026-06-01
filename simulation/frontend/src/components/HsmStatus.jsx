import React, { useEffect, useState } from 'react';
import { Api } from '../api.js';

export default function HsmStatus() {
  const [health, setHealth] = useState(null);
  const [info, setInfo] = useState(null);

  useEffect(() => {
    let mounted = true;
    const ping = async () => {
      try {
        const [h, i] = await Promise.all([Api.health(), Api.info()]);
        if (!mounted) return;
        setHealth(h);
        setInfo(i);
      } catch (e) {
        if (mounted) setHealth({ backend: 'erreur', error: e.message });
      }
    };
    ping();
    const it = setInterval(ping, 8000);
    return () => { mounted = false; clearInterval(it); };
  }, []);

  const hsmA = health?.hsmA;

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-3">
      <h3 className="text-sm font-semibold tracking-wide text-slate-200 mb-3">
        🩺 HSM PayHSM (src/lib/payhsm)
      </h3>

      <div className="flex items-center justify-between bg-slate-950/50 rounded-lg p-2 ring-1 ring-rose-700/30 mb-2">
        <div>
          <div className="text-xs font-semibold text-rose-200">payhsm-httpd · LMK fragmentée</div>
          <div className="text-[10px] font-mono text-slate-500">{health?.hsmA_url || '...'}</div>
        </div>
        <span className={`text-[11px] font-mono ${hsmA?.initialized ? 'text-emerald-400' : 'text-amber-400'}`}>
          {hsmA?.reachable ? (hsmA?.initialized ? 'LMK ACTIVE' : 'NEED STARTUP') : 'OFFLINE'}
        </span>
      </div>

      {info?.lmk && (
        <div className="text-[10px] font-mono text-slate-500 mb-2 space-y-0.5">
          <div>Fragments P1/P2/P3 : {info.lmk.fragmented ? 'oui' : 'non'}</div>
          <div>Intégrité HMAC : {info.lmk.integrityOk ? 'OK' : '—'}</div>
          <div>Réf. : {info.lmk.hmacRefPrefix}</div>
          <div>Clés coffre : {info.keyCount ?? '—'}</div>
        </div>
      )}

      {info?.keys && (
        <div className="bg-slate-950/40 rounded-lg p-2 ring-1 ring-white/5">
          <div className="text-xs text-slate-400 mb-1">KCV (votre LMK — pas de clés en clair)</div>
          <div className="grid grid-cols-2 gap-1 text-[10px] font-mono text-slate-500">
            {Object.entries(info.keys).map(([k, v]) => (
              <div key={k}><span className="text-slate-400">{k}:</span> {v}</div>
            ))}
          </div>
        </div>
      )}

      {health?.vaultKeys === 0 && hsmA?.initialized && (
        <p className="mt-2 text-[11px] text-amber-300">
          Coffre Switch vide → onglet Banque : « Initialiser coffre Switch »
        </p>
      )}

      {!hsmA?.reachable && (
        <p className="mt-2 text-[11px] text-amber-300">
          Lance payhsm-httpd depuis src/lib/payhsm puis Provision + Démarrer sur :8765
        </p>
      )}
    </div>
  );
}
