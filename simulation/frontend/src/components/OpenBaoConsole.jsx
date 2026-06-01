import React, { useCallback, useEffect, useState } from 'react';
import { Api } from '../api.js';

const COMMANDS = [
  '# 1) OpenBao (Docker, mode dev)',
  './simulation/openbao/start.sh',
  '',
  '# 2) Variables (backend simulateur)',
  'export OPENBAO_ADDR=http://127.0.0.1:8200',
  'export OPENBAO_TOKEN=payhsm-dev-token',
  '',
  '# 3) Backend + frontend',
  'cd simulation/backend && npm start',
  '# autre terminal :',
  'cd simulation/frontend && npm run dev',
  '# → http://127.0.0.1:5173  onglet OpenBao',
  '',
  '# 4) Vérifications CLI',
  'curl -s http://127.0.0.1:4000/api/openbao/status | python3 -m json.tool',
  'curl -s http://127.0.0.1:4000/api/openbao/coffre | python3 -m json.tool',
  './simulation/openbao/show-coffre.sh',
  '',
  '# 5) PayHSM + coffre',
  './src/lib/payhsm/bin/payhsm-httpd 8765',
  "# puis « Initialiser coffre Switch »",
].join('\n');

function CopyBtn({ text, label = 'Copier' }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch { /* ignore */ }
  };
  return (
    <button type="button" onClick={copy}
      className="text-[10px] px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300">
      {done ? '✓' : label}
    </button>
  );
}

function KeyList({ keys, accent }) {
  if (!keys?.length) return null;
  return (
    <div className="max-h-56 overflow-y-auto text-[10px] font-mono">
      {keys.map((k) => (
        <div key={k.key_id} className="py-1 border-b border-white/5">
          <span className={accent}>{k.key_id}</span>
          <span className="text-slate-500">
            {' '}· {k.key_type}
            {k.kcv ? ` · KCV ${k.kcv}` : ''}
            {k.wrapped_by ? ` · ${k.wrapped_by}` : ''}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function OpenBaoConsole() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    setBusy(true);
    setErr(null);
    try { setData(await Api.openbaoCoffre()); }
    catch (e) { setErr(e.message); setData(null); }
    setBusy(false);
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, [refresh]);

  const enabled = data?.enabled;
  const ok = data?.health?.ok;
  const ob = data?.openbao;
  const mem = data?.memory;

  return (
    <div className="space-y-4">
      <div className="bg-slate-900/60 rounded-xl ring-1 ring-teal-500/30 p-4">
        <div className="flex flex-wrap items-start justify-between gap-2 mb-3">
          <div>
            <h2 className="text-lg font-semibold text-teal-300">OpenBao — coffre Switch</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Module <code className="text-teal-500/80">simulation/openbao/</code> — OpenBao{' '}
              <strong className="text-teal-400/90">réel</strong> (Docker :8200). Cet onglet = vue du
              simulateur (pas :8200/ui). Stockage : cryptogrammes Switch + <code>lmkRef</code> — pas la LMK.
            </p>
          </div>
          <button type="button" onClick={refresh} disabled={busy}
            className="text-xs px-3 py-1.5 rounded-lg bg-teal-600/80 hover:bg-teal-500 disabled:opacity-50">
            {busy ? 'Actualisation…' : 'Actualiser'}
          </button>
        </div>
        {!enabled && (
          <p className="text-sm text-amber-300/90">
            OpenBao inactif — exportez OPENBAO_ADDR puis relancez le backend.
          </p>
        )}
        {enabled && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="rounded-lg bg-slate-800/80 p-3 ring-1 ring-white/5">
              <p className="text-slate-500 mb-1">API</p>
              <p className={`font-mono ${ok ? 'text-teal-300' : 'text-rose-400'}`}>
                {ok ? '● connecté' : '○ indisponible'}
              </p>
              <p className="font-mono text-slate-400 mt-1 break-all">{data.addr}</p>
            </div>
            <div className="rounded-lg bg-slate-800/80 p-3 ring-1 ring-white/5">
              <p className="text-slate-500 mb-1">KV</p>
              <p className="font-mono text-slate-300">{data.kvMount}/data/{data.kvPath}</p>
              {ob?.version != null && <p className="text-slate-500 mt-1">version {ob.version}</p>}
            </div>
            <div className="rounded-lg bg-slate-800/80 p-3 ring-1 ring-white/5">
              <p className="text-slate-500 mb-1">Secret</p>
              <p className="font-mono text-slate-300">{ob?.found ? `${ob.keyCount} clé(s)` : 'vide'}</p>
              {ob?.lmkRef && <p className="text-slate-500 mt-1 font-mono text-[10px]">LMK {ob.lmkRef}</p>}
            </div>
          </div>
        )}
        {err && <p className="text-xs text-rose-400 mt-3">{err}</p>}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-4">
          <h3 className="text-sm font-semibold text-slate-200 mb-2">Clés OpenBao (KV)</h3>
          {enabled && !ob?.found && (
            <p className="text-xs text-slate-500">Aucun secret — initialisez le coffre Switch.</p>
          )}
          <KeyList keys={ob?.keys} accent="text-teal-200" />
          {ob?.savedAt && <p className="text-[10px] text-slate-600 mt-2">sauvegardé {ob.savedAt}</p>}
        </div>
        <div className="bg-slate-900/60 rounded-xl ring-1 ring-violet-500/20 p-4">
          <h3 className="text-sm font-semibold text-violet-200 mb-2">
            Mémoire simulateur ({mem?.keyCount ?? 0})
          </h3>
          <KeyList keys={mem?.keys} accent="text-violet-200" />
          {!mem?.keys?.length && <p className="text-xs text-slate-600">Vide — HSM + provision requis.</p>}
        </div>
      </div>
      <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <h3 className="text-sm font-semibold text-slate-200">Commandes</h3>
          <CopyBtn text={COMMANDS} label="Copier tout" />
        </div>
        <pre className="text-[11px] font-mono text-slate-400 whitespace-pre-wrap leading-relaxed">{COMMANDS}</pre>
      </div>
    </div>
  );
}
