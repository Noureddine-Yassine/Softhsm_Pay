import React, { useCallback, useEffect, useState } from 'react';
import { Api } from '../api.js';

export default function KeyVault() {
  const [keys, setKeys] = useState([]);
  const [logs, setLogs] = useState([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [okMsg, setOkMsg] = useState(null);

  const load = useCallback(async (tryRestore = false) => {
    try {
      let r = await Api.vault();
      let list = r.SWITCH_KEY_VAULT || [];
      if (!list.length && tryRestore) {
        await Api.switchInit().catch(() => {});
        r = await Api.vault();
        list = r.SWITCH_KEY_VAULT || [];
      }
      setKeys(list);
      setErr(null);
      return list;
    } catch (e) {
      setErr(e.message);
      setKeys([]);
      return [];
    }
  }, []);

  const loadLogs = () =>
    fetch('/api/switch/exchange-logs')
      .then((r) => r.json())
      .then((d) => setLogs(d.logs || []))
      .catch(() => setLogs([]));

  useEffect(() => {
    load(true);
    loadLogs();
    const t = setInterval(() => {
      load(false);
      loadLogs();
    }, 8000);
    return () => clearInterval(t);
  }, [load]);

  const refreshVault = async () => {
    setBusy(true);
    setErr(null);
    setOkMsg(null);
    const list = await load(true);
    await loadLogs();
    setOkMsg(list.length
      ? `${list.length} clé(s) — coffre restauré depuis disque/OpenBao si besoin`
      : 'Coffre vide — établir les clés dans le terminal HSM (:8765) puis SWITCH PULL');
    setBusy(false);
  };

  const switchInit = async () => {
    setBusy(true);
    setErr(null);
    setOkMsg(null);
    try {
      const r = await Api.switchInit();
      await load(false);
      setOkMsg(r.message || 'Switch initialisé');
    } catch (e) {
      setErr(e.message);
    }
    setBusy(false);
  };

  const saveVault = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await Api.switchProvision();
      setKeys(r.keys || []);
      const p = r.persisted || {};
      setOkMsg(
        p.disk || p.openbao
          ? `Coffre sauvegardé (disque${p.openbao ? ' + OpenBao' : ''}) — ${r.count ?? keys.length} clé(s)`
          : (r.hint || 'Sauvegarde — vérifiez que le HSM est démarré (startup sur :8765)'),
      );
    } catch (e) {
      setErr(e.message);
    }
    setBusy(false);
  };

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-violet-500/30 p-4">
      <h3 className="text-sm font-semibold text-violet-300 mb-1">SWITCH_KEY_VAULT — mode manuel</h3>
      <p className="text-[11px] text-slate-500 mb-2">
        Clés créées dans le <strong className="text-violet-300/90">terminal HSM :8765</strong> (NE/A0/EXPORT).
        Sauvegarde automatique à chaque <code className="text-emerald-400/90">SWITCH PULL</code> /{' '}
        <code>STORE</code> — persistance disque + OpenBao (même LMK).
      </p>
      <ol className="text-[10px] text-slate-500 mb-2 list-decimal list-inside space-y-0.5">
        <li>ZMK : <code className="text-amber-200/80">NE|ZMK|16|3|Y</code> puis <code>A4</code> → <code>SWITCH STORE ZMK</code></li>
        <li>TMK : idem → <code>SWITCH STORE TMK</code></li>
        <li>TPK/TAK : <code>A0</code> + <code>A8/L</code> → <code>SWITCH PULL TPK</code> / <code>TAK</code></li>
      </ol>
      <div className="flex flex-wrap gap-2 mb-2">
        <button
          type="button"
          onClick={refreshVault}
          disabled={busy}
          className="text-xs px-3 py-1 rounded bg-teal-600/70 hover:bg-teal-500 disabled:opacity-50"
        >
          Actualiser
        </button>
        <button
          type="button"
          onClick={switchInit}
          disabled={busy}
          className="text-xs px-3 py-1 rounded bg-slate-600/70 hover:bg-slate-500 disabled:opacity-50"
        >
          Restaurer (SWITCH INIT)
        </button>
        <button
          type="button"
          onClick={saveVault}
          disabled={busy}
          className="text-xs px-3 py-1 rounded bg-violet-600/70 hover:bg-violet-500 disabled:opacity-50"
        >
          Sauvegarder coffre
        </button>
      </div>
      {err && <p className="text-xs text-rose-400 mb-2">{err}</p>}
      {okMsg && !err && <p className="text-xs text-emerald-400/90 mb-2">{okMsg}</p>}
      <p className="text-[10px] text-amber-200/70 mb-1">Journal A6 Switch</p>
      <div className="max-h-24 overflow-y-auto text-[9px] font-mono mb-2 text-slate-400">
        {logs.length === 0 && <p>(vide — EXPORT depuis terminal HSM)</p>}
        {logs.map((e, i) => (
          <div key={i}>
            [{new Date(e.ts).toLocaleTimeString()}] {e.message}
          </div>
        ))}
      </div>
      <div className="max-h-40 overflow-y-auto text-[10px] font-mono">
        {keys.length === 0 && (
          <p className="text-slate-600">Vide — cliquez Actualiser après SWITCH PULL, ou Restaurer si déjà sauvegardé.</p>
        )}
        {keys.map((k) => (
          <div key={k.key_id} className="py-1 border-b border-white/5">
            <span className="text-violet-200">{k.key_id}</span>
            <span className="text-slate-500">
              {' '}
              · {k.key_type}
              {k.kcv ? ` · KCV ${k.kcv}` : ''}
              {k.origin ? ` · ${k.origin}` : ''}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
