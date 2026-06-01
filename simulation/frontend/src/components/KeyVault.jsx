import React, { useEffect, useState } from 'react';
import { Api } from '../api.js';

export default function KeyVault() {
  const [keys, setKeys] = useState([]);
  const [openbao, setOpenbao] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [okMsg, setOkMsg] = useState(null);

  const load = () =>
    Api.vault()
      .then((r) => setKeys(r.SWITCH_KEY_VAULT || []))
      .catch(() => setKeys([]));

  useEffect(() => {
    load();
    Api.openbaoStatus().then(setOpenbao).catch(() => setOpenbao({ enabled: false }));
    const t = setInterval(() => {
      load();
      Api.openbaoStatus().then(setOpenbao).catch(() => setOpenbao({ enabled: false }));
    }, 5000);
    return () => clearInterval(t);
  }, []);

  const initVault = async () => {
    setBusy(true);
    setErr(null);
    setOkMsg(null);
    try {
      const r = await Api.switchProvision();
      setKeys(r.keys || []);
      setOkMsg(r.hint || `${r.count || 0} clés dans le coffre Switch`);
    } catch (e) {
      setErr(e.message);
    }
    setBusy(false);
  };

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-violet-500/30 p-4">
      <h3 className="text-sm font-semibold text-violet-300 mb-1">SWITCH_KEY_VAULT</h3>
      <p className="text-[11px] text-slate-500 mb-2">
        LMK → TMK, ZMK, IMK, PVK · ZMK → ZPK acquéreur · TMK → TPK/TAK (ATM001). Pas de clé émetteur.
      </p>
      {openbao?.enabled && (
        <p className={`text-[10px] mb-2 font-mono ${openbao.ok ? 'text-teal-400/90' : 'text-amber-400/90'}`}>
          OpenBao {openbao.ok ? '✓' : '✗'} {openbao.addr} · KV {openbao.kvPath || 'payhsm/switch-coffre'}
        </p>
      )}
      {!openbao?.enabled && (
        <p className="text-[10px] text-slate-600 mb-2">
          OpenBao : inactif (coffre fichier local). Activer : simulation/openbao/start.sh + OPENBAO_ADDR.
        </p>
      )}
      <div className="flex flex-wrap gap-2 mb-2">
        <button
          type="button"
          onClick={initVault}
          disabled={busy}
          className="text-xs px-3 py-1 rounded bg-violet-600/70 hover:bg-violet-500 disabled:opacity-50"
        >
          {busy ? 'Initialisation…' : 'Initialiser coffre Switch'}
        </button>
      </div>
      <p className="text-[10px] text-slate-500 mb-2">
        Ordre : Provision LMK (:8765) → Démarrer HSM (même passphrase) →{' '}
        <strong className="text-violet-300/90">Initialiser coffre Switch</strong> (une fois par LMK) →
        Core Banking.         Coffre sauvegardé <strong className="text-slate-400">disque + OpenBao</strong> (si configuré) :
        même LMK PayHSM → restauration automatique au démarrage.
      </p>
      {err && <p className="text-xs text-rose-400 mb-2">{err}</p>}
      {okMsg && !err && <p className="text-xs text-emerald-400/90 mb-2">{okMsg}</p>}
      <div className="max-h-40 overflow-y-auto text-[10px] font-mono">
        {keys.length === 0 && (
          <p className="text-slate-600">
            Vide — Provision + Démarrer HSM (:8765), puis « Initialiser coffre Switch » (persisté pour cette LMK).
          </p>
        )}
        {keys.map((k) => (
          <div key={k.key_id} className="py-1 border-b border-white/5">
            <span className="text-violet-200">{k.key_id}</span>
            <span className="text-slate-500">
              {' '}
              · {k.key_type}
              {k.kcv ? ` · KCV ${k.kcv}` : ''}
              {k.wrapped_by ? ` · ${k.wrapped_by}` : ''}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
