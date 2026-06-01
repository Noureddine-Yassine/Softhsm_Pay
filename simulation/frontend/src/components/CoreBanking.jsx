import React, { useEffect, useState } from 'react';
import { Api } from '../api.js';

export default function CoreBanking() {
  const [cards, setCards] = useState([]);
  const [pan, setPan] = useState('');
  const [name, setName] = useState('');
  const [pin, setPin] = useState('');
  const [balance, setBalance] = useState('5000');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const load = () => Api.cards().then((r) => setCards(r.cards || [])).catch(() => {});

  useEffect(() => { load(); }, []);

  const onCreate = async (e) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const r = await Api.createCard({
        pan, customerName: name, pin, balance: Number(balance),
      });
      setMsg({ ok: true, text: `Carte créée — PVV émis par HSM (${r.pvv})` });
      setPan('');
      setPin('');
      load();
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    }
    setBusy(false);
  };

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-4">
      <h3 className="text-sm font-semibold text-slate-200 mb-2">🏦 Core Banking — Créer une carte</h3>
      <p className="text-[11px] text-slate-500 mb-3">
        Proxy → <span className="font-mono">/api/corebanking/issue</span> →{' '}
        <span className="font-mono text-rose-300/90">pin_compute_pvv</span> (pin.c).
        PVV stocké dans le HSM ; solde/nom ici seulement.
      </p>
      <form onSubmit={onCreate} className="space-y-2 text-sm">
        <input className="w-full rounded bg-slate-950 px-2 py-1.5 ring-1 ring-white/10 font-mono"
          placeholder="PAN (16 chiffres)" value={pan} onChange={(e) => setPan(e.target.value)} maxLength={16} />
        <input className="w-full rounded bg-slate-950 px-2 py-1.5 ring-1 ring-white/10"
          placeholder="Nom client" value={name} onChange={(e) => setName(e.target.value)} />
        <input className="w-full rounded bg-slate-950 px-2 py-1.5 ring-1 ring-white/10 font-mono"
          placeholder="PIN client" type="password" value={pin} onChange={(e) => setPin(e.target.value)} />
        <input className="w-full rounded bg-slate-950 px-2 py-1.5 ring-1 ring-white/10"
          placeholder="Solde initial" value={balance} onChange={(e) => setBalance(e.target.value)} />
        <button type="submit" disabled={busy}
          className="w-full rounded-lg bg-emerald-600/80 hover:bg-emerald-500 py-2 text-sm font-medium disabled:opacity-50">
          {busy ? 'Émission…' : 'Créer carte + PVV'}
        </button>
      </form>
      {msg && (
        <p className={`mt-2 text-xs ${msg.ok ? 'text-emerald-400' : 'text-rose-400'}`}>{msg.text}</p>
      )}
      <div className="mt-3 max-h-32 overflow-y-auto text-[10px] font-mono text-slate-500">
        {cards.map((c) => (
          <div key={c.pan} className="py-0.5 border-b border-white/5">
            {c.panMasked} · {c.customer_name} · solde {c.balance}€ {c.pvvSet ? '· PVV ✓' : ''}
          </div>
        ))}
      </div>
    </div>
  );
}
