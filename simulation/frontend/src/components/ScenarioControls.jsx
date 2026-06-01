/**
 * Sélecteur de scénario + champs de saisie (PAN, PIN, montant)
 * + boutons pour lancer la transaction.
 */
import React, { useEffect, useState } from 'react';
import { Api } from '../api.js';

const PRESETS = {
  intra: {
    label: 'INTRA-BANQUE — Carte Banque A sur GAB Banque A',
    pan: '4111111111111111',
    pin: '1234',
    amount: 500,
    hint:
      'Même GAB ATM001 (Banque A). Carte 4xxx — créez-la dans Core Banking si besoin ; PVV auto côté HSM si la carte est en base.',
  },
  inter: {
    label: 'INTER-BANQUES — Carte Banque B sur GAB Banque A',
    pan: '5512345678901234',
    pin: '1234',
    amount: 300,
    hint:
      'Même GAB ATM001. PayHSM : GAP + TPK→ZPK seulement. Réseau : routage BIN (pas de ZPK-PEER ni translate-zpk sur PayHSM). PAN 55xx quelconque.',
  },
};

/** Exemples PAN autre banque (BIN 55xxxx) — pas votre 4xxx Banque A */
const INTER_BIN_EXAMPLES = [
  { pan: '5500000000000004', note: 'BIN 550000' },
  { pan: '5512345678901234', note: 'BIN 551234' },
  { pan: '5566778899001122', note: 'BIN 556677' },
  { pan: '5599887766554433', note: 'BIN 559988' },
];

export default function ScenarioControls({ onResult, busy, setBusy, scenario, setScenario }) {
  const [pan, setPan] = useState(PRESETS.intra.pan);
  const [pin, setPin] = useState(PRESETS.intra.pin);
  const [amount, setAmount] = useState(PRESETS.intra.amount);
  const [cardsA, setCardsA] = useState([]);

  useEffect(() => {
    if (scenario !== 'intra') return;
    Api.cards()
      .then((r) => {
        const list = r.cards || [];
        setCardsA(list.filter((c) => c.pan.startsWith('4')));
      })
      .catch(() => setCardsA([]));
  }, [busy, scenario]);

  const switchScenario = (s) => {
    setScenario(s);
    setPan(PRESETS[s].pan);
    setPin(PRESETS[s].pin);
    setAmount(PRESETS[s].amount);
  };

  const run = async () => {
    setBusy(true);
    try {
      const fn = scenario === 'intra' ? Api.runIntra : Api.runInter;
      const r = await fn(pan, pin, Number(amount));
      onResult(r);
    } catch (e) {
      onResult({ ok: false, error: e.message });
    } finally {
      setBusy(false);
    }
  };

  const reset = async () => {
    setBusy(true);
    try {
      await Api.reset();
      onResult(null);
    } finally {
      setBusy(false);
    }
  };

  const quickPans =
    scenario === 'intra'
      ? cardsA.map((c) => ({ pan: c.pan, label: c.panMasked }))
      : INTER_BIN_EXAMPLES.map((e) => ({ pan: e.pan, label: `${e.note} ···${e.pan.slice(-4)}` }));

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-4">
      <h3 className="text-sm font-semibold tracking-wide text-slate-200 mb-3">
        🎬 Scénario de simulation
      </h3>

      <div className="grid grid-cols-2 gap-2 mb-3">
        {Object.entries(PRESETS).map(([k, v]) => (
          <button
            key={k}
            onClick={() => switchScenario(k)}
            className={`text-left rounded-lg p-3 ring-1 transition ${
              scenario === k
                ? 'bg-sky-500/20 ring-sky-500 text-sky-100'
                : 'bg-slate-950/40 ring-white/5 text-slate-400 hover:bg-slate-900'
            }`}
          >
            <div className="text-[10px] uppercase font-mono tracking-wider opacity-80">{k}</div>
            <div className="text-xs font-semibold mt-1 leading-tight">{v.label}</div>
          </button>
        ))}
      </div>

      <p className="text-[11px] text-slate-500 mb-1 italic">{PRESETS[scenario].hint}</p>
      {scenario === 'inter' && (
        <p className="text-[10px] text-sky-500/80 mb-3 font-mono">
          GAB commun : ATM001 (Banque A) · Ne pas utiliser de PAN 41xx / 42xx ici
        </p>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="text-[11px] uppercase tracking-wider text-slate-500">PAN (numéro carte)</label>
          <input
            value={pan}
            onChange={(e) => setPan(e.target.value)}
            className="w-full bg-slate-950/80 border border-white/10 rounded px-3 py-1.5 font-mono text-sm mt-1"
          />
          {quickPans.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {quickPans.map((c) => (
                <button
                  key={c.pan}
                  type="button"
                  onClick={() => setPan(c.pan)}
                  className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                    c.pan === pan ? 'bg-sky-500/30 text-sky-200' : 'bg-white/5 text-slate-400 hover:bg-white/10'
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          )}
        </div>
        <div>
          <label className="text-[11px] uppercase tracking-wider text-slate-500">PIN</label>
          <input
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            maxLength={12}
            className="w-full bg-slate-950/80 border border-white/10 rounded px-3 py-1.5 font-mono text-sm mt-1"
          />
        </div>
        <div>
          <label className="text-[11px] uppercase tracking-wider text-slate-500">Montant (€)</label>
          <input
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            className="w-full bg-slate-950/80 border border-white/10 rounded px-3 py-1.5 font-mono text-sm mt-1"
          />
        </div>
      </div>

      <div className="flex gap-2 mt-4">
        <button
          onClick={run}
          disabled={busy}
          className="flex-1 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white font-semibold py-2.5 rounded-lg shadow"
        >
          {busy ? '⏳ En cours…' : scenario === 'inter' ? '▶ Lancer (crypto → réseau)' : '▶ Lancer le retrait'}
        </button>
        <button
          onClick={reset}
          disabled={busy}
          className="bg-slate-700 hover:bg-slate-600 disabled:opacity-40 text-slate-100 font-medium px-4 rounded-lg"
          title="Réinitialiser soldes + journal"
        >
          ⟲
        </button>
      </div>
    </div>
  );
}
