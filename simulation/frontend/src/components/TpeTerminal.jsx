import React, { useState, useEffect, useCallback } from 'react';
import { Api } from '../api.js';

const STEP_LABELS = {
  card: '① Puce (ARQC)',
  network: '② Réseau',
  issuer: '③ PayHSM émetteur (vérif ARQC → ARPC)',
  card_arpc: '④ Puce (vérif ARPC / MK-AC)',
  balance: '⑤ Solde Core Banking',
};

export default function TpeTerminal({ onResult }) {
  const [pan, setPan] = useState('4111111111111111');
  const [amount, setAmount] = useState('42.50');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);

  const loadProfile = useCallback(async (panValue) => {
    const norm = String(panValue || '').replace(/\s/g, '');
    if (norm.length !== 16) {
      setProfile(null);
      return;
    }
    setProfileLoading(true);
    try {
      const p = await Api.cardEmvProfile(norm);
      setProfile(p);
    } catch (e) {
      setProfile({
        registered: false,
        error: e?.message || 'Backend injoignable — lancez : cd simulation/backend && npm start',
      });
    }
    setProfileLoading(false);
  }, []);

  useEffect(() => {
    const t = setTimeout(() => loadProfile(pan), 350);
    return () => clearTimeout(t);
  }, [pan, loadProfile]);

  const onPay = async () => {
    setBusy(true);
    setResult(null);
    try {
      const cents = Math.round(parseFloat(amount.replace(',', '.')) * 100);
      const r = await Api.emvPurchase({
        pan,
        amountCents: cents,
      });
      setResult(r);
      onResult?.(r);
      await loadProfile(pan);
    } catch (e) {
      const err = { approved: false, reason: e.message, message: e.message, steps: [] };
      setResult(err);
      onResult?.(err);
    }
    setBusy(false);
  };

  const canPay = profile?.registered && profile?.pvvSet && !busy;

  return (
    <div className="bg-gradient-to-br from-slate-900 to-slate-950 rounded-xl ring-1 ring-cyan-500/30 p-4">
      <h3 className="text-sm font-semibold text-cyan-300 mb-1">💳 Terminal TPE (EMV)</h3>
      <p className="text-[11px] text-slate-500 mb-3">
        Saisissez un PAN enregistré : le TPE charge <strong className="text-slate-400">date</strong>,{' '}
        <strong className="text-slate-400">ATC</strong> et <strong className="text-slate-400">PSN</strong>{' '}
        de la carte. MK-AC unique par carte (IMK Switch + PAN) ; SK-AC par transaction (ATC).
      </p>

      <div className="mb-3 p-2 rounded-lg bg-black/30 ring-1 ring-cyan-900/40 text-[10px] space-y-1">
        <div className="text-cyan-600/80 font-medium">
          Profil puce (Core Banking)
          {profileLoading && <span className="text-slate-600 ml-2">…</span>}
        </div>
        {!profile && pan.replace(/\s/g, '').length < 16 && (
          <div className="text-slate-500">PAN 16 chiffres → chargement profil EMV</div>
        )}
        {profile && !profile.registered && (
          <div className="text-rose-400/90">{profile.error || 'Carte non enregistrée'}</div>
        )}
        {profile?.registered && (
          <>
            <div className="grid grid-cols-2 gap-x-2 text-slate-400">
              <span>Client</span>
              <span className="text-slate-300 truncate">{profile.customer_name}</span>
              <span>Date carte</span>
              <span className="font-mono text-slate-300">{profile.emv_date_display}</span>
              <span>Prochain ATC</span>
              <span className="font-mono text-amber-300">{profile.emv_atc}</span>
              <span>PSN</span>
              <span className="font-mono text-slate-300">{profile.emv_psn}</span>
              <span>Terminal</span>
              <span className="font-mono text-slate-300">{profile.terminal}</span>
              <span>Solde</span>
              <span className="font-mono text-emerald-300/90">
                {profile.balance != null ? `${profile.balance}€` : '—'}
              </span>
              <span>PVV HSM</span>
              <span className={profile.pvvSet ? 'text-emerald-400' : 'text-rose-400'}>
                {profile.pvvSet ? 'OK' : 'manquant'}
              </span>
            </div>
            <div className="mt-1.5 pt-1.5 border-t border-white/5 text-slate-500">
              <div>{profile.mk_ac_hint}</div>
              <div>{profile.sk_ac_hint}</div>
            </div>
          </>
        )}
      </div>

      <div className="flex flex-wrap gap-1 mb-3 text-[10px] text-slate-500 items-center">
        <span className="px-1.5 py-0.5 rounded bg-cyan-950 ring-1 ring-cyan-800">PUCE ARQC</span>
        <span>→</span>
        <span className="px-1.5 py-0.5 rounded bg-slate-800 ring-1 ring-white/10">SWITCH</span>
        <span>→</span>
        <span className="px-1.5 py-0.5 rounded bg-emerald-950 ring-1 ring-emerald-800">PayHSM</span>
        <span>→</span>
        <span className="px-1.5 py-0.5 rounded bg-cyan-950 ring-1 ring-cyan-800">PUCE ARPC</span>
      </div>

      <div className="space-y-2 text-sm">
        <input
          className="w-full rounded bg-black/40 px-2 py-1.5 ring-1 ring-cyan-900/50 font-mono text-xs"
          value={pan}
          onChange={(e) => setPan(e.target.value)}
          placeholder="PAN (16 chiffres)"
        />
        <input
          className="w-full rounded bg-black/40 px-2 py-1.5 ring-1 ring-cyan-900/50"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="Montant EUR"
        />
        <button
          type="button"
          onClick={onPay}
          disabled={!canPay}
          className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-sm font-medium disabled:opacity-50"
        >
          {busy ? 'Flux EMV…' : canPay ? 'Payer (ARQC → ARPC → vérif puce)' : 'Carte / PVV requis'}
        </button>
      </div>

      {result && (
        <div
          className={`mt-3 text-xs font-mono p-2 rounded space-y-2 ${
            result.approved ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
          }`}
        >
          <div className="font-semibold">{result.approved ? 'APPROVED' : 'DECLINED'}</div>

          {(result.dateDisplay || result.atc) && (
            <div className="p-2 rounded bg-black/25 space-y-0.5 text-[10px]">
              <div className="text-slate-500 uppercase tracking-wide">Transaction utilisée</div>
              {result.amountDisplay && <div>Montant : {result.amountDisplay}</div>}
              {result.dateDisplay && <div>Date : {result.dateDisplay}</div>}
              {result.atc && <div>ATC : {result.atc}</div>}
              {result.nextAtc != null && (
                <div className="text-amber-400/80">Prochain ATC carte : {result.nextAtc}</div>
              )}
              {result.terminal && <div>Terminal : {result.terminal}</div>}
              {result.txData && (
                <div className="break-all text-slate-400 mt-1">txData : {result.txData}</div>
              )}
            </div>
          )}

          {result.iccKeyChain?.length > 0 && (
            <div className="p-2 rounded bg-black/25 text-[10px] text-slate-400 space-y-0.5">
              <div className="text-cyan-600/80 font-medium mb-1">Clé ICC (dérivation)</div>
              {result.iccKeyChain.map((line) => (
                <div key={line}>→ {line}</div>
              ))}
            </div>
          )}

          {(result.steps || []).map((s) => (
            <div
              key={s.id}
              className={`pl-2 border-l-2 ${s.ok ? 'border-emerald-600' : 'border-rose-600'}`}
            >
              <div>
                {s.ok ? '✓' : '✗'} {STEP_LABELS[s.id] || s.id}
                {s.api && <span className="text-slate-500"> {s.api}</span>}
              </div>
              <div className="text-[10px] opacity-80">{s.label}</div>
              {s.arqc && <div>ARQC: {s.arqc}</div>}
              {s.arpc && <div>ARPC reçu: {s.arpc}</div>}
              {s.arpcExpected && (
                <div className="text-amber-400/80">ARPC recalculé (MK-AC): {s.arpcExpected}</div>
              )}
            </div>
          ))}

          {result.newBalance != null && result.approved && (
            <div className="text-emerald-300/90">Nouveau solde : {result.newBalance}€</div>
          )}
          {result.message && <div>{result.message}</div>}
        </div>
      )}
    </div>
  );
}
