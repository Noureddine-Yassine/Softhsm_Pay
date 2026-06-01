import React, { useState } from 'react';
import { Api } from '../api.js';

export default function MacIntegrity() {
  const [pan, setPan] = useState('4111111111111111');
  const [amount, setAmount] = useState('100');
  const [message, setMessage] = useState('');
  const [mac, setMac] = useState('');
  const [tampered, setTampered] = useState(false);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const sign = async () => {
    setBusy(true);
    try {
      const cents = Math.round(parseFloat(amount) * 100);
      const r = await Api.macSign({ pan, amountCents: cents });
      setMessage(r.message);
      setMac(r.mac);
      setTampered(false);
      setResult(null);
    } catch (e) {
      setResult({ valid: false, error: e.message });
    }
    setBusy(false);
  };

  const verify = async () => {
    setBusy(true);
    try {
      const msg = tampered ? message + 'TAMPER' : message;
      const r = await Api.macVerify({ message: msg, mac });
      setResult(r);
    } catch (e) {
      setResult({ valid: false, error: e.message });
    }
    setBusy(false);
  };

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-amber-500/30 p-4">
      <h3 className="text-sm font-semibold text-amber-300 mb-1">🔒 MAC ISO-8583 (TAK)</h3>
      <p className="text-[11px] text-slate-500 mb-3">
        Proxy → <span className="font-mono">/api/mac/calc|verify</span> →{' '}
        <span className="font-mono text-rose-300/90">mac.c</span> (calculate_mac_tak, verify_mac).
      </p>
      <div className="space-y-2 text-sm">
        <input className="w-full rounded bg-slate-950 px-2 py-1 font-mono text-xs"
          value={pan} onChange={(e) => setPan(e.target.value)} placeholder="PAN" />
        <input className="w-full rounded bg-slate-950 px-2 py-1"
          value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="Montant EUR" />
        <button type="button" onClick={sign} disabled={busy}
          className="w-full py-1.5 rounded bg-amber-700/60 text-xs">1. Signer trame (HSM)</button>
        {message && (
          <pre className="text-[10px] text-slate-400 break-all bg-black/30 p-1 rounded">{message}</pre>
        )}
        {mac && <p className="text-[10px] font-mono text-amber-200">MAC: {mac}</p>}
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input type="checkbox" checked={tampered} onChange={(e) => setTampered(e.target.checked)} />
          Simuler altération trame (hacker)
        </label>
        <button type="button" onClick={verify} disabled={busy || !mac}
          className="w-full py-1.5 rounded bg-slate-700 text-xs">2. Vérifier MAC</button>
      </div>
      {result && (
        <p className={`mt-2 text-xs font-mono ${result.valid ? 'text-emerald-400' : 'text-rose-400'}`}>
          {result.valid ? 'MAC VALIDE — intégrité OK' : 'MAC INVALIDE — trame rejetée'}
        </p>
      )}
    </div>
  );
}
