import React from 'react';

export default function ResultBanner({ result }) {
  if (!result) return null;

  if (result.demonstration && result.ok) {
    return (
      <div className="bg-sky-900/40 ring-1 ring-sky-600/60 rounded-xl p-3 text-sky-100 text-sm">
        <div className="font-semibold">✓ Crypto inter — translation réseau OK</div>
        <p className="text-xs mt-1 text-sky-200/90">{result.message}</p>
        {result.cryptoPath && (
          <p className="text-[11px] font-mono mt-1 text-sky-300/80">{result.cryptoPath}</p>
        )}
        {result.bin && (
          <p className="text-[11px] mt-1 text-sky-400/70">
            BIN {result.bin} → {result.issuer} · GAB {result.terminal}
          </p>
        )}
        {result.txId && (
          <span className="text-sky-400/80 text-xs font-mono">{result.txId}</span>
        )}
      </div>
    );
  }

  /* EMV : approved sans ok · ATM : ok + approved */
  if (result.approved === true) {
    const label =
      result.debited != null
        ? `Paiement TPE · −${Number(result.debited).toFixed(2)}€`
        : result.arqc
          ? 'Paiement EMV approuvé'
          : 'Transaction approuvée';
    return (
      <div className="bg-emerald-900/40 ring-1 ring-emerald-700/60 rounded-xl p-3 text-emerald-200 text-sm font-medium">
        ✓ APPROVED — {label}
        {result.newBalance != null && (
          <>
            {' '}
            · solde restant : <span className="font-mono">{result.newBalance}€</span>
          </>
        )}
        {result.txId && (
          <span className="ml-3 text-emerald-400 text-xs font-mono">{result.txId}</span>
        )}
      </div>
    );
  }

  if (result.approved === false) {
    return (
      <div className="bg-amber-900/40 ring-1 ring-amber-700/60 rounded-xl p-3 text-amber-200 text-sm font-medium">
        ✗ DECLINED — {result.reason || result.message || 'refus'}
        {result.txId && (
          <span className="ml-3 text-amber-400 text-xs font-mono">{result.txId}</span>
        )}
      </div>
    );
  }

  if (result.ok === false || result.error) {
    return (
      <div className="bg-red-900/40 ring-1 ring-red-700/60 rounded-xl p-3 text-red-200 text-sm font-medium">
        ✕ Échec — {result.error || result.reason || result.message || 'erreur inconnue'}
      </div>
    );
  }

  if (result.ok === true) {
    return (
      <div className="bg-emerald-900/40 ring-1 ring-emerald-700/60 rounded-xl p-3 text-emerald-200 text-sm font-medium">
        ✓ APPROVED — Retrait validé · solde restant :{' '}
        <span className="font-mono">{result.newBalance ?? '—'}€</span>
        {result.txId && (
          <span className="ml-3 text-emerald-400 text-xs font-mono">{result.txId}</span>
        )}
      </div>
    );
  }

  return null;
}
