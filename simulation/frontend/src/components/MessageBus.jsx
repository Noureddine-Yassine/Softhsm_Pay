/**
 * Log temps réel des messages échangés entre acteurs.
 * Chaque ligne montre : étape, "FROM → TO", type, label, et un payload
 * dépliable (JSON pretty).
 */
import React, { useState } from 'react';

const KIND_COLOR = {
  request:  'text-sky-300',
  response: 'text-emerald-300',
  crypto:   'text-amber-300',
  info:     'text-slate-300',
  error:    'text-red-400',
};

const KIND_ICON = {
  request:  '→',
  response: '←',
  crypto:   '🔒',
  info:     'i',
  error:    '✕',
};

function Row({ e }) {
  const [open, setOpen] = useState(false);
  const c = KIND_COLOR[e.kind] || 'text-slate-300';
  return (
    <div className="border-b border-white/5 py-2 text-[12px] font-mono">
      <button onClick={() => setOpen(!open)} className="w-full text-left hover:bg-white/[0.03] -mx-2 px-2 py-1 rounded">
        <div className="flex items-baseline gap-2">
          <span className="text-slate-600 text-[10px] w-12 shrink-0">#{String(e.stage).padStart(2,'0')}</span>
          <span className={`${c} w-6 shrink-0 text-center`}>{KIND_ICON[e.kind] || '·'}</span>
          <span className="text-slate-400 shrink-0">{e.from}</span>
          <span className="text-slate-600 shrink-0">→</span>
          <span className="text-slate-400 shrink-0">{e.to}</span>
          <span className="text-slate-200 truncate flex-1">{e.label}</span>
          <span className="text-slate-700 text-[10px] shrink-0">{new Date(e.ts).toLocaleTimeString()}</span>
        </div>
      </button>
      {open && e.payload && (
        <pre className="mt-1 ml-20 text-[10.5px] text-slate-400 bg-black/40 p-2 rounded overflow-x-auto">
{JSON.stringify(e.payload, null, 2)}
        </pre>
      )}
    </div>
  );
}

export default function MessageBus({ events, txFilter }) {
  const filtered = txFilter ? events.filter((e) => e.txId === txFilter) : events;
  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold tracking-wide text-slate-200">
          📨 Journal des messages
          {txFilter && <span className="text-xs text-slate-500 font-mono ml-2">tx={txFilter}</span>}
        </h3>
        <span className="text-[11px] text-slate-500">{filtered.length} événements</span>
      </div>
      <div className="max-h-[420px] overflow-y-auto thin-scroll">
        {filtered.length === 0 && (
          <div className="text-slate-600 text-sm italic text-center py-8">
            Aucun événement — lance un scénario pour voir le trafic.
          </div>
        )}
        {filtered.map((e) => <Row key={e.id} e={e} />)}
      </div>
    </div>
  );
}
