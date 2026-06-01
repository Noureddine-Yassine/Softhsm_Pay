/**
 * Panneau "acteur" du flux (GAB-A, Switch-A, Réseau, Switch-B, HSM-B, etc.).
 * Affiche son nom, son rôle, et les derniers messages le concernant.
 */
import React from 'react';

const COLORS = {
  'GAB-A':       { ring: 'ring-blue-500',   bg: 'bg-blue-950/40',    badge: 'bg-blue-500/20 text-blue-300',   icon: '🏧' },
  'GAB-B':       { ring: 'ring-purple-500', bg: 'bg-purple-950/40',  badge: 'bg-purple-500/20 text-purple-300', icon: '🏧' },
  'SWITCH-A':    { ring: 'ring-blue-400',   bg: 'bg-blue-950/30',    badge: 'bg-blue-500/20 text-blue-300',   icon: '🔀' },
  'SWITCH-B':    { ring: 'ring-purple-400', bg: 'bg-purple-950/30',  badge: 'bg-purple-500/20 text-purple-300', icon: '🔀' },
  'NETWORK':     { ring: 'ring-teal-400',   bg: 'bg-teal-950/40',    badge: 'bg-teal-500/20 text-teal-300',   icon: '🌐' },
  'PayHSM (Banque A)': { ring: 'ring-rose-500', bg: 'bg-rose-950/50', badge: 'bg-rose-500/20 text-rose-300', icon: '🔐' },
  'EPP-A (GAP)': { ring: 'ring-blue-500', bg: 'bg-blue-950/40', badge: 'bg-blue-500/20 text-blue-300', icon: '⌨' },
  'HSM-A (réel)': { ring: 'ring-rose-500', bg: 'bg-rose-950/50', badge: 'bg-rose-500/20 text-rose-300', icon: '🔐' },
  'HSM-A (sim)': { ring: 'ring-rose-400',   bg: 'bg-rose-950/40',    badge: 'bg-rose-500/20 text-rose-300',   icon: '🔐' },
  'HSM-B (sim)': { ring: 'ring-rose-400',   bg: 'bg-rose-950/40',    badge: 'bg-rose-500/20 text-rose-300',   icon: '🔐' },
  'HSM-NETWORK': { ring: 'ring-rose-300',   bg: 'bg-rose-950/30',    badge: 'bg-rose-500/20 text-rose-300',   icon: '🔐' },
};

const KIND_BADGE = {
  request:  'bg-sky-500/15 text-sky-300 border border-sky-700/40',
  response: 'bg-emerald-500/15 text-emerald-300 border border-emerald-700/40',
  crypto:   'bg-amber-500/15 text-amber-300 border border-amber-700/40',
  info:     'bg-slate-500/15 text-slate-300 border border-slate-700/40',
  error:    'bg-red-500/15 text-red-300 border border-red-700/40',
};

export default function Actor({ name, role, hint, events = [], active = false, kcv = null }) {
  const color = COLORS[name] || { ring: 'ring-slate-500', bg: 'bg-slate-900/60', badge: 'bg-slate-500/20 text-slate-300', icon: '◇' };
  const lastFive = events.slice(-5).reverse();

  return (
    <div className={`rounded-xl ${color.bg} ${active ? 'ring-2 ' + color.ring + ' shadow-glow' : 'ring-1 ring-white/5'} p-4 transition-all`}>
      <div className="flex items-start gap-2">
        <div className="text-2xl">{color.icon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-bold tracking-wide">{name}</span>
            <span className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded ${color.badge}`}>{role}</span>
          </div>
          <p className="text-xs text-slate-400 mt-1 leading-snug">{hint}</p>
          {kcv && (
            <p className="text-[10px] font-mono mt-1 text-slate-500 truncate">
              KCV: {Object.entries(kcv).map(([k, v]) => `${k}=${v}`).join(' · ')}
            </p>
          )}
        </div>
      </div>

      <div className="mt-3 space-y-1.5 max-h-44 overflow-y-auto thin-scroll">
        {lastFive.length === 0 && (
          <div className="text-[11px] text-slate-600 italic">Aucun trafic pour l'instant…</div>
        )}
        {lastFive.map((e) => (
          <div key={e.id} className="text-[11px] msg-in">
            <div className="flex items-center gap-1.5">
              <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${KIND_BADGE[e.kind] || KIND_BADGE.info}`}>
                {e.kind}
              </span>
              <span className="text-slate-300 truncate">{e.label}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
