/**
 * Diagramme animé du flux des deux scénarios.
 * SVG dimensionné dynamiquement pour s'adapter à la largeur du conteneur.
 */
import React from 'react';

const ACTORS_INTRA = [
  { id: 'gaba',  label: 'GAB-A',  x: 0.1,  color: '#3b82f6' },
  { id: 'swa',   label: 'Switch-A',  x: 0.4, color: '#3b82f6' },
  { id: 'hsma',  label: 'PayHSM', x: 0.7, color: '#e11d48' },
  { id: 'core',  label: 'Core Banking', x: 0.9, color: '#1d4ed8' },
];

const ACTORS_INTER = [
  { id: 'gaba',  label: 'GAB-A',  x: 0.04, color: '#3b82f6' },
  { id: 'swa',   label: 'Switch-A',  x: 0.22, color: '#3b82f6' },
  { id: 'hsma',  label: 'PayHSM', x: 0.36, color: '#e11d48', sub: ':8765' },
  { id: 'net',   label: 'Réseau', x: 0.55, color: '#14b8a6' },
  { id: 'swb',   label: 'Switch-B', x: 0.74, color: '#9333ea' },
  { id: 'hsmb',  label: 'HSM-B', x: 0.88, color: '#e11d48', sub:'sim' },
  { id: 'core',  label: 'Core-B', x: 0.98, color: '#9333ea' },
];

const ARROWS_INTRA = [
  { from: 'gaba', to: 'swa', label: 'PIN block / TPK + PAN', stage: 3 },
  { from: 'swa',  to: 'hsma', label: 'verify(PB, PAN, ref TPK, ref PVK, PVV)', stage: 6 },
  { from: 'hsma', to: 'swa',  label: 'OK / KO', stage: 7, back: true },
  { from: 'swa',  to: 'core', label: 'check solde', stage: 8 },
  { from: 'swa',  to: 'gaba', label: 'APPROVED → billets 💵', stage: 9, back: true },
];

const ARROWS_INTER = [
  { from: 'gaba', to: 'swa',  label: 'PIN block / TPK_A', stage: 3 },
  { from: 'swa',  to: 'hsma', label: 'translate TPK_A→ZPK_A', stage: 4 },
  { from: 'hsma', to: 'swa',  label: 'PB / ZPK_A', stage: 5, back: true },
  { from: 'swa',  to: 'net',  label: 'ISO 0200 (PB/ZPK_A)', stage: 5 },
  { from: 'net',  to: 'swb',  label: 'PB / ZPK_B (translation HSM réseau)', stage: 8 },
  { from: 'swb',  to: 'hsmb', label: 'verify(PB, PAN, refs ZPK+PVK, PVV)', stage: 13 },
  { from: 'hsmb', to: 'swb',  label: 'OK / KO', stage: 14, back: true },
  { from: 'swb',  to: 'core', label: 'solde', stage: 15 },
  { from: 'swb',  to: 'net',  label: 'réponse 0210', stage: 16, back: true },
  { from: 'net',  to: 'swa',  label: 'relais', stage: 17, back: true },
  { from: 'swa',  to: 'gaba', label: 'APPROVED → billets 💵', stage: 18, back: true },
];

export default function FlowDiagram({ scenario, activeStage }) {
  const actors = scenario === 'intra' ? ACTORS_INTRA : ACTORS_INTER;
  const arrows = scenario === 'intra' ? ARROWS_INTRA : ARROWS_INTER;
  const W = 900, H = 240;
  const ax = (frac) => 40 + frac * (W - 80);
  const ay = H / 2;

  const idx = Object.fromEntries(actors.map((a) => [a.id, a]));

  return (
    <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-3">
      <h3 className="text-sm font-semibold tracking-wide text-slate-200 mb-2">
        🗺️ Schéma du flux — {scenario === 'intra' ? 'INTRA-BANQUE' : 'INTER-BANQUES'}
      </h3>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto">
        {/* Backbone */}
        <line x1={20} y1={ay} x2={W - 20} y2={ay} stroke="rgba(255,255,255,0.06)" strokeDasharray="4 4" />

        {/* Arrows */}
        {arrows.map((a, i) => {
          const x1 = ax(idx[a.from].x);
          const x2 = ax(idx[a.to].x);
          const yOff = a.back ? 32 : -32;
          const yPath = ay + yOff;
          const active = activeStage && a.stage <= activeStage;
          const stroke = active ? '#38bdf8' : 'rgba(255,255,255,0.18)';
          const labelFill = active ? '#bae6fd' : 'rgba(255,255,255,0.35)';
          return (
            <g key={i}>
              <path
                d={`M ${x1} ${ay} Q ${(x1 + x2) / 2} ${yPath} ${x2} ${ay}`}
                fill="none" stroke={stroke} strokeWidth={active ? 2 : 1.2}
                markerEnd={`url(#arrowhead-${active ? 'on' : 'off'})`}
              />
              <text
                x={(x1 + x2) / 2}
                y={yPath - (a.back ? -6 : 6)}
                textAnchor="middle"
                fontSize="10"
                fontFamily="JetBrains Mono, ui-monospace, monospace"
                fill={labelFill}
              >
                {a.label}
              </text>
            </g>
          );
        })}

        {/* Actors */}
        {actors.map((a) => {
          const x = ax(a.x);
          return (
            <g key={a.id}>
              <circle cx={x} cy={ay} r={18} fill={a.color} stroke="rgba(255,255,255,0.2)" strokeWidth="2" />
              <text x={x} y={ay + 4} textAnchor="middle" fontSize="11" fontWeight="700" fill="white">
                {a.label[0]}
              </text>
              <text x={x} y={ay + 36} textAnchor="middle" fontSize="10.5" fontWeight="600" fill="#e2e8f0">
                {a.label}
              </text>
              {a.sub && (
                <text x={x} y={ay + 48} textAnchor="middle" fontSize="9" fill="#94a3b8">
                  {a.sub}
                </text>
              )}
            </g>
          );
        })}

        <defs>
          <marker id="arrowhead-on" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L6,4 L0,8 Z" fill="#38bdf8" />
          </marker>
          <marker id="arrowhead-off" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L6,4 L0,8 Z" fill="rgba(255,255,255,0.4)" />
          </marker>
        </defs>
      </svg>
    </div>
  );
}
