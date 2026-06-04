import React, { useEffect, useMemo, useState } from 'react';
import { Api, subscribeStream } from './api.js';
import Actor from './components/Actor.jsx';
import MessageBus from './components/MessageBus.jsx';
import ScenarioControls from './components/ScenarioControls.jsx';
import HsmStatus from './components/HsmStatus.jsx';
import FlowDiagram from './components/FlowDiagram.jsx';
import ResultBanner from './components/ResultBanner.jsx';
import CoreBanking from './components/CoreBanking.jsx';
import TpeTerminal from './components/TpeTerminal.jsx';
import MacIntegrity from './components/MacIntegrity.jsx';
import OpenBaoConsole from './components/OpenBaoConsole.jsx';
import BackendBanner from './components/BackendBanner.jsx';

export default function App() {
  const [events, setEvents] = useState([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [scenario, setScenario] = useState('intra');
  const [activeTx, setActiveTx] = useState(null);
  const [tab, setTab] = useState('atm');
  const [bankRefresh, setBankRefresh] = useState(0);

  useEffect(() => {
    const stop = subscribeStream(
      (e) => setEvents((prev) => [...prev, e]),
      () => setEvents([]),
    );
    return stop;
  }, []);

  const eventsByActor = useMemo(() => {
    const map = {};
    for (const e of events) {
      if (activeTx && e.txId !== activeTx) continue;
      [e.from, e.to].forEach((a) => {
        if (!a) return;
        if (!map[a]) map[a] = [];
        map[a].push(e);
      });
    }
    return map;
  }, [events, activeTx]);

  const txList = useMemo(() => {
    const set = new Set();
    for (const e of events) if (e.txId) set.add(e.txId);
    return [...set];
  }, [events]);

  const currentStage = useMemo(() => {
    const evs = activeTx ? events.filter((e) => e.txId === activeTx) : events;
    return evs.reduce((m, e) => Math.max(m, e.stage || 0), 0);
  }, [events, activeTx]);

  const onResult = (r) => {
    setResult(r);
    if (r?.txId) setActiveTx(r.txId);
    if (r?.approved === true) setBankRefresh((n) => n + 1);
  };

  return (
    <div className="min-h-screen p-4 md:p-6 max-w-[1500px] mx-auto">
      <header className="flex items-end justify-between mb-5 flex-wrap gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight">
            PayHSM <span className="text-sky-400">·</span> Simulateur bancaire
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Toute la crypto via votre LMK{' '}
            <span className="font-mono text-rose-300">src/lib/payhsm</span> (payhsm-httpd) —
            le Switch ne stocke que des cryptogrammes GCM
          </p>
        </div>
        <a
          href="http://127.0.0.1:8765"
          target="_blank"
          rel="noopener"
          className="text-xs bg-slate-800 ring-1 ring-white/10 text-slate-300 px-3 py-1.5 rounded-lg hover:bg-slate-700 font-mono"
        >
          Console technique HSM ↗
        </a>
      </header>

      <nav className="flex gap-2 mb-4 flex-wrap">
        {[
          ['banking', 'Banque & coffre'],
          ['openbao', 'OpenBao'],
          ['tpe', 'Terminal TPE (EMV)'],
          ['atm', 'Flux ATM'],
        ].map(([id, label]) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={`text-xs px-3 py-1.5 rounded-lg ${tab === id ? 'bg-sky-600 text-white' : 'bg-slate-800 text-slate-400'}`}
          >
            {label}
          </button>
        ))}
      </nav>

      <BackendBanner />

      {result && (
        <div className="mb-4">
          <ResultBanner result={result} />
        </div>
      )}

      {tab === 'openbao' && (
        <div className="mb-6">
          <OpenBaoConsole />
        </div>
      )}

      {tab === 'banking' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <CoreBanking key={bankRefresh} />
          <MacIntegrity />
        </div>
      )}

      {tab === 'tpe' && (
        <div className="grid grid-cols-12 gap-4 mb-6">
          <div className="col-span-12 lg:col-span-5">
            <TpeTerminal onResult={onResult} />
          </div>
          <div className="col-span-12 lg:col-span-7">
            <MessageBus events={events} txFilter={activeTx} />
          </div>
        </div>
      )}

      {tab === 'atm' && (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-4 space-y-4">
            <ScenarioControls
              onResult={onResult}
              busy={busy}
              setBusy={setBusy}
              scenario={scenario}
              setScenario={setScenario}
            />
            <HsmStatus />
            {txList.length > 0 && (
              <div className="bg-slate-900/60 rounded-xl ring-1 ring-white/10 p-3">
                <h3 className="text-sm font-semibold text-slate-200 mb-2">Transactions</h3>
                <button
                  type="button"
                  onClick={() => setActiveTx(null)}
                  className={`block w-full text-left text-[11px] font-mono px-2 py-1 rounded mb-1 ${!activeTx ? 'bg-sky-500/20 text-sky-200' : 'hover:bg-white/5 text-slate-400'}`}
                >
                  toutes
                </button>
                {txList.map((tx) => (
                  <button
                    key={tx}
                    type="button"
                    onClick={() => setActiveTx(tx)}
                    className={`block w-full text-left text-[11px] font-mono px-2 py-1 rounded ${activeTx === tx ? 'bg-sky-500/20 text-sky-200' : 'hover:bg-white/5 text-slate-400'}`}
                  >
                    {tx}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="col-span-12 lg:col-span-8 space-y-4">
            <FlowDiagram scenario={scenario} activeStage={currentStage} />
            {scenario === 'intra' ? (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Actor name="GAB-A" role="ATM" hint="PIN block TPK" events={eventsByActor['GAB-A']} />
                <Actor name="SWITCH-A" role="Switch" hint="PVV + solde" events={eventsByActor['SWITCH-A']} />
                <Actor name="PayHSM (Banque A)" role="payhsm-httpd :8765" hint="TPK/PVK/ZPK · LMK" events={eventsByActor['PayHSM (Banque A)']} />
              </div>
            ) : (
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                <Actor name="GAB-A" role="ATM acquéreur" events={eventsByActor['GAB-A']} />
                <Actor name="EPP-A (GAP)" role="TPK" events={eventsByActor['EPP-A (GAP)']} />
                <Actor name="SWITCH-A" role="Switch A" events={eventsByActor['SWITCH-A']} />
                <Actor name="PayHSM (Banque A)" role="payhsm-httpd :8765" events={eventsByActor['PayHSM (Banque A)']} />
                <Actor name="NETWORK" role="Réseau CMI" events={eventsByActor['NETWORK']} />
                <Actor name="SWITCH-B" role="Switch émetteur B" events={eventsByActor['SWITCH-B']} />
              </div>
            )}
            <MessageBus events={events} txFilter={activeTx} />
          </div>
        </div>
      )}

      <footer className="mt-6 text-center text-[11px] text-slate-600">
        PFE PayHSM · HSM stateless · clés de travail dans SWITCH_KEY_VAULT
      </footer>
    </div>
  );
}
