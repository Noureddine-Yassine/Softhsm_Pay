/**
 * Bus d'événements de simulation — alimente le flux SSE (Server-Sent Events).
 * Le frontend s'abonne via /api/stream et reçoit chaque message échangé
 * entre les acteurs (GAB, Switch, Réseau, HSM) en temps réel.
 *
 * Chaque event suit la forme :
 *   {
 *     id, ts, txId,
 *     from, to,            // acteurs : 'GAB-A', 'SWITCH-A', 'NETWORK', 'SWITCH-B', 'HSM-A', 'HSM-B'
 *     kind,                // 'request' | 'response' | 'crypto' | 'info' | 'error'
 *     label,               // texte court affiché
 *     payload,             // objet inspectable (PAN, PIN block, clés masquées, etc.)
 *     stage                // étape logique (1..N) — utile pour la timeline
 *   }
 */
import { EventEmitter } from 'node:events';

class SimBus extends EventEmitter {
  constructor() {
    super();
    this.history = []; // garde les N derniers events pour reconnexion frontend
    this.maxHistory = 500;
    this.seq = 0;
  }

  publish(evt) {
    const enriched = {
      id: ++this.seq,
      ts: new Date().toISOString(),
      ...evt,
    };
    this.history.push(enriched);
    if (this.history.length > this.maxHistory) {
      this.history.splice(0, this.history.length - this.maxHistory);
    }
    this.emit('event', enriched);
    return enriched;
  }

  clear() {
    this.history = [];
    this.seq = 0;
    this.emit('reset');
  }
}

export const bus = new SimBus();
