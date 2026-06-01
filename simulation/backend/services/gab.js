/**
 * GAB — le module GAP (EPP) forme le PIN block sous TPK-ATM001.
 * L’exécution crypto passe par PayHSM (clés TPK sous LMK) ; le Switch ne voit que le PIN block.
 */
import { bus } from '../bus.js';
import { HsmA, requireHsmReady } from '../hsm/hsmReal.js';
import { CONFIG } from '../config.js';
import { payhsmCall, GAP_ACTOR } from './payhsmJournal.js';

function maskPan(pan) {
  return pan.replace(/.(?=.{4})/g, '*');
}

async function gabGap({ txId, pan, pin, amount, terminal, labelExtra }) {
  await requireHsmReady();
  const tpk = `TPK-${terminal}`;

  bus.publish({
    txId, stage: 1, from: 'GAB-A', to: 'EPP-A', kind: 'info',
    label: labelExtra || 'Saisie PIN sur Pin-Pad sécurisé (EPP)',
    payload: { pan: maskPan(pan), terminal, montant: amount },
  });

  /* GAP = chiffrement PIN → PIN block sous TPK (crypto dans PayHSM car TPK sous LMK) */
  const r = await payhsmCall({
    txId,
    stage: 2,
    from: GAP_ACTOR,
    replyTo: 'GAB-A',
    api: '/api/gap',
    label: `GAP chiffre le PIN → PIN block ISO 9564-0 sous ${tpk}`,
    keysHint: `${tpk} + TMK (cryptogrammes coffre Switch)`,
    responseLabel: `GAP → GAB : PIN block prêt (chiffré ${tpk})`,
    callFn: () => HsmA.gap(terminal, pin, pan),
  });

  if (r.rc !== 0 && !r.pinBlock) {
    throw new Error(r.message || 'GAP échoué — TPK provisionné pour ATM001 ?');
  }

  bus.publish({
    txId, stage: 4, from: 'GAB-A', to: 'SWITCH-A', kind: 'crypto',
    label: `GAB remet au Switch : PIN block ${tpk} + PAN (aucune clé en clair)`,
    payload: { pinBlock_tpk: r.pinBlock, terminal, pan: maskPan(pan) },
  });

  return { pinBlock: r.pinBlock, terminal, pan, amount };
}

export async function gabA_intra({ txId, pan, pin, amount, terminal }) {
  return gabGap({
    txId, pan, pin, amount,
    terminal: terminal || CONFIG.GAB_TERMINAL,
    labelExtra: 'Saisie PIN — retrait intra-banque',
  });
}

export async function gabA_inter({ txId, pan, pin, amount }) {
  return gabGap({
    txId, pan, pin, amount,
    terminal: CONFIG.GAB_TERMINAL,
    labelExtra: 'Saisie PIN — carte étrangère (inter-banques)',
  });
}
