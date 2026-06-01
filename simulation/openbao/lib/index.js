/**
 * Module OpenBao PayHSM — point d’entrée unique.
 */
export { OPENBAO } from './config.js';
export {
  isOpenBaoEnabled,
  openBaoHealth,
  saveSwitchVaultToOpenBao,
  loadSwitchVaultFromOpenBao,
  clearSwitchVaultInOpenBao,
  readSwitchVaultRawFromOpenBao,
} from './client.js';
export { summarizeVaultKeys } from './vaultSummary.js';
export { createOpenBaoRouter } from './routes.js';
