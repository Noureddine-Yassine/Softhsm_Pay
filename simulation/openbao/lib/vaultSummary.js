/** Résumé coffre pour l’UI (pas de cryptogrammes complets). */
export function summarizeVaultKeys(keys) {
  return (keys || [])
    .filter((k) => k.key_id !== 'ZPK-PEER')
    .map((k) => ({
      key_id: k.key_id,
      key_type: k.key_type,
      kcv: k.kcv || null,
      wrapped_by: k.wrapped_by || null,
    }));
}
