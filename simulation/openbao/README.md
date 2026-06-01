# OpenBao — module PayHSM

Stockage **réel** du coffre Switch (Docker OpenBao KV v2).  
La **LMK** reste dans PayHSM (`payhsm-httpd`) — OpenBao ne reçoit que des **cryptogrammes** + `lmkRef` (empreinte 8 car.).

## Structure

```
simulation/openbao/
├── docker-compose.yml   # Conteneur openbao/openbao:2.1.0 (dev)
├── start.sh             # Démarre Docker
├── show-coffre.sh       # Lecture CLI du secret KV
├── .env.example         # Variables d’environnement
├── README.md
└── lib/                 # Toute la logique Node.js
    ├── config.js        # OPENBAO_ADDR, TOKEN, chemin KV
    ├── client.js        # API KV : save / load / health
    ├── vaultSummary.js  # Résumé clés pour l’UI (sans blobs)
    ├── routes.js        # GET /api/openbao/status | /coffre
    └── index.js         # Exports
```

## Démarrage

```bash
./simulation/openbao/start.sh
export OPENBAO_ADDR=http://127.0.0.1:8200
export OPENBAO_TOKEN=payhsm-dev-token
cd simulation/backend && npm start
```

UI : simulateur http://127.0.0.1:5173 → onglet **OpenBao**.

## Contenu du secret KV

| Champ | Description |
|--------|-------------|
| `lmkRef` | Empreinte LMK PayHSM (pas la LMK) |
| `keys[]` | TMK, ZMK, IMK, PVK, ZPK, TPK, TAK — `cryptogram` sous LMK |
| `savedAt` | Horodatage |

## Intégration backend

- `simulation/backend/config.js` importe `OPENBAO` depuis `openbao/lib/config.js`
- `server.js` monte `createOpenBaoRouter({ listVault })` sur `/api/openbao`
- `switchVaultPersist.js` lit/écrit via `openbao/lib/client.js` (disque + OpenBao)

## CLI

```bash
./simulation/openbao/show-coffre.sh
curl -s http://127.0.0.1:4000/api/openbao/status | python3 -m json.tool
```
