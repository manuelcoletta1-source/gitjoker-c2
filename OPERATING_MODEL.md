# Operating Model (GITJOKER-C2)

## Pipeline (alto livello)
1) Input (richiesta di pubblicazione)
2) Controlli ex-ante (policy + integrità)
3) Generazione evidenze (manifest/receipt/freeze)
4) Pubblicazione (solo se tutti i controlli passano)
5) Evento di audit (append-only)

## Controlli minimi (fail-closed)
- integrità struttura repo (file richiesti presenti)
- coerenza hash / manifest
- policy reference (UNEBDO/OPC) non indeterminata
- nessun dato personale nel payload (hash-only)

## Output
- `PACK_MANIFEST.json`
- `receipt.json` (se previsto)
- `FREEZE.md` (se previsto)
- evento audit con reason codes
