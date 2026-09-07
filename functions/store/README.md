# storeScanResults store adapters

The ingest logic lives in `functions/handler.js` and depends only on an injected `db`
port — it is storage-agnostic. Swapping the backend is choosing which adapter to inject;
the handler and its tests never change.

## Adapters

| Adapter | File | Use |
|---|---|---|
| In-memory (test/local) | `../testkit/inmemory-firestore.js` | unit tests, local smoke server |
| Firestore (retired) | wired in `../index.js` via `firebase-admin` | current prod — **being retired** |
| **MariaDB (target)** | `./mariadb-store.js` | self-hosted relational store on NAS-backed infra |

## MariaDB adapter (`mariadb-store.js`)

Exposes the exact port the handler uses —
`collection("clients").doc(cid).collection("scans").doc(sid)` → `{ get(), set(data,{merge}) }`
plus `serverTimestamp()` — and maps that one path to the schema in
`../../deploy/mariadb/schema.sql`. Merge writes touch only supplied fields; `findings` rows
are replaced only when `findings` is present, so a partial `{error, updated_at}` write never
wipes stored findings. Monotonic status is enforced by the handler and preserved here.

Injection (mysql2/promise pool):

```js
const mysql = require("mysql2/promise");
const { createMariaDbStore } = require("./store/mariadb-store");
const { createStoreScanResultsHandler } = require("./handler");

const pool = await mysql.createPool(process.env.ASP_MARIADB_URL);
const handler = createStoreScanResultsHandler({
  db: createMariaDbStore({ pool }),
  ingestToken: process.env.INGEST_TOKEN || "",
});
```

## Secrets (by NAME only — never commit values)

`ASP_MARIADB_URL` (or `MARIADB_HOST`/`MARIADB_PORT`/`MARIADB_USER`/`MARIADB_PASSWORD`/
`MARIADB_DATABASE`), `INGEST_TOKEN`, `ASP_EVIDENCE_ROOT`.

## Tests

`node --test` runs `../test/mariadb-store.test.js`: the real handler is driven through this
adapter over an in-memory fake pool (upsert-merge, findings replace, monotonic status,
tenant isolation, fail-loud on bad paths). An env-gated case runs the same round-trip
against a real MariaDB when `ASP_MARIADB_URL` is set (and `mysql2` is installed), else SKIPs.

## Left for Bill (subsequent PRs)

- Point `index.js`'s prod shell at this adapter (add `mysql2`, drop `firebase-admin`) —
  the store URL/contract the workflows use is unchanged.
- Provision MariaDB + evidence volumes on the NAS (`../../deploy/mariadb/docker-compose.yml`),
  apply `schema.sql`, wire `ASP_MARIADB_URL` / `INGEST_TOKEN`.
- Cut the dashboard read path off the Firestore Web SDK to a self-hosted Read API.
