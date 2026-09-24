# AttackSim Pro — MariaDB backup & DR

Self-hosted, NAS-backed. Credentials come from the environment **by name** — never
committed. Verified end to end in CI (`.github/workflows/store-integration.yml` seeds a
row, backs up, deletes it, restores, and asserts it returns).

## Backup (`backup.sh`)

`mysqldump --single-transaction` (consistent, non-locking on InnoDB) of the ASP database
to a timestamped `.sql.gz` under `$ASP_BACKUP_DIR` (a NAS-backed volume). Keeps the newest
`$ASP_BACKUP_KEEP` (default 14) dumps.

```sh
MARIADB_HOST=… MARIADB_USER=… MARIADB_PASSWORD=… MARIADB_DATABASE=attacksimpro \
  ASP_BACKUP_DIR=/nas/asp/backups sh deploy/mariadb/backup.sh
```

Run nightly from cron on the NAS host, e.g. `15 2 * * *`. Copy `$ASP_BACKUP_DIR` off-NAS as
part of the NAS backup job so the dumps survive a NAS loss.

## Restore (`restore.sh`)

Restores a dump into a target database (the dump carries its own `CREATE DATABASE`/`USE`).
Overwrites the target's ASP tables — use a fresh/scratch target during recovery.

```sh
MARIADB_HOST=… MARIADB_USER=… MARIADB_PASSWORD=… sh deploy/mariadb/restore.sh <dump.sql.gz>
```

## DR / rollback

The MariaDB datadir and the evidence-file volume are the only stateful assets; both are
NAS-backed and in the backup set. Recovery = restore the newest dump into a fresh MariaDB
container, remount the evidence volume, redeploy the stateless containers. The migration
itself is config-selected (`ASP_STORE`/`ASP_MARIADB_URL`), so rolling the store choice back
is a config change, not a data migration. A Firestore→MariaDB backfill is a separate,
explicitly-approved step — never run autonomously.
