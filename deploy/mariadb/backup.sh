#!/bin/sh
# AttackSim Pro — MariaDB backup (self-hosted, NAS-backed). POSIX sh (BusyBox-safe).
# Dumps the ASP schema to a timestamped gzip under $ASP_BACKUP_DIR (a NAS-backed volume).
# Credentials come from the environment BY NAME — never hardcoded. Fail-closed on any
# missing config. No deploy side effects; safe to run from cron on the NAS host.
#
#   MARIADB_HOST MARIADB_PORT MARIADB_USER MARIADB_PASSWORD MARIADB_DATABASE ASP_BACKUP_DIR
set -eu

: "${MARIADB_HOST:?set MARIADB_HOST}"
: "${MARIADB_USER:?set MARIADB_USER}"
: "${MARIADB_PASSWORD:?set MARIADB_PASSWORD}"
: "${MARIADB_DATABASE:?set MARIADB_DATABASE}"
PORT="${MARIADB_PORT:-3306}"
DIR="${ASP_BACKUP_DIR:?set ASP_BACKUP_DIR (NAS-backed volume)}"

mkdir -p "$DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$DIR/.asp-${MARIADB_DATABASE}-${STAMP}.sql"
OUT="$DIR/asp-${MARIADB_DATABASE}-${STAMP}.sql.gz"

# The MySQL 8 client probes information_schema.COLUMN_STATISTICS, which MariaDB does not
# have; disable it when this client supports the flag. The MariaDB client lacks the flag
# (and does not need it), so add it only when present — keeps the script portable across
# the CI runner (MySQL client) and the NAS host (MariaDB client).
COLSTATS=""
if mysqldump --help 2>/dev/null | grep -q -- '--column-statistics'; then
  COLSTATS="--column-statistics=0"
fi

# Dump to a temp file first so a mysqldump failure is caught before we publish a .gz
# (POSIX sh has no pipefail). --single-transaction = consistent, non-locking on InnoDB.
# shellcheck disable=SC2086  # $COLSTATS is intentionally a single optional flag or empty
mysqldump --host="$MARIADB_HOST" --port="$PORT" --user="$MARIADB_USER" \
  --password="$MARIADB_PASSWORD" --single-transaction --routines --triggers $COLSTATS \
  --databases "$MARIADB_DATABASE" > "$TMP"
gzip -c "$TMP" > "$OUT"
rm -f "$TMP"

# Retention: keep the newest $ASP_BACKUP_KEEP (default 14) dumps for this database.
KEEP="${ASP_BACKUP_KEEP:-14}"
ls -1t "$DIR"/asp-"$MARIADB_DATABASE"-*.sql.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do
  rm -f "$old"
done

echo "backup: wrote $OUT ($(wc -c < "$OUT") bytes); retained newest $KEEP"
