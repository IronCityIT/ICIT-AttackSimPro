#!/bin/sh
# AttackSim Pro — MariaDB restore (DR / rollback). POSIX sh (BusyBox-safe).
# Restores a gzip dump produced by backup.sh into a target database. Credentials by name.
# This OVERWRITES the target database's ASP tables — intended for a fresh/scratch target
# during recovery, never run blindly against production.
#
#   deploy/mariadb/restore.sh <dump.sql.gz>
#   MARIADB_HOST MARIADB_PORT MARIADB_USER MARIADB_PASSWORD [MARIADB_DATABASE]
set -eu

DUMP="${1:?usage: restore.sh <dump.sql.gz>}"
[ -f "$DUMP" ] || { echo "restore: no such dump: $DUMP" >&2; exit 1; }
: "${MARIADB_HOST:?set MARIADB_HOST}"
: "${MARIADB_USER:?set MARIADB_USER}"
: "${MARIADB_PASSWORD:?set MARIADB_PASSWORD}"
PORT="${MARIADB_PORT:-3306}"

# The dump was written with --databases, so it carries its own USE/CREATE DATABASE.
gzip -dc "$DUMP" | mysql --host="$MARIADB_HOST" --port="$PORT" \
  --user="$MARIADB_USER" --password="$MARIADB_PASSWORD" ${MARIADB_DATABASE:+"$MARIADB_DATABASE"}

echo "restore: applied $DUMP"
