#!/usr/bin/env bash
# Restore drill and disaster recovery (ТЗ 32, 44).
#
# By default this restores into a SEPARATE database so the drill can be run without touching
# production. Restoring over the live database requires --target production and an explicit
# confirmation, because it destroys current data.

set -Eeuo pipefail

BACKUP_DIR="${1:-}"
TARGET_MODE="drill"
COMPOSE="${COMPOSE:-docker compose}"
PG_USER="${POSTGRES_USER:-msp}"
PG_DB="${POSTGRES_DB:-msp}"
DRILL_DB="${DRILL_DB:-msp_restore_drill}"

usage() {
    cat >&2 <<'USAGE'
Usage: restore.sh <backup-directory> [--target drill|production]

  drill       restore into a temporary database and verify (default, safe)
  production  restore over the live database (destructive, requires confirmation)
USAGE
    exit 2
}

shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_MODE="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

[[ -n "$BACKUP_DIR" ]] || usage
[[ -f "${BACKUP_DIR}/postgres.dump" ]] || fail "postgres.dump not found in ${BACKUP_DIR}"

case "$TARGET_MODE" in
    drill)
        RESTORE_DB="$DRILL_DB"
        log "restore drill into database '${RESTORE_DB}' (production is untouched)"
        $COMPOSE exec -T postgres psql --username="$PG_USER" --dbname=postgres \
            -c "DROP DATABASE IF EXISTS ${RESTORE_DB};" \
            -c "CREATE DATABASE ${RESTORE_DB};"
        ;;
    production)
        RESTORE_DB="$PG_DB"
        cat >&2 <<WARNING

  WARNING: this will overwrite the live database '${RESTORE_DB}'.
  All data written since the backup was taken will be lost.

WARNING
        read -r -p "Type the database name to confirm: " CONFIRM
        [[ "$CONFIRM" == "$RESTORE_DB" ]] || fail "confirmation did not match; nothing was changed"
        log "stopping application services before the restore"
        $COMPOSE stop api worker-mail worker-ti worker-maintenance scheduler || true
        ;;
    *)
        usage
        ;;
esac

log "restoring dump"
$COMPOSE exec -T postgres pg_restore \
    --username="$PG_USER" \
    --dbname="$RESTORE_DB" \
    --clean --if-exists --no-owner --no-privileges \
    < "${BACKUP_DIR}/postgres.dump" \
    || log "pg_restore reported non-fatal warnings"

log "verifying restored data"
ROWS=$($COMPOSE exec -T postgres psql --username="$PG_USER" --dbname="$RESTORE_DB" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
log "restored schema contains ${ROWS} tables"
[[ "${ROWS//[^0-9]/}" -gt 20 ]] || fail "restored schema looks incomplete (${ROWS} tables)"

AUDIT=$($COMPOSE exec -T postgres psql --username="$PG_USER" --dbname="$RESTORE_DB" -tAc \
    "SELECT count(*) FROM audit_events;" 2>/dev/null || echo 0)
log "audit events restored: ${AUDIT//[^0-9]/}"

if [[ "$TARGET_MODE" == "drill" ]]; then
    log "drill successful; dropping the temporary database"
    $COMPOSE exec -T postgres psql --username="$PG_USER" --dbname=postgres \
        -c "DROP DATABASE IF EXISTS ${RESTORE_DB};"
    log "RESTORE DRILL PASSED — record this in the acceptance report (ТЗ 44)"
else
    log "applying migrations in case the backup predates the current schema"
    $COMPOSE run --rm migrate
    log "starting application services"
    $COMPOSE start api worker-mail worker-ti worker-maintenance scheduler
    log "RESTORE COMPLETE"
fi
