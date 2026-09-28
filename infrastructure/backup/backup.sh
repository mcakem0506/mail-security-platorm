#!/usr/bin/env bash
# Backup for the Mail Security Platform (ТЗ 32).
#
# Backs up PostgreSQL, configuration and policy versions. Object storage is backed up according
# to the retention policy and is handled separately because of its size. Redis is NOT backed up:
# it is a cache and broker, never authoritative storage.
#
# A restore drill is mandatory before production acceptance (ТЗ 32, 44) — see restore.sh.

set -Eeuo pipefail

BACKUP_ROOT="${BACKUP_ROOT:-/backup}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${BACKUP_ROOT}/${STAMP}"
RETAIN_DAYS="${BACKUP_RETAIN_DAYS:-30}"
COMPOSE="${COMPOSE:-docker compose}"
PG_USER="${POSTGRES_USER:-msp}"
PG_DB="${POSTGRES_DB:-msp}"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

trap 'fail "backup failed at line $LINENO"' ERR

mkdir -p "$TARGET"
chmod 700 "$TARGET"

log "backing up PostgreSQL"
# --clean --if-exists makes the dump restorable onto a populated database.
$COMPOSE exec -T postgres pg_dump \
    --username="$PG_USER" \
    --dbname="$PG_DB" \
    --format=custom \
    --compress=6 \
    --clean --if-exists \
    > "${TARGET}/postgres.dump"

[[ -s "${TARGET}/postgres.dump" ]] || fail "database dump is empty"

log "backing up configuration"
tar czf "${TARGET}/config.tar.gz" \
    --exclude='infrastructure/compose/secrets/*' \
    --exclude='infrastructure/nginx/tls/*' \
    compose.yml .env.example infrastructure/nginx infrastructure/compose 2>/dev/null || true

# Secrets and TLS keys are deliberately excluded: they live in the secret store and are rotated
# independently (ТЗ 28). Record only the fact that they exist.
{
    echo "backup: ${STAMP}"
    echo "postgres_dump_bytes: $(stat -c%s "${TARGET}/postgres.dump")"
    echo "secrets_excluded: true"
    echo "object_storage_included: ${INCLUDE_OBJECT_STORAGE:-false}"
} > "${TARGET}/manifest.txt"

if [[ "${INCLUDE_OBJECT_STORAGE:-false}" == "true" ]]; then
    log "backing up object storage"
    $COMPOSE exec -T object-storage mc mirror --quiet /data "${TARGET}/object-storage" \
        || log "WARNING: object storage mirror incomplete"
fi

log "verifying the dump can be read"
$COMPOSE exec -T postgres pg_restore --list < "${TARGET}/postgres.dump" > "${TARGET}/contents.txt" \
    || fail "dump verification failed: the backup is not restorable"

TABLES=$(grep -c 'TABLE DATA' "${TARGET}/contents.txt" || true)
log "dump contains ${TABLES} tables with data"
[[ "${TABLES}" -gt 0 ]] || fail "dump contains no table data"

log "pruning backups older than ${RETAIN_DAYS} days"
find "$BACKUP_ROOT" -maxdepth 1 -type d -name '20*' -mtime "+${RETAIN_DAYS}" -exec rm -rf {} + || true

log "backup complete: ${TARGET}"
