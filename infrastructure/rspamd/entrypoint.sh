#!/bin/sh
# Запуск сканера Rspamd (ТЗ 1.2 §4). Порядок: выпуск конфигурации из начального пакета,
# приёмник результатов от непривилегированного пользователя, синхронизация с панелью от root
# (применять выпуски вправе только она), затем сам сканер.
set -eu

ROOT=/var/lib/msp-rspamd
mkdir -p "$ROOT/outbox" /run/rspamd /var/lib/rspamd
chown _rspamd:_rspamd /run/rspamd /var/lib/rspamd
chown 65534:65534 "$ROOT/outbox"

if [ -f /bootstrap/rspamd.json ]; then
    python3 -m msp_antispam.node apply --config /bootstrap/rspamd.json
fi

PANEL_SPAM_URL=""
if [ -n "${MSP_PANEL_URL:-}" ]; then
    PANEL_SPAM_URL="${MSP_PANEL_URL}/spam-scans"
fi

# Приёмник результатов и метрики: свой пользователь, никаких прав на конфигурацию и ключи.
MSP_PANEL_SPAM_URL="$PANEL_SPAM_URL" setpriv --reuid=65534 --regid=65534 --clear-groups \
    python3 -m msp_antispam.node collector --outbox "$ROOT/outbox" &

# Синхронизация с панелью: забирает назначение, применяет выпуск, сообщает состояние.
if [ -n "${MSP_PANEL_URL:-}" ] && [ -n "${MSP_PANEL_TOKEN_FILE:-}" ]; then
    python3 -m msp_antispam.node sync --interval "${MSP_SYNC_INTERVAL:-30}" &
fi

exec rspamd -f -u _rspamd -g _rspamd -c /opt/msp-rspamd/rspamd.conf \
    --var "LOCAL_CONFDIR=$ROOT/active"
