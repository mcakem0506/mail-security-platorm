#!/bin/sh
# Запуск сканера Rspamd (ТЗ 1.2 §4). Порядок: выпуск конфигурации из начального пакета,
# приёмник результатов от непривилегированного пользователя, затем сам сканер.
set -eu

ROOT=/var/lib/msp-rspamd
mkdir -p "$ROOT/outbox" /run/rspamd /var/lib/rspamd
chown _rspamd:_rspamd /run/rspamd /var/lib/rspamd
chown 65534:65534 "$ROOT/outbox"

if [ -f /bootstrap/rspamd.json ]; then
    python3 -m msp_antispam.node apply --config /bootstrap/rspamd.json
fi

# Приёмник результатов: свой пользователь и никаких прав на конфигурацию и ключи.
setpriv --reuid=65534 --regid=65534 --clear-groups \
    python3 -m msp_antispam.node collector --outbox "$ROOT/outbox" &

exec rspamd -f -u _rspamd -g _rspamd -c /opt/msp-rspamd/rspamd.conf \
    --var "LOCAL_CONFDIR=$ROOT/active"
