#!/bin/sh
# Точка входа узла шлюза.
#
# Порядок важен. Каталоги и права готовятся до всего остального; конфигурация применяется той
# же логикой, что и при обновлении (msp_gateway.node), а не отдельной копией для первого
# запуска; Postfix запускается последним и в переднем плане, чтобы им управлял контейнер.
set -eu

ROOT=/var/lib/msp
mkdir -p "$ROOT/config" "$ROOT/state" "$ROOT/journal/tmp" "$ROOT/journal/new" \
         /var/log/msp /run/secrets/gateway

# Состояние, которое меняется во время работы и не относится к версии конфигурации.
# Пустые файлы означают «не сливаем, справочник свежий».
touch "$ROOT/state/drain.pcre" "$ROOT/state/recipient_gate.pcre"
chmod 0755 "$ROOT/state"
chmod 0644 "$ROOT/state/drain.pcre" "$ROOT/state/recipient_gate.pcre"

# Журнал копий принадлежит писателю; прочим доступ закрыт (§62: кража данных через журнал).
chown -R mspjournal:mspjournal "$ROOT/journal"
chmod 0700 "$ROOT/journal"

chown postfix:postfix /var/log/msp

if [ ! -L "$ROOT/config/active" ]; then
  if [ ! -d /bootstrap ]; then
    echo "msp-gateway: нет активной конфигурации и нет /bootstrap — запускать нечего" >&2
    exit 1
  fi
  python3 -m msp_gateway.node apply /bootstrap --no-health
fi

# postfix check создаёт недостающие каталоги очереди на пустом томе и исправляет права.
postfix -c "$MAIL_CONFIG" check
exec postfix -c "$MAIL_CONFIG" start-fg
