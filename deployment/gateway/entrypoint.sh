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

# Собственные данные агента наблюдения: единственное место, куда он вправе писать.
mkdir -p "$ROOT/agent"
chown mspagent:mspagent "$ROOT/agent"
chmod 0750 "$ROOT/agent"

if [ ! -L "$ROOT/config/active" ]; then
  if [ ! -d /bootstrap ]; then
    echo "msp-gateway: нет активной конфигурации и нет /bootstrap — запускать нечего" >&2
    exit 1
  fi
  python3 -m msp_gateway.node apply /bootstrap --no-health
fi

# postfix check создаёт недостающие каталоги очереди на пустом томе и исправляет права.
postfix -c "$MAIL_CONFIG" check
# Журнал Postfix создаётся с правами 0600 для root. Агенту нужно чтение, остальным — нет:
# в журнале адреса отправителей и получателей. Читает только группа агента.
touch /var/log/msp/postfix.log
chown root:mspagent /var/log/msp/postfix.log
chmod 0640 /var/log/msp/postfix.log

# Отчёт сборщика теневых копий лежит вне журнала: журнал закрыт для всех, кроме сборщика, а
# агент наблюдения обязан видеть состояние сборщика, не видя самих писем (там только счётчики).
mkdir -p "$ROOT/status"
chown mspjournal:mspjournal "$ROOT/status"
chmod 0755 "$ROOT/status"

# Постоянный идентификатор узла: общий для агента, сборщика и синхронизации, читается всеми,
# создаётся один раз и переживает пересоздание контейнера (лежит в томе).
python3 -c "from pathlib import Path; from msp_gateway.agent import node_identity; node_identity(Path('$ROOT'))"
chmod 0644 "$ROOT/node_id"

# Агент наблюдения: читает журнал и очередь, отдаёт метрики. Работает без прав на изменение
# Postfix; если он упадёт, почта продолжит ходить (пропадёт только наблюдаемость).
# Связь с панелью управления (ТЗ 1.1 §37). Выключена по умолчанию: без адреса панели узел
# работает автономно на последней применённой конфигурации. Применение требует root
# (postmap, postfix reload); проверка пакета и откат выполняются теми же функциями, что и при
# ручном применении, поэтому панель может предложить конфигурацию, но не обойти проверку узла.
if [ -n "${MSP_PANEL_URL:-}" ] && [ -n "${MSP_PANEL_TOKEN_FILE:-}" ]; then
  python3 -m msp_gateway.node sync --interval "${MSP_SYNC_INTERVAL:-30}" &
fi

# Сборщик теневых копий (ТЗ 1.1 §34). Отдельный процесс владельца журнала: его сбой не может
# ни задержать, ни отклонить, ни потерять почту.
if [ -n "${MSP_INGEST_URL:-}" ] && [ -n "${MSP_INGEST_TOKEN_FILE:-}" ]; then
  setpriv --reuid=mspjournal --regid=mspjournal --clear-groups \
    python3 -m msp_gateway.node collector --interval "${MSP_COLLECT_INTERVAL:-5}" &
fi

# Закрытие приёма при безнадёжно устаревшем справочнике (ТЗ §16). Требует postfix reload, поэтому
# выполняет root; включается явно, потому что без справочника в боевом режиме узел принимал бы всех.
if [ "${MSP_RECIPIENT_GATE:-0}" = "1" ]; then
  (
    while true; do
      python3 -m msp_gateway.node gate-refresh >/dev/null 2>&1 || true
      sleep 30
    done
  ) &
fi

if [ "${MSP_AGENT:-1}" = "1" ]; then
  # Снимок очереди снимает root: у агента нет права говорить с postqueue (см. agent.py).
  (
    while true; do
      if postqueue -j > "$ROOT/agent/queue.json.tmp" 2>/dev/null; then
        chown root:mspagent "$ROOT/agent/queue.json.tmp"
        chmod 0640 "$ROOT/agent/queue.json.tmp"
        mv -f "$ROOT/agent/queue.json.tmp" "$ROOT/agent/queue.json"
      fi
      sleep 5
    done
  ) &
  setpriv --reuid=mspagent --regid=mspagent --clear-groups     python3 -m msp_gateway.node agent --queue-snapshot "$ROOT/agent/queue.json" --role "${MSP_ROLE:-LAB}" --port "${MSP_METRICS_PORT:-9100}" &
fi
exec postfix -c "$MAIL_CONFIG" start-fg
