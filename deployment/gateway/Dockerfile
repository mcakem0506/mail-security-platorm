# Транспортный узел шлюза MSP (ТЗ 1.1 §3, §8).
#
# Postfix — зрелый MTA, свой SMTP-сервер на Python не пишется. Образ неизменяем: конфигурация
# в него не входит, она приходит пакетом и активируется при запуске (§8: config generated
# outside image). Контейнер не привилегированный, без доступа к Docker-сокету.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Без предварительной настройки пакет postfix задаёт вопросы через debconf и ломает сборку.
RUN apt-get update \
 && apt-get install -y --no-install-recommends debconf \
 && echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections \
 && apt-get install -y --no-install-recommends \
      postfix postfix-pcre python3 ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

# Пользователь, от имени которого Postfix запускает писателя журнала. Не postfix: писатель
# выполняет код над письмом, и у него не должно быть прав на очередь.
RUN groupadd --gid 10002 mspjournal \
 && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin mspjournal

# Только стандартная библиотека: образу транспорта не нужны зависимости продукта.
COPY packages/gateway/msp_gateway /opt/msp/msp_gateway
COPY deployment/gateway/msp-journal-write /usr/local/bin/msp-journal-write
COPY deployment/gateway/entrypoint.sh /usr/local/bin/msp-gateway-entrypoint
RUN chmod 0755 /usr/local/bin/msp-journal-write /usr/local/bin/msp-gateway-entrypoint

ENV PYTHONPATH=/opt/msp \
    MAIL_CONFIG=/var/lib/msp/config/active

# Очередь Postfix — источник истины для принятой почты (§6) и обязана быть на постоянном
# томе (§7). Без него перезапуск контейнера теряет почту, уже подтверждённую кодом 250.
VOLUME ["/var/spool/postfix", "/var/lib/msp"]

EXPOSE 25 2525

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD postfix status >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/msp-gateway-entrypoint"]
