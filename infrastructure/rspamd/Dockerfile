# Сканер Rspamd для MSP 1.2 (ТЗ 1.2 §3, §4). Rspamd — специализированный сканер: SPF, DKIM, DMARC,
# ARC, RBL и спам-эвристики не пишутся заново, а берутся из него. MSP остаётся слоем политики,
# корреляции и аудита.
#
# Образ не содержит боевой конфигурации: она приходит выпуском (local.d, maps.d, scripts) из
# каталога /var/lib/msp-rspamd/active. Файлы пакета не редактируются.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends rspamd ca-certificates python3 python3-pydantic util-linux \
 && rm -rf /var/lib/apt/lists/*

COPY infrastructure/rspamd/rspamd.conf /opt/msp-rspamd/rspamd.conf
COPY infrastructure/rspamd/entrypoint.sh /usr/local/bin/msp-rspamd-entrypoint
COPY packages/antispam/msp_antispam /opt/msp/msp_antispam
RUN chmod 0755 /usr/local/bin/msp-rspamd-entrypoint

ENV PYTHONPATH=/opt/msp

# Контроллер доступен только внутри сети узла; наружу его порт не публикуется.
VOLUME ["/var/lib/msp-rspamd", "/var/lib/rspamd"]
EXPOSE 11332 11333

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 -c "import socket;socket.create_connection(('127.0.0.1',11332),3).close()" || exit 1

ENTRYPOINT ["/usr/local/bin/msp-rspamd-entrypoint"]
