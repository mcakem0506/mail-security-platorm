# Служба принуждения узла (MSP 1.3, ТЗ 1.3 §13): решение до очереди для Rspamd и послеочередной шлюз для Postfix.
# Один образ, две роли (команда запуска): ``node serve`` и ``afterqueue``. Анализа письма здесь нет: разбор записи
# сканера — код этапа 1.2, правила — подписанная политика, письмо уходит в панель только для полного анализа и карантина.
FROM python:3.12-slim

RUN pip install --no-cache-dir "pydantic>=2.8" "PyYAML>=6.0" "tldextract>=5.1" "idna>=3.7" "nh3>=0.2.17" "dnspython>=2.6" \
 && useradd --system --uid 10053 --no-create-home --shell /usr/sbin/nologin mspenf \
 && mkdir -p /opt/msp /var/lib/msp-enforcement /var/lib/msp-enforcement-aq \
 && chown mspenf /var/lib/msp-enforcement /var/lib/msp-enforcement-aq

COPY packages/enforcement/msp_enforcement /opt/msp/msp_enforcement
COPY packages/antispam/msp_antispam /opt/msp/msp_antispam
COPY packages/mail-parser/msp_mail_parser /opt/msp/msp_mail_parser
COPY packages/shared-contracts/msp_contracts /opt/msp/msp_contracts

ENV PYTHONPATH=/opt/msp PYTHONUNBUFFERED=1
# tldextract не должна ходить в сеть за списком суффиксов: используется встроенный снимок.
ENV TLDEXTRACT_CACHE=/tmp/tldextract
USER mspenf
VOLUME ["/var/lib/msp-enforcement", "/var/lib/msp-enforcement-aq"]
EXPOSE 11390 10025

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:11390/healthz',timeout=3)" || exit 1

CMD ["python", "-m", "msp_enforcement.node", "serve", "--host", "0.0.0.0", "--port", "11390"]
