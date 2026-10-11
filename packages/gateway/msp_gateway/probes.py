"""Синтетические SMTP-пробы шлюза (ТЗ 1.1 §47, §48, §12, §53).

Проба отвечает на вопрос «что шлюз сделает с этим письмом», не отправляя письма: сессия
доходит до ответа на ``RCPT TO`` и закрывается командой ``RSET``/``QUIT`` до ``DATA``. Поэтому
проверки открытого релея безопасны на любом узле, в том числе с живым трафиком: ни одно письмо
не попадёт в очередь.

Результат — не «ошибка/успех», а одно из состояний, потому что у каждого своё следствие:

* ``ACCEPTED`` — шлюз согласился принять получателя;
* ``REJECTED`` — отказ навсегда (5xx);
* ``DEFERRED`` — временный отказ (4xx), письмо повторится;
* ``UNREACHABLE`` — до шлюза не дошли (сеть, порт, таймаут).

Для проверки открытого релея важно различать последние три: ``REJECTED`` — правильный ответ,
``DEFERRED`` — тоже безопасный (письмо не принято), а ``UNREACHABLE`` — не «безопасно», а «не
проверено», и записывать его как прохождение нельзя.
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from dataclasses import dataclass
from enum import StrEnum


class ProbeState(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    UNREACHABLE = "UNREACHABLE"


@dataclass(frozen=True)
class ProbeResult:
    state: ProbeState
    #: Этап, на котором получен ответ: connect, ehlo, starttls, mail, rcpt.
    stage: str
    code: int | None = None
    message: str = ""
    starttls_offered: bool | None = None

    @property
    def is_safe_for_relay_test(self) -> bool:
        """Письмо принято не было. ``UNREACHABLE`` сюда не входит: непроверенное — не безопасное."""
        return self.state in (ProbeState.REJECTED, ProbeState.DEFERRED)


def _classify(code: int) -> ProbeState:
    if 200 <= code < 300:
        return ProbeState.ACCEPTED
    if 400 <= code < 500:
        return ProbeState.DEFERRED
    return ProbeState.REJECTED


def _insecure_context() -> ssl.SSLContext:
    # Проба проверяет поведение собственного слушателя, а не личность сервера: сертификат
    # лабораторного узла часто выдан внутренним УЦ, которого нет в доверенных у процесса
    # проверки. Проверка цепочки до Exchange — отдельная проба (tls_probe), и она строгая.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def smtp_probe(
    host: str,
    port: int,
    *,
    mail_from: str,
    rcpt_to: str,
    helo: str = "probe.msp.invalid",
    starttls: bool = False,
    timeout: float = 10.0,
) -> ProbeResult:
    """Дойти до ответа на ``RCPT TO`` и закрыть сессию, не передавая данные."""
    client: smtplib.SMTP | None = None
    stage = "connect"
    offered: bool | None = None
    try:
        client = smtplib.SMTP(timeout=timeout)
        code, message = client.connect(host, port)
        if code >= 400:
            return ProbeResult(_classify(code), stage, code, _text(message))
        stage = "ehlo"
        code, message = client.ehlo(helo)
        if code >= 400:
            return ProbeResult(_classify(code), stage, code, _text(message))
        offered = client.has_extn("starttls")
        if starttls:
            stage = "starttls"
            if not offered:
                return ProbeResult(ProbeState.REJECTED, stage, None, "STARTTLS не предложен", offered)
            code, message = client.starttls(context=_insecure_context())
            if code >= 400:
                return ProbeResult(_classify(code), stage, code, _text(message), offered)
            client.ehlo(helo)
        stage = "mail"
        code, message = client.mail(mail_from)
        if code >= 400:
            return ProbeResult(_classify(code), stage, code, _text(message), offered)
        stage = "rcpt"
        code, message = client.rcpt(rcpt_to)
        return ProbeResult(_classify(code), stage, code, _text(message), offered)
    except smtplib.SMTPResponseException as exc:
        return ProbeResult(_classify(exc.smtp_code), stage, exc.smtp_code, _text(exc.smtp_error), offered)
    except (TimeoutError, OSError, smtplib.SMTPException) as exc:
        # Сообщение исключения не берём: оно может содержать адрес из запроса. Достаточно класса.
        return ProbeResult(ProbeState.UNREACHABLE, stage, None, type(exc).__name__, offered)
    finally:
        if client is not None:
            try:
                client.quit()
            except (OSError, smtplib.SMTPException):
                client.close()


def _text(value: object) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value)[:200]


#: Домен зарезервированной зоны ``.invalid``: он заведомо не существует и не принадлежит нам.
EXTERNAL_PROBE_ADDRESS = "relay-probe@open-relay-test.invalid"


def open_relay_probe(host: str, port: int, *, starttls: bool = False, timeout: float = 10.0) -> ProbeResult:
    """Попытка доставки с недоверенного адреса на внешнего получателя (ТЗ §12).

    Ожидается отказ. ``ACCEPTED`` — критическая находка: шлюз принял бы чужое письмо в чужой
    адрес. Проба идёт с адреса, которого у шлюза в доверенных нет (пробы запускаются из места,
    не входящего в ``trusted_networks``), поэтому принять его шлюз не должен ни при каком режиме.
    """
    return smtp_probe(
        host,
        port,
        mail_from="attacker@external-sender.invalid",
        rcpt_to=EXTERNAL_PROBE_ADDRESS,
        starttls=starttls,
        timeout=timeout,
    )


def banner_probe(host: str, port: int, *, timeout: float = 5.0) -> ProbeResult:
    """Слушатель отвечает приветствием SMTP. Нижний уровень проверки здоровья."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            greeting = sock.recv(512).decode("ascii", errors="replace")
    except OSError as exc:
        return ProbeResult(ProbeState.UNREACHABLE, "connect", None, type(exc).__name__)
    if greeting.startswith("220"):
        return ProbeResult(ProbeState.ACCEPTED, "connect", 220, greeting.strip()[:200])
    code = int(greeting[:3]) if greeting[:3].isdigit() else None
    state = _classify(code) if code is not None else ProbeState.UNREACHABLE
    return ProbeResult(state, "connect", code, greeting.strip()[:200])
