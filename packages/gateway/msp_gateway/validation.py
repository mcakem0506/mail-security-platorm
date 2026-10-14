"""Проверка значений, которые попадут в конфигурацию Postfix (ТЗ 1.1 §64).

Конфигурация MTA собирается из значений, пришедших из API и интерфейса, а Postfix устроен так,
что один неосторожный символ меняет смысл настройки:

* перевод строки начинает новую директиву — значение «a.example\\nmynetworks = 0.0.0.0/0» из
  поля «домен» превращает шлюз в открытый релей;
* ``$`` раскрывается как имя параметра, ``$myhostname`` в значении подставляется молча;
* пробел и запятая разделяют элементы списка, ``%`` и ``!`` в адресе — старые формы маршрутизации;
* в картах ``hash:`` ключ от значения отделяет пробел.

Поэтому здесь нет «очистки» значений: всё, что не похоже на ожидаемый формат, отклоняется целиком
с названием причины. Очистка молча превращает неверный ввод в другой, валидный, и оператор об этом
не узнаёт; отказ заставляет его посмотреть.

Модуль зависит только от стандартной библиотеки: его использует и генератор конфигурации, и
узловой агент, и скрипт записи журнала, который запускается самим Postfix.
"""

from __future__ import annotations

import ipaddress
import re

#: Метка домена: буквы, цифры, дефис внутри; не длиннее 63 символов (RFC 1035).
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

#: Верхний предел длины имени целиком (RFC 1035).
MAX_DOMAIN_LENGTH = 253

#: Всё, что в Postfix имеет синтаксическое значение. Ни один из этих символов не встречается в
#: допустимом имени хоста, домена или адреса, который мы собираемся записать в конфигурацию.
_FORBIDDEN_CHARS = re.compile(r"[\s\x00-\x1f\x7f$%!#\\\"'`;|&<>(){}\[\],=:]")

#: Символы IP-адреса и подсети. Проверка по набору символов идёт раньше разбора: ``ipaddress``
#: снисходителен к лишнему, а в конфигурацию должно попасть только то, что мы сами напечатали.
_IP_CHARS = re.compile(r"[0-9a-fA-F:.]+")
_NETWORK_CHARS = re.compile(r"[0-9a-fA-F:.]+(/[0-9]{1,3})?")

#: Локальная часть адреса: разрешён консервативный набор. Адреса, требующие кавычек, в каталог
#: получателей шлюза не принимаются — они редки, а цена ошибки разбора здесь высока.
_LOCAL_PART = re.compile(r"^[a-z0-9][a-z0-9._+\-]{0,63}$")


class ConfigValueError(ValueError):
    """Значение отклонено. Сообщение называет поле и причину, но не повторяет само значение.

    Повторять значение в тексте ошибки нельзя: оно может быть попыткой инъекции, а текст
    ошибки попадает в журнал и в интерфейс.
    """


def _reject(field: str, reason: str) -> ConfigValueError:
    return ConfigValueError(f"{field}: {reason}")


def check_plain(value: str, field: str) -> str:
    """Общая проверка: непустая строка без управляющих символов и синтаксиса Postfix."""
    if not isinstance(value, str):
        raise _reject(field, "ожидалась строка")
    if not value:
        raise _reject(field, "значение пустое")
    if _FORBIDDEN_CHARS.search(value):
        raise _reject(field, "содержит символ, имеющий смысл в конфигурации MTA")
    return value


def domain(value: str, field: str = "domain") -> str:
    """Имя домена в нижнем регистре, ASCII.

    Интернационализированные домены принимаются только в punycode: Postfix хранит и сравнивает
    ASCII, а запись в карту символов за его пределами — повод для расхождения между тем, что
    проверил оператор, и тем, что сравнит MTA.
    """
    candidate = check_plain(value, field).lower().rstrip(".")
    if len(candidate) > MAX_DOMAIN_LENGTH:
        raise _reject(field, "имя домена длиннее 253 символов")
    try:
        candidate.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _reject(field, "домен должен быть в ASCII (punycode)") from exc
    labels = candidate.split(".")
    if len(labels) < 2:
        raise _reject(field, "ожидалось имя вида example.test, а не одна метка")
    for label in labels:
        if not _LABEL.match(label):
            raise _reject(field, "метка домена нарушает формат")
    # Хвост из одних цифр — это попытка записать IP-адрес как домен; для хоста назначения
    # IP пишется в скобках отдельным полем, и спутать их значило бы обойти проверку CIDR.
    if labels[-1].isdigit():
        raise _reject(field, "последняя метка не может состоять из одних цифр")
    return candidate


def hostname(value: str, field: str = "host") -> str:
    """Имя хоста назначения. Допускается и IP-адрес — для лабораторных стендов."""
    if not isinstance(value, str) or not value:
        raise _reject(field, "значение пустое")
    if _IP_CHARS.fullmatch(value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise _reject(field, "некорректный IP-адрес") from exc
    lowered = check_plain(value, field).lower().rstrip(".")
    if len(lowered) > MAX_DOMAIN_LENGTH:
        raise _reject(field, "имя хоста длиннее 253 символов")
    # Имя без точки допустимо: так выглядит имя сервиса внутри сети контейнеров.
    for label in lowered.split("."):
        if not _LABEL.match(label):
            raise _reject(field, "метка имени хоста нарушает формат")
    return lowered


def port(value: int, field: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _reject(field, "порт должен быть целым числом")
    if not 1 <= value <= 65535:
        raise _reject(field, "порт вне диапазона 1..65535")
    return value


def network(value: str, field: str = "network") -> str:
    """Подсеть или адрес в нотации CIDR.

    ``0.0.0.0/0`` и ``::/0`` отклоняются отдельно и безусловно: это единственное значение, которое
    превращает доверенную сеть в «весь Интернет», и оператор, написавший его по ошибке или под
    давлением, не должен получить работающий открытый релей. Широкие, но не полные сети
    допустимы — это решение оператора, а не ошибка формата.
    """
    if not isinstance(value, str) or not _NETWORK_CHARS.fullmatch(value):
        raise _reject(field, "некорректная подсеть")
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise _reject(field, "некорректная подсеть") from exc
    if parsed.prefixlen == 0:
        raise _reject(field, "подсеть «весь Интернет» не может быть доверенной")
    return str(parsed)


def email_address(value: str, field: str = "address") -> str:
    """Адрес получателя: ``local@domain`` в нижнем регистре, без экзотики."""
    if not isinstance(value, str) or value.count("@") != 1:
        raise _reject(field, "ожидался адрес вида user@example.test")
    local, _, host = value.strip().lower().partition("@")
    if not _LOCAL_PART.match(local):
        raise _reject(field, "локальная часть содержит недопустимые символы")
    domain(host, field)
    return f"{local}@{host}"


def map_value(value: str, field: str) -> str:
    """Значение для правой части записи карты: ни пробелов, ни переводов строк."""
    return check_plain(value, field)


_PATH = re.compile(r"^/[A-Za-z0-9_./-]{1,200}$")


def absolute_path(value: str, field: str) -> str:
    """Абсолютный путь из безопасного набора символов, без ``..``.

    Пути вставляются в конфигурацию, поэтому набор символов ограничен тем, что нужно настоящим
    путям, а не тем, что файловая система допускает.
    """
    if not isinstance(value, str) or not _PATH.fullmatch(value):
        raise _reject(field, "ожидался абсолютный путь из букв, цифр и «_ . / -»")
    if ".." in value.split("/"):
        raise _reject(field, "путь не должен содержать «..»")
    return value
