"""Проверка значений, попадающих в конфигурацию Postfix (ТЗ 1.1 §64).

Postfix устроен так, что один символ меняет смысл настройки: перевод строки начинает новую
директиву, ``$`` раскрывает параметр. Поэтому тесты здесь — про враждебный ввод в каждом поле,
из которого собирается конфигурация, и про то, что отказ не повторяет значение в тексте ошибки
(текст попадает в журнал и в интерфейс).
"""

from __future__ import annotations

import pytest
from msp_gateway import validation as v

#: Строки, которые в любом поле обязаны быть отвергнуты.
INJECTIONS = [
    "a.example\nmynetworks = 0.0.0.0/0",
    "a.example\r\nrelay_domains = ",
    "a.example\x00",
    "$myhostname.example",
    "${myhostname}.example",
    "a.example;rm",
    "a.example|b",
    "a.example`id`",
    "a b.example",
    "a,b.example",
    "a=b.example",
    "a:b.example",
    'a".example',
    "a'.example",
    "a\\b.example",
    "a%b.example",
    "a!b.example",
    "a#b.example",
    "<a>.example",
]


@pytest.mark.parametrize("value", INJECTIONS)
def test_a_domain_with_config_syntax_is_refused(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.domain(value)


@pytest.mark.parametrize("value", INJECTIONS)
def test_a_hostname_with_config_syntax_is_refused(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.hostname(value)


@pytest.mark.parametrize("value", INJECTIONS)
def test_the_refusal_does_not_repeat_the_value(value: str) -> None:
    """Текст ошибки попадает в журнал и в интерфейс; значение там может быть попыткой инъекции."""
    with pytest.raises(v.ConfigValueError) as caught:
        v.domain(value)
    message = str(caught.value)
    assert value not in message
    assert "\n" not in message


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "1.2.3.4",
        "-a.example",
        "a-.example",
        "a..example",
        "." + "a" * 70 + ".example",
        "ü.example",
    ],
)
def test_a_malformed_domain_is_refused(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.domain(value)


def test_a_domain_is_normalised_not_trusted() -> None:
    assert v.domain("Corp.EXAMPLE.") == "corp.example"


def test_an_internationalised_domain_is_accepted_only_as_punycode() -> None:
    """Postfix хранит и сравнивает ASCII: запись символов за его пределами — повод для расхождения
    между тем, что проверил оператор, и тем, что сравнит MTA."""
    assert v.domain("xn--80ak6aa92e.example") == "xn--80ak6aa92e.example"
    with pytest.raises(v.ConfigValueError):
        v.domain("пример.example")


def test_a_domain_longer_than_253_characters_is_refused() -> None:
    long = ".".join(["a" * 60] * 5) + ".example"
    with pytest.raises(v.ConfigValueError):
        v.domain(long)


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "0.0.0.0/00"])
def test_the_whole_internet_is_never_a_trusted_network(value: str) -> None:
    """Единственное значение, которое превращает доверенную сеть в открытый релей."""
    with pytest.raises(v.ConfigValueError):
        v.network(value)


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.0/33",
        "10.0.0.0/24\nx",
        "10.0.0.0/24 ",
        "garbage",
        "10.0.0.0/",
        "300.1.1.1/8",
        "10.0.0.0/8;",
        "",
    ],
)
def test_a_malformed_network_is_refused(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.network(value)


@pytest.mark.parametrize("value", ["10.0.0.0/8", "10.77.0.64/26", "192.0.2.1", "2001:db8::/32", "fd00::1"])
def test_ordinary_networks_are_accepted(value: str) -> None:
    assert v.network(value)


def test_a_broad_but_not_total_network_is_the_operators_decision() -> None:
    """Широкая сеть — решение оператора, а не ошибка формата: /1 допустим, /0 нет."""
    assert v.network("0.0.0.0/1") == "0.0.0.0/1"


@pytest.mark.parametrize("value", [0, 65536, -1, True, "25", 25.0])
def test_a_port_outside_the_range_or_of_the_wrong_type_is_refused(value: object) -> None:
    with pytest.raises(v.ConfigValueError):
        v.port(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [25, 2525, 65535])
def test_valid_ports_are_accepted(value: int) -> None:
    assert v.port(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "a%b@x.example",
        "a@b@c.example",
        "no-at-sign",
        "@x.example",
        "a b@x.example",
        '"quoted"@x.example',
        "a@x",
    ],
)
def test_a_malformed_address_is_refused(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.email_address(value)


def test_an_address_is_lowercased() -> None:
    assert v.email_address("Ivan.Petrov@Corp.Example") == "ivan.petrov@corp.example"


@pytest.mark.parametrize(
    "value", ["/etc/../passwd", "relative/path", "/a b", "/a;b", "/a$b", "", "/" + "a" * 300]
)
def test_an_unsafe_path_is_refused(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.absolute_path(value, "path")


def test_a_safe_path_is_accepted() -> None:
    assert v.absolute_path("/run/secrets/gateway/tls.crt", "path") == "/run/secrets/gateway/tls.crt"


def test_a_hostname_may_be_an_address_or_a_service_name() -> None:
    assert v.hostname("fake-exchange") == "fake-exchange"
    assert v.hostname("10.0.0.5") == "10.0.0.5"
    assert v.hostname("2001:db8::1") == "2001:db8::1"


def test_a_malformed_ip_literal_is_refused() -> None:
    with pytest.raises(v.ConfigValueError):
        v.hostname("999.999.999.999")


# ---------------------------------------------------------------------------------------------
# Каждый слой защиты проверяется отдельно
# ---------------------------------------------------------------------------------------------
# У domain() два независимых слоя: запрещённые символы и формат метки. Ослабление одного
# маскируется другим — это достоинство защиты, но тест, который смотрит только на итог, не
# отличает рабочие два слоя от одного. Мутационная проверка это показала: три ослабления из
# четырёх прошли незамеченными. Поэтому слои проверяются порознь.


@pytest.mark.parametrize("value", INJECTIONS)
def test_the_character_layer_refuses_config_syntax_on_its_own(value: str) -> None:
    """``check_plain`` — единственный слой у значений карт и всего, что не домен."""
    with pytest.raises(v.ConfigValueError):
        v.check_plain(value, "field")


@pytest.mark.parametrize("value", INJECTIONS)
def test_a_map_value_has_only_the_character_layer(value: str) -> None:
    with pytest.raises(v.ConfigValueError):
        v.map_value(value, "field")


@pytest.mark.parametrize("value", ["a_b.example", "a+b.example", "a*.example", "a@b.example", "a/b.example"])
def test_the_label_layer_refuses_what_the_character_layer_allows(value: str) -> None:
    """Символы, не запрещённые первым слоем, но недопустимые в метке: второй слой работает сам."""
    v.check_plain(value, "field")  # первый слой их пропускает
    with pytest.raises(v.ConfigValueError):
        v.domain(value)


@pytest.mark.parametrize("value", ["", None, 5, b"bytes"])
def test_a_non_string_or_empty_value_is_refused(value: object) -> None:
    with pytest.raises(v.ConfigValueError):
        v.check_plain(value, "field")  # type: ignore[arg-type]


def test_a_plain_value_passes_untouched() -> None:
    assert v.check_plain("exchange-1.corp.example", "field") == "exchange-1.corp.example"
