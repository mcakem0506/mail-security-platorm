"""Зоны DNS для проверок: у каждого сценария свой домен.

Rspamd кэширует ответы DNS, поэтому два сценария на одном домене влияют друг на друга. Свой домен
на сценарий — единственный надёжный способ их изолировать, и он же оставляет сам стенд общим.
"""

from __future__ import annotations

import uuid

from .harness import SENDER_IP, DkimKey, build_message


class Zone:
    def __init__(self, label: str = "z", *, selector: str = "s1") -> None:
        self.domain = f"{label}{uuid.uuid4().hex[:8]}.com"
        self.selector = selector
        self.key = DkimKey.generate(self.domain, selector)
        self.helo = f"mail.{self.domain}"
        self.address = f"user@{self.domain}"

    # --- записи ----------------------------------------------------------------------------
    def records(
        self,
        *,
        spf: str | None = None,
        dmarc: str | None = None,
        dkim: bool = True,
        sender_ip: str = SENDER_IP,
        extra: dict[str, dict[str, object]] | None = None,
        ptr: bool = True,
    ) -> dict[str, dict[str, object]]:
        out: dict[str, dict[str, object]] = {
            self.domain: {"A": [sender_ip]},
            self.helo: {"A": [sender_ip]},
        }
        if spf is not None:
            out[self.domain]["TXT"] = [spf.replace("{ip}", sender_ip)]
        if dmarc is not None:
            out[f"_dmarc.{self.domain}"] = {"TXT": [dmarc]}
        if dkim:
            out[self.key.dns_name] = self.key.dns_record
        if ptr:
            out[reverse_name(sender_ip)] = {"PTR": [self.helo]}
        out.update(extra or {})
        return out

    # --- письмо ----------------------------------------------------------------------------
    def message(
        self, message_id: str, *, sign: bool = True, from_address: str | None = None, **kwargs: object
    ) -> bytes:
        raw = build_message(message_id, from_address or self.address, **kwargs)  # type: ignore[arg-type]
        return self.key.sign(raw) if sign else raw


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
