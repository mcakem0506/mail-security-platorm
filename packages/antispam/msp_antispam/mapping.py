"""Версионируемое отображение символов Rspamd в сигналы MSP (ТЗ 1.2 §26).

Правило «оценка сканера выше X — высокий риск» здесь отсутствует намеренно: оценка зависит от
набора символов и весов конкретной версии Rspamd, и порог на неё превращает чужие настройки в
наше решение. Вместо этого каждый символ либо отображён на именованный сигнал, либо нет.
Неизвестный символ сохраняется как свидетельство и на риск не влияет, пока его не рассмотрели.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .model import RspamdEvidence
from .policy import SpamPolicy

DATA = Path(__file__).parent / "data" / "symbol_mapping.yaml"

#: Выведенный сигнал: не символ, а условие над оценкой и порогом политики (в одном месте, с версией).
SPAM_HIGH_SCORE = "SPAM_HIGH_SCORE"


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class MappingEntry:
    symbol: str
    signal: str
    kind: str
    risk_effect: str

    @property
    def is_prefix(self) -> bool:
        return self.symbol.endswith("*")

    def matches(self, name: str) -> bool:
        return name.startswith(self.symbol[:-1]) if self.is_prefix else name == self.symbol


@dataclass(frozen=True)
class SymbolMapping:
    version: str
    entries: tuple[MappingEntry, ...]

    def lookup(self, name: str) -> MappingEntry | None:
        exact = [e for e in self.entries if not e.is_prefix and e.matches(name)]
        if exact:
            return exact[0]
        prefixed = [e for e in self.entries if e.is_prefix and e.matches(name)]
        return prefixed[0] if prefixed else None


def parse_mapping(raw: dict[str, Any]) -> SymbolMapping:
    version = str(raw.get("version", "")).strip()
    if not version:
        raise MappingError("у отображения нет версии")
    entries: list[MappingEntry] = []
    seen: set[str] = set()
    for item in raw.get("entries") or []:
        symbol = str(item.get("symbol", "")).strip()
        signal = str(item.get("signal", "")).strip()
        kind = str(item.get("kind", "")).strip()
        effect = str(item.get("risk_effect", "")).strip()
        if not symbol or not signal or kind not in {"AUTH", "HELO", "REPUTATION", "SPAM", "CONTEXT"}:
            raise MappingError("запись отображения неполная")
        if effect not in {"INCREASE", "NONE"}:
            raise MappingError("risk_effect должен быть INCREASE или NONE")
        if symbol in seen:
            raise MappingError("символ указан дважды")
        seen.add(symbol)
        entries.append(MappingEntry(symbol, signal, kind, effect))
    return SymbolMapping(version, tuple(entries))


@lru_cache(maxsize=1)
def default_mapping() -> SymbolMapping:
    return parse_mapping(yaml.safe_load(DATA.read_text(encoding="utf-8")))


@dataclass
class Signal:
    code: str
    kind: str
    risk_effect: str
    symbol: str = ""
    score: float = 0.0


@dataclass
class MappedSignals:
    mapping_version: str
    signals: list[Signal] = field(default_factory=list)
    #: Символы без отображения: сохранены как свидетельство, на риск не влияют.
    unmapped: list[str] = field(default_factory=list)

    def codes(self, *, risk_only: bool = False) -> list[str]:
        out: list[str] = []
        for signal in self.signals:
            if risk_only and signal.risk_effect != "INCREASE":
                continue
            if signal.code not in out:
                out.append(signal.code)
        return out


#: Символы с нулевым весом и служебные, которые не стоит считать «неизвестными» в отчётах.
_NOISE_PREFIXES = (
    "MIME_",
    "RCVD_",
    "RCPT_",
    "FROM_",
    "TO_",
    "MISSING_",
    "SINGLE_",
    "ONCE_",
    "DATE_",
    "SUBJECT_",
)


def apply_mapping(
    evidence: RspamdEvidence, policy: SpamPolicy, mapping: SymbolMapping | None = None
) -> MappedSignals:
    mapping = mapping or default_mapping()
    out = MappedSignals(mapping.version)
    for symbol in evidence.symbols:
        entry = mapping.lookup(symbol.name)
        if entry is None:
            out.unmapped.append(symbol.name)
            continue
        out.signals.append(Signal(entry.signal, entry.kind, entry.risk_effect, symbol.name, symbol.score))
    if evidence.score >= policy.thresholds.spam:
        out.signals.append(Signal(SPAM_HIGH_SCORE, "SPAM", "INCREASE", "", evidence.score))
    return out
