"""Lookalike detection: homoglyphs, typosquatting, display-name similarity (ТЗ 9.3, 11.3)."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

# Confusable mapping (subset of Unicode confusables relevant to email/domain abuse).
_CONFUSABLES: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ь": "b", "г": "r", "т": "t", "м": "m", "к": "k",
    "н": "h", "в": "b", "З": "3", "з": "3", "ч": "4",
    # Greek -> Latin
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ζ": "z", "η": "n", "μ": "u", "σ": "o", "γ": "y", "θ": "0", "φ": "o",
    # Armenian / other
    "օ": "o", "ո": "n", "ս": "u", "գ": "q", "զ": "q", "ա": "w", "ե": "e", "ր": "r",
    # Latin with diacritics / extended
    "ạ": "a", "ą": "a", "ä": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "å": "a", "ā": "a",
    "ẹ": "e", "é": "e", "è": "e", "ê": "e", "ë": "e", "ē": "e", "ę": "e",
    "ị": "i", "í": "i", "ì": "i", "î": "i", "ï": "i", "ī": "i", "ı": "i",
    "ọ": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o", "ō": "o",
    "ụ": "u", "ú": "u", "ù": "u", "û": "u", "ü": "u", "ū": "u",
    "ç": "c", "ć": "c", "č": "c", "ñ": "n", "ń": "n", "ş": "s", "ś": "s", "š": "s",
    "ţ": "t", "ť": "t", "ý": "y", "ÿ": "y", "ž": "z", "ź": "z", "ż": "z", "ğ": "g", "ł": "l",
    "đ": "d", "ð": "d", "þ": "b", "ß": "b",
    # ASCII visual confusions folded to a canonical skeleton
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "8": "b", "9": "g",
    "|": "l", "!": "i", "$": "s", "@": "a", "vv": "w", "rn": "m",
}  # fmt: skip

_MULTI = {k: v for k, v in _CONFUSABLES.items() if len(k) > 1}
_SINGLE = {k: v for k, v in _CONFUSABLES.items() if len(k) == 1}

_SCRIPT_RANGES: list[tuple[int, int, str]] = [
    (0x0041, 0x024F, "Latin"),
    (0x0370, 0x03FF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x3040, 0x30FF, "Japanese"),
    (0x4E00, 0x9FFF, "Han"),
]

_COMMON_SERVICE_DOMAINS: frozenset[str] = frozenset(
    """
microsoft.com microsoftonline.com office.com office365.com outlook.com live.com sharepoint.com
onedrive.com windows.net azure.com google.com gmail.com googlemail.com docs.google.com
apple.com icloud.com amazon.com aws.amazon.com paypal.com dropbox.com box.com adobe.com
docusign.com docusign.net zoom.us slack.com atlassian.com github.com gitlab.com linkedin.com
facebook.com instagram.com whatsapp.com telegram.org sberbank.ru vtb.ru alfabank.ru tinkoff.ru
gosuslugi.ru nalog.ru mail.ru yandex.ru vk.com ozon.ru wildberries.ru dhl.com fedex.com ups.com
pochta.ru cdek.ru 1c.ru kaspersky.com kaspersky.ru bitrix24.ru
""".split()
)


def script_names(text: str) -> set[str]:
    out: set[str] = set()
    for ch in text:
        cp = ord(ch)
        if ch.isdigit() or not ch.isalpha():
            continue
        for lo, hi, name in _SCRIPT_RANGES:
            if lo <= cp <= hi:
                out.add(name)
                break
        else:
            out.add("Other")
    return out


def is_mixed_script(text: str) -> bool:
    return len(script_names(text)) > 1


@lru_cache(maxsize=16384)
def skeleton(text: str) -> str:
    """Fold a string to a confusable skeleton: 'аррӏе' and 'app1e' both -> 'apple'-ish."""
    text = unicodedata.normalize("NFKD", (text or "").lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    for src, dst in _MULTI.items():
        text = text.replace(src, dst)
    text = "".join(_SINGLE.get(ch, ch) for ch in text)
    return re.sub(r"[\s\-_.]+", "", text)


def has_homoglyph(text: str) -> bool:
    """True when non-ASCII characters fold into ASCII lookalikes."""
    return any(ch in _SINGLE and not ch.isascii() for ch in (text or "").lower())


def homoglyph_chars(text: str) -> list[str]:
    return sorted({ch for ch in (text or "").lower() if ch in _SINGLE and not ch.isascii()})


def levenshtein(a: str, b: str, max_distance: int = 4) -> int:
    """Bounded Levenshtein distance; returns max_distance+1 when the bound is exceeded."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            best = min(best, cur[j])
        if best > max_distance:
            return max_distance + 1
        prev = cur
    return prev[-1]


def damerau_levenshtein(a: str, b: str, max_distance: int = 4) -> int:
    """Distance counting adjacent transpositions as one edit (typosquatting: 'exmaple')."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
        if min(d[i]) > max_distance:
            return max_distance + 1
    return d[la][lb]


_MIN_TYPOSQUAT_LENGTH = 6


def _allowed_distance(length: int) -> int:
    if length <= 5:
        return 1
    if length <= 10:
        return 2
    return 3


@dataclass(frozen=True)
class LookalikeMatch:
    target: str
    technique: str  # homoglyph|typosquat|insertion|separator|subdomain_deception|containment
    distance: int
    confidence: float
    detail: str = ""


def compare_labels(candidate: str, target: str) -> LookalikeMatch | None:
    """Compare two registrable-domain labels (e.g. 'micr0soft' vs 'microsoft')."""
    cand = (candidate or "").lower()
    targ = (target or "").lower()
    if not cand or not targ or cand == targ:
        return None
    sk_c, sk_t = skeleton(cand), skeleton(targ)
    if sk_c == sk_t:
        technique = "homoglyph" if has_homoglyph(cand) else "visual_substitution"
        return LookalikeMatch(target, technique, 0, 0.95, f"skeleton match '{sk_t}'")
    # target embedded with extra tokens: "microsoft-login", "secure-sberbank"
    if len(targ) >= 5 and (sk_t in sk_c) and len(sk_c) <= len(sk_t) + 12:
        return LookalikeMatch(target, "containment", len(sk_c) - len(sk_t), 0.7, f"contains '{targ}'")
    # Short labels are excluded from edit-distance matching: one edit on a 4-5 character name
    # ("mail" vs "gmail") is ordinary similarity, not evidence of typosquatting.
    if len(sk_t) < _MIN_TYPOSQUAT_LENGTH:
        return None
    limit = _allowed_distance(len(sk_t))
    dist = damerau_levenshtein(sk_c, sk_t, limit)
    if 0 < dist <= limit:
        confidence = 0.85 if dist == 1 else 0.7 if dist == 2 else 0.55
        return LookalikeMatch(target, "typosquat", dist, confidence, f"edit distance {dist} from '{targ}'")
    return None


def find_lookalike(
    host: str, registrable: str, label: str, targets: dict[str, str], target_labels: dict[str, str]
) -> LookalikeMatch | None:
    """Find the best lookalike relation between a host and protected/known domains.

    ``targets`` maps registrable domain -> human label (e.g. 'corp.example' -> 'organization').
    ``target_labels`` maps the eTLD+1 label -> registrable domain.
    """
    host = (host or "").lower()
    if not host:
        return None
    if registrable in targets:
        return None  # exact corporate/known domain: not a lookalike
    best: LookalikeMatch | None = None
    for t_label, t_reg in target_labels.items():
        m = compare_labels(label, t_label)
        if m is not None:
            m = LookalikeMatch(t_reg, m.technique, m.distance, m.confidence, m.detail)
            if best is None or m.confidence > best.confidence:
                best = m
    if best is not None:
        return best
    # subdomain deception: corp.example.evil.ru / corp-example.evil.ru
    sk_host = skeleton(host)
    for t_reg in targets:
        sk_t = skeleton(t_reg)
        if len(sk_t) >= 6 and sk_t in sk_host and skeleton(registrable) != sk_t:
            return LookalikeMatch(
                t_reg, "subdomain_deception", 0, 0.8, f"'{t_reg}' appears outside the registrable domain"
            )
    return None


def common_service_targets() -> tuple[dict[str, str], dict[str, str]]:
    targets = {d: "known_service" for d in _COMMON_SERVICE_DOMAINS}
    labels: dict[str, str] = {}
    for d in _COMMON_SERVICE_DOMAINS:
        labels.setdefault(d.split(".")[0], d)
    return targets, labels


def normalize_person_name(name: str) -> str:
    """Normalise a display name for impersonation comparison."""
    name = unicodedata.normalize("NFKC", (name or "")).lower()
    name = re.sub(r"[\"'`´]", "", name)
    name = re.sub(r"\s*\(.*?\)\s*", " ", name)
    name = re.sub(r"<[^>]*>", " ", name)
    name = re.sub(r"[^\w\s.\-]", " ", name, flags=re.UNICODE)
    return re.sub(r"\s+", " ", name).strip()


def name_tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[\s.\-_]+", normalize_person_name(name)) if len(t) > 1]


def name_similarity(a: str, b: str) -> float:
    """0..1 similarity between two person names, resistant to token order and homoglyphs."""
    ta, tb = name_tokens(a), name_tokens(b)
    if not ta or not tb:
        return 0.0
    sa = {skeleton(t) for t in ta}
    sb = {skeleton(t) for t in tb}
    if sa == sb:
        return 1.0
    inter = len(sa & sb)
    if inter:
        return min(1.0, 0.55 + 0.45 * inter / max(len(sa), len(sb)))
    joined_a, joined_b = "".join(sorted(sa)), "".join(sorted(sb))
    dist = damerau_levenshtein(joined_a, joined_b, 3)
    if dist <= 2 and len(joined_b) >= 6:
        return 0.75
    return 0.0
