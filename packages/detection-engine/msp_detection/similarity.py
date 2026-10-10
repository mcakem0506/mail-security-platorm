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
    [
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "live.com",
        "sharepoint.com",
        "onedrive.com",
        "windows.net",
        "azure.com",
        "google.com",
        "gmail.com",
        "googlemail.com",
        "docs.google.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "aws.amazon.com",
        "paypal.com",
        "dropbox.com",
        "box.com",
        "adobe.com",
        "docusign.com",
        "docusign.net",
        "zoom.us",
        "slack.com",
        "atlassian.com",
        "github.com",
        "gitlab.com",
        "linkedin.com",
        "facebook.com",
        "instagram.com",
        "whatsapp.com",
        "telegram.org",
        "sberbank.ru",
        "vtb.ru",
        "alfabank.ru",
        "tinkoff.ru",
        "gosuslugi.ru",
        "nalog.ru",
        "mail.ru",
        "yandex.ru",
        "vk.com",
        "ozon.ru",
        "wildberries.ru",
        "dhl.com",
        "fedex.com",
        "ups.com",
        "pochta.ru",
        "cdek.ru",
        "1c.ru",
        "kaspersky.com",
        "kaspersky.ru",
        "bitrix24.ru",
    ]
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
    """True when the string as a whole uses more than one script.

    For a *domain* this is the right test: a single label mixing scripts is what punycode
    spoofing looks like. For free text such as a display name it is far too broad — see
    :func:`has_mixed_script_token`.
    """
    return len(script_names(text)) > 1


#: Words split on whitespace and the punctuation that separates name parts.
_WORD_SPLIT_RE = re.compile(r"[\s.,\-_/\\()\[\]«»\"']+")


def has_mixed_script_token(text: str) -> bool:
    """True when a *single word* mixes scripts.

    This is the distinction that matters for display names. ``Отдел продаж Partner`` mixes
    Cyrillic and Latin, but each word is written in one script — an ordinary Russian company name
    containing a Latin brand. ``Аpple`` mixes them *inside one word*, with a Cyrillic А standing
    in for the Latin one, and nothing legitimate is written that way.

    Judging the whole string instead flags a large share of normal Russian corporate mail, which
    is how a detection rule teaches people to ignore it.
    """
    return any(len(word) > 1 and len(script_names(word)) > 1 for word in _WORD_SPLIT_RE.split(text or ""))


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

#: Labels of this length or shorter are handled by the short-label detector below instead of by
#: edit distance. Four and five character labels are the problem case: "corp" is one edit away
#: from card, core, cork, corn, cord, carp and corps, all of which are ordinary words that
#: appear in legitimate mail.
MAX_SHORT_LABEL = 5

#: Characters a variant may be built from. Deliberately not the whole alphabet: a domain label
#: is letters, digits and hyphen (RFC 1123), and generating anything else would produce variants
#: that cannot be registered.
_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"

#: The four transforms ТЗ 1.0.4 §3 names, in the order they are tried.
SHORT_TRANSFORMS = ("insertion", "deletion", "substitution", "transposition")


def _insertions(label: str) -> set[str]:
    return {label[:i] + ch + label[i:] for i in range(len(label) + 1) for ch in _LABEL_ALPHABET}


def _deletions(label: str) -> set[str]:
    return {label[:i] + label[i + 1 :] for i in range(len(label))}


def _substitutions(label: str) -> set[str]:
    return {
        label[:i] + ch + label[i + 1 :] for i in range(len(label)) for ch in _LABEL_ALPHABET if ch != label[i]
    }


def _transpositions(label: str) -> set[str]:
    """Adjacent transpositions only: "corp" -> "ocrp", "crop", "copr"."""
    return {
        label[:i] + label[i + 1] + label[i] + label[i + 2 :]
        for i in range(len(label) - 1)
        if label[i] != label[i + 1]
    }


@lru_cache(maxsize=4096)
def short_label_variants(label: str) -> dict[str, str]:
    """Every single-edit variant of a short label, mapped to the transform that produced it.

    Pure and offline by construction: no DNS, no WHOIS, no crawling (ТЗ 1.0.4 §4). The result is
    a dictionary rather than a set because the transform is part of the evidence an analyst
    reads — "letter doubled" and "two letters swapped" are different stories about intent.

    A variant reachable by more than one transform keeps the first in ``SHORT_TRANSFORMS``
    order, so the classification is stable rather than dependent on set iteration.
    """
    label = (label or "").lower()
    if not label or len(label) > MAX_SHORT_LABEL:
        return {}

    produced = {
        "insertion": _insertions(label),
        "deletion": _deletions(label),
        "substitution": _substitutions(label),
        "transposition": _transpositions(label),
    }
    variants: dict[str, str] = {}
    for transform in SHORT_TRANSFORMS:
        for variant in produced[transform]:
            # A label cannot start or end with a hyphen, and the label itself is not a variant.
            if variant == label or variant.startswith("-") or variant.endswith("-"):
                continue
            variants.setdefault(variant, transform)
    return variants


def compare_short_labels(candidate: str, target: str) -> LookalikeMatch | None:
    """Match a candidate label against a short protected label, one edit away.

    Separate from :func:`compare_labels` on purpose. Edit distance on a short label produces far
    too many matches to score on its own, so this detector returns a match with a **low**
    confidence and the caller is required to find corroborating evidence before the signal
    counts (ТЗ 1.0.4 §3). The match itself is a statement that the shape is suspicious, not that
    the message is.
    """
    cand = (candidate or "").lower()
    targ = (target or "").lower()
    if not cand or not targ or cand == targ or len(targ) > MAX_SHORT_LABEL:
        return None
    # Skeletons, so that a homoglyph or a visual substitution inside the variant still matches;
    # compare_labels already catches a pure skeleton collision, which is a stronger signal.
    sk_c, sk_t = skeleton(cand), skeleton(targ)
    if sk_c == sk_t:
        return None
    transform = short_label_variants(sk_t).get(sk_c)
    if transform is None:
        return None
    return LookalikeMatch(
        target,
        f"short_{transform}",
        1,
        0.35,
        f"одна правка ({transform}) от короткой метки «{targ}»",
    )


def find_short_lookalike(
    registrable: str, label: str, targets: dict[str, str], target_labels: dict[str, str]
) -> LookalikeMatch | None:
    """The short-label counterpart of :func:`find_lookalike`.

    Returns ``None`` for an exact protected domain, and for anything :func:`find_lookalike`
    would already have caught — this detector exists for the gap below that threshold
    (GAP-001), not to duplicate it.
    """
    if not label or registrable in targets:
        return None
    best: LookalikeMatch | None = None
    for t_label, t_reg in target_labels.items():
        match = compare_short_labels(label, t_label)
        if match is None:
            continue
        match = LookalikeMatch(t_reg, match.technique, match.distance, match.confidence, match.detail)
        if best is None or match.confidence > best.confidence:
            best = match
    return best


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


def contains_domain(host: str, domain: str) -> bool:
    """True when ``domain`` appears inside ``host`` as a run of whole labels.

    A plain substring test is not enough and was a defect: ``corp.example`` is a substring of
    ``ccorp.example``, so a different company with a longer name was reported as pushing our
    domain out of the registrable part — an explanation that sends an analyst looking for
    something that is not there.

    Each label is compared through :func:`skeleton`, so ``co-rp.example.evil.test`` and
    ``c0rp.example.evil.test`` still match, but the comparison happens **per label**: calling
    ``skeleton`` on the whole host first would be no better than a substring test, because the
    skeleton drops the dots that carry the label boundaries.
    """
    if not host or not domain:
        return False
    host_labels = [skeleton(part) for part in host.split(".") if part]
    domain_labels = [skeleton(part) for part in domain.split(".") if part]
    if not domain_labels or len(domain_labels) > len(host_labels):
        return False
    return any(
        host_labels[i : i + len(domain_labels)] == domain_labels
        for i in range(len(host_labels) - len(domain_labels) + 1)
    )


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
    # subdomain deception: our domain appears as whole labels but is not the registrable one,
    # as in corp.example.attacker.test or mail.corp.example.evil.ru.
    for t_reg in targets:
        sk_t = skeleton(t_reg)
        if len(sk_t) >= 6 and contains_domain(host, t_reg) and skeleton(registrable) != sk_t:
            return LookalikeMatch(
                t_reg, "subdomain_deception", 0, 0.8, f"'{t_reg}' appears outside the registrable domain"
            )

    # Label merge: the whole corporate domain squeezed into a single label, with the dot
    # dropped or replaced — corpexample.example, corp-example.example, corp--example.example.
    # A separate technique from subdomain deception, and named separately: the two look alike
    # in a substring test and mean different things to whoever reads the verdict.
    host_labels = [part for part in host.split(".") if part]
    for t_reg in targets:
        merged = skeleton(t_reg)
        if len(merged) < 6 or skeleton(registrable) == merged:
            continue
        for part in host_labels:
            sk_part = skeleton(part)
            if sk_part == merged:
                return LookalikeMatch(
                    t_reg, "label_merge", 0, 0.85, f"'{t_reg}' записан одной меткой «{part}»"
                )
            # One edit on top of the merge — corp-exampl.example. Kept at a single edit on
            # purpose: the merge is already the strong part of the signal, and allowing the
            # usual distance for an eleven-character name would widen the false-positive
            # surface for the sake of a rarer variant.
            if len(sk_part) >= 6 and damerau_levenshtein(sk_part, merged, 1) == 1:
                return LookalikeMatch(
                    t_reg,
                    "label_merge",
                    1,
                    0.75,
                    f"'{t_reg}' записан одной меткой «{part}» с одной правкой",
                )
    return None


def common_service_targets() -> tuple[dict[str, str], dict[str, str]]:
    targets = dict.fromkeys(_COMMON_SERVICE_DOMAINS, "known_service")
    labels: dict[str, str] = {}
    for d in _COMMON_SERVICE_DOMAINS:
        labels.setdefault(d.split(".")[0], d)
    return targets, labels


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-zа-яё0-9])(?=[A-ZА-ЯЁ])")


def display_name_words(name: str) -> list[str]:
    """Split a display name into words, including across camel-case boundaries.

    The camel-case split is what keeps "CorpSecurity" distinguishable from "Corps": the capital
    letter is the boundary, and lower-casing before splitting throws that information away.
    """
    if not name:
        return []
    spaced = _CAMEL_BOUNDARY.sub(" ", name)
    return [word for word in re.split(r"[^0-9A-Za-zА-Яа-яЁё]+", spaced) if word]


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


#: Words that make a display name a role rather than a person, across the languages this
#: platform sees. The list is short on purpose: it disambiguates, while the structural test
#: below does the actual work.
_ROLE_WORDS = frozenset(
    {
        "отдел",
        "служба",
        "группа",
        "департамент",
        "управление",
        "сектор",
        "дирекция",
        "бухгалтерия",
        "канцелярия",
        "склад",
        "логистика",
        "поддержка",
        "техподдержка",
        "администрация",
        "секретариат",
        "приемная",
        "приёмная",
        "ресепшн",
        "офис",
        "team",
        "support",
        "sales",
        "service",
        "helpdesk",
        "billing",
        "accounting",
        "finance",
        "hr",
        "admin",
        "office",
        "desk",
        "department",
        "noreply",
        "no-reply",
        "info",
        "contact",
        "mail",
        "notifications",
        "notification",
        "system",
    }
)


def is_personal_name(name: str) -> bool:
    """Whether a display name looks like a person rather than a role.

    This decides whether a name is worth comparing against the directory at all. Generic role
    names — "Бухгалтерия", "Отдел продаж", "Support Team" — are shared by every organisation, so
    matching them flags a contractor's accounting department as impersonating ours.

    The test is structural rather than a list lookup: a personal name is two or more capitalised
    word-tokens, none of which is a role word. A list of names would be incomplete in a
    different way in every language; the shape generalises.

    Deliberately conservative in both directions:

    * a single token ("Иван", "Support") is not treated as personal — too little to go on, and
      the cost of missing an impersonation here is lower than the cost of flagging every
      contractor's shared mailbox;
    * a name containing a role word is never personal, even with two tokens ("Отдел продаж").
    """
    text = (name or "").strip()
    if not text or "@" in text:
        return False
    tokens = [t for t in re.split(r"[\s.,]+", text) if len(t) > 1]
    if len(tokens) < 2:
        return False
    lowered = {t.lower().strip("«»\"'()") for t in tokens}
    if lowered & _ROLE_WORDS:
        return False
    # Every token should read as a word, not a code or an address fragment.
    return all(re.match(r"^[^\W\d_]+$", token.strip("«»\"'()-"), re.UNICODE) for token in tokens)
