"""Proving that a message really passed through the infrastructure it claims (ТЗ 1.0.1 §4.3, §4.4).

Listing ``ksmg`` as a trusted gateway is not enough. Headers are free text that any sender can
write, so ``X-KSMG-Antivirus-Status: Clean`` in a message that never went near the organisation's
KSMG is a forgery — and a common one, because it makes a message look pre-screened.

This module answers one question per message: **did the delivery chain actually traverse a hop we
operate?** Only if it did are that hop's headers, and the ``Authentication-Results`` written by its
authentication server, treated as evidence.

Two asymmetries are deliberate and are not configurable:

* an unproven *negative* verdict is still surfaced to the analyst, because forged headers are
  themselves a signal — it simply does not feed the risk score as a gateway detection;
* an unproven *clean* verdict is worth nothing either way, since no gateway verdict lowers risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from msp_contracts import TrustedMailHop, TrustState

from .received import ReceivedHop, parse_received


def _host_matches(candidate: str, expected: str) -> bool:
    """Hostname comparison that accepts a subdomain of the configured host.

    ``ksmg-01.corp.example`` satisfies a hop configured as ``corp.example``, but
    ``ksmg-01.corp.example.attacker.tld`` does not: the suffix must fall on a label boundary.
    """
    candidate = (candidate or "").strip().rstrip(".").lower()
    expected = (expected or "").strip().rstrip(".").lower()
    if not candidate or not expected:
        return False
    return candidate == expected or candidate.endswith("." + expected)


def _ip_matches(ip: IPv4Address | IPv6Address | None, hop: TrustedMailHop) -> bool:
    if ip is None:
        return False
    return any(ip in network for network in hop.networks())


def _source_names(received: ReceivedHop) -> tuple[str, str]:
    """Both names the receiving MTA recorded for the sending host.

    They are checked independently rather than as ``rdns or helo``: a receiver that logs a short
    reverse-DNS name (``ksmg-01``) alongside a fully qualified HELO (``ksmg-01.corp.example``) is
    completely ordinary, and preferring one would discard the only name that matches.
    """
    return received.rdns, received.helo


def _source_matches(received: ReceivedHop, hop: TrustedMailHop) -> str:
    """The matching source name for ``hop``, or an empty string when neither matches."""
    for candidate in _source_names(received):
        if candidate and hop.hostname and _host_matches(candidate, hop.hostname):
            return candidate
    return ""


@dataclass
class HopMatch:
    """Evidence that one configured hop appears in this message's chain."""

    hop: TrustedMailHop
    #: Index of the ``Received`` header the match was found in.
    received_index: int
    matched_by: str  # hostname_by|hostname_from|ip_from
    detail: str = ""

    @property
    def chain_position(self) -> int:
        """Where the hop itself sits in the chain.

        A hop appears in two headers: the one it wrote (where it is the ``by`` host) and the one
        the *next* machine wrote (where it is the ``from`` host). Both prove the message passed
        it, but only the first gives its own position directly — so a ``from`` match at index
        *i* means the hop wrote header *i + 1*. Without this normalisation the same hop would
        report two different positions depending on which clause happened to match first, and a
        configured ``position_in_chain`` could never be checked reliably.
        """
        return self.received_index if self.matched_by == "hostname_by" else self.received_index + 1


@dataclass
class ChainVerification:
    """The outcome of checking one message's chain against the configured topology."""

    matches: list[HopMatch] = field(default_factory=list)
    hops: list[ReceivedHop] = field(default_factory=list)
    #: Hops that were configured but not found in this chain.
    missing_hops: list[str] = field(default_factory=list)
    #: A hop that was found, but not where the topology says it belongs.
    position_mismatches: list[str] = field(default_factory=list)
    chain_present: bool = False
    #: Every enabled hop the deployment declared, whether or not it appears in this chain.
    known_hops: list[TrustedMailHop] = field(default_factory=list)

    def matched(self, provider_id: str) -> HopMatch | None:
        for match in self.matches:
            if match.hop.provider_id == provider_id or match.hop.id == provider_id:
                return match
        return None

    def verified_provider_ids(self) -> set[str]:
        return {m.hop.provider_id for m in self.matches if m.hop.provider_id}

    def trusted_authserv_ids(self) -> set[str]:
        """Authentication servers whose results may be believed *for this message*.

        Only hops the chain actually proved contribute: an allowlist entry belonging to a hop
        this message never passed is exactly the case §4.4 is about.
        """
        out: set[str] = set()
        for match in self.matches:
            out.update(a.strip().lower() for a in match.hop.authserv_ids if a.strip())
        return out

    def configured_authserv_ids(self) -> set[str]:
        """Every authentication server the organisation declared, verified or not.

        This distinguishes "the deployment has not described its topology yet" from "the
        topology is known and this message does not fit it".
        """
        out: set[str] = set()
        for hop in self.known_hops:
            out.update(a.strip().lower() for a in hop.authserv_ids if a.strip())
        return out


def _corroborated(match: HopMatch, chain: list[ReceivedHop]) -> bool:
    """Whether a hop's own header is confirmed by the machine that received from it.

    This is what stops a forged chain. An attacker can write any number of ``Received`` headers,
    including one whose ``by`` clause names the organisation's gateway — so a ``by`` match on its
    own proves nothing. What the attacker cannot write is the header the *next machine inwards*
    added, because that machine belongs to the organisation. So a self-claim is believed only
    when the hop above it independently records receiving the message from the same host or from
    an address inside its networks.

    A match found via ``from`` or by address needs no corroboration: it already *is* the next
    machine's statement. Neither does a hop at the top of the chain, which was written by the
    last system to handle the message — normally the mailbox server itself.
    """
    if match.matched_by != "hostname_by":
        return True
    above_index = match.received_index - 1
    if above_index < 0:
        return True
    above = next((hop for hop in chain if hop.index == above_index), None)
    if above is None:
        return True
    if _source_matches(above, match.hop):
        return True
    return _ip_matches(above.ip, match.hop)


def verify_chain(received_headers: list[str], hops: list[TrustedMailHop]) -> ChainVerification:
    """Check which configured hops this message demonstrably passed through.

    A hop is considered proved when the chain shows either

    * a ``from`` clause naming it, or a source address inside its networks — the next machine
      inwards recorded receiving the message from it. This is the strong form: that header was
      written by a different system, one the organisation operates; or
    * a ``by`` clause naming it — the hop's own statement about itself — **and** corroboration
      from the hop above, since a self-claim alone can be forged (see :func:`_corroborated`).
    """
    chain = parse_received(received_headers)
    enabled = [hop for hop in hops if hop.enabled]
    verification = ChainVerification(hops=chain, chain_present=bool(chain), known_hops=enabled)

    for configured in enabled:
        candidates: list[HopMatch] = []
        for received in chain:
            if configured.hostname and _host_matches(received.by_host, configured.hostname):
                candidates.append(HopMatch(configured, received.index, "hostname_by", received.by_host))
            elif source_name := _source_matches(received, configured):
                candidates.append(HopMatch(configured, received.index, "hostname_from", source_name))
            elif _ip_matches(received.ip, configured):
                candidates.append(HopMatch(configured, received.index, "ip_from", received.ip_text))
        if not candidates:
            if configured.hostname or configured.ip_networks:
                verification.missing_hops.append(configured.hostname or configured.id or "unnamed hop")
            continue

        corroborated = [c for c in candidates if _corroborated(c, chain)]
        if not corroborated:
            # The hop appears only as its own unconfirmed claim. Reported as a topology mismatch
            # rather than silently ignored: a header naming our gateway on a path that does not
            # include it is the signature of a forged chain.
            claim = candidates[0]
            verification.position_mismatches.append(
                f"{configured.hostname or configured.id}: заявлено в Received (hop "
                f"{claim.received_index}), но соседний узел этого не подтверждает"
            )
            continue

        # Prefer the hop's own header when it is corroborated: its position needs no inference.
        found = next((c for c in corroborated if c.matched_by == "hostname_by"), corroborated[0])
        if configured.position_in_chain is not None and found.chain_position != configured.position_in_chain:
            # The hop is in the chain but not where the topology puts it. That can be a
            # legitimate routing change, so it is reported rather than treated as forgery —
            # but it is not proof of the expected path either.
            verification.position_mismatches.append(
                f"{configured.hostname or configured.id}: expected position "
                f"{configured.position_in_chain}, found {found.chain_position}"
            )
            continue
        verification.matches.append(found)
    return verification


@dataclass
class HeaderTrustDecision:
    trusted: bool
    state: TrustState
    reason: str


def decide_header_trust(
    provider_id: str,
    *,
    verification: ChainVerification,
    registered: bool,
) -> HeaderTrustDecision:
    """Decide whether headers attributed to ``provider_id`` may be believed.

    ``registered`` means the organisation declared it runs this gateway at all. Without that,
    the headers are an unknown third party's claim and are never evidence.
    """
    if not registered:
        return HeaderTrustDecision(
            False,
            TrustState.UNKNOWN_GATEWAY,
            "организация не использует этот шлюз: заголовки может добавить любой отправитель",
        )
    if not verification.chain_present:
        return HeaderTrustDecision(
            False,
            TrustState.UNVERIFIED_CHAIN,
            "в письме нет цепочки Received, подтвердить прохождение шлюза невозможно",
        )
    match = verification.matched(provider_id)
    if match is None:
        mismatch = next(
            (m for m in verification.position_mismatches if provider_id in m or m.startswith(provider_id)),
            "",
        )
        if mismatch:
            return HeaderTrustDecision(
                False, TrustState.TOPOLOGY_MISMATCH, f"шлюз найден не на своём месте в цепочке: {mismatch}"
            )
        return HeaderTrustDecision(
            False,
            TrustState.UNVERIFIED_CHAIN,
            "цепочка доставки не подтверждает прохождение через зарегистрированный шлюз",
        )
    return HeaderTrustDecision(
        True,
        TrustState.TRUSTED,
        f"подтверждено в цепочке Received (hop {match.received_index}, {match.matched_by}: {match.detail})",
    )


@dataclass
class AuthResultsTrust:
    """Which ``Authentication-Results`` headers may be read (ТЗ 1.0.1 §4.4)."""

    trusted_headers: list[str] = field(default_factory=list)
    untrusted_headers: list[str] = field(default_factory=list)
    #: A header claiming to come from *our own* authentication server, asserting a pass, on a
    #: message whose chain does not show it passing that server. That is impersonation of the
    #: organisation's infrastructure, not merely an unrecognised third party.
    forged_pass_claims: list[str] = field(default_factory=list)
    allowlist: set[str] = field(default_factory=set)

    @property
    def tampering_suspected(self) -> bool:
        return bool(self.forged_pass_claims)


def _authserv_id(header: str) -> str:
    """The authentication server that wrote this header: the first token before the ';'."""
    head = header.split(";", 1)[0].strip()
    return head.split()[0].strip().lower() if head else ""


_PASS_TOKENS = ("spf=pass", "dkim=pass", "dmarc=pass", "compauth=pass")


def filter_authentication_results(
    headers: list[str],
    *,
    verification: ChainVerification,
    extra_allowlist: tuple[str, ...] = (),
) -> AuthResultsTrust:
    """Keep only the ``Authentication-Results`` written by a verified authentication server.

    A message can carry any number of these headers, and an attacker can prepend one saying
    everything passed. Only the ones whose ``authserv-id`` belongs to a hop the chain proves the
    message traversed are handed on to the authentication interpreter.

    When the deployment has declared no authentication servers at all, every header is passed
    through: refusing to read authentication results before the topology has been described would
    silently weaken detection rather than strengthen it, and the missing allowlist is reported
    separately as a readiness blocker. That fallback applies only to a deployment with *no*
    allowlist — once one exists, a message that does not match it is not covered by it, even
    though the allowlist itself was configured for other paths.

    Two kinds of unusable header are distinguished, because conflating them produces a flood of
    false positives on ordinary mail:

    *untrusted*
        The ``authserv-id`` belongs to nobody the organisation declared — a forwarding service, a
        mailing list, a partner's gateway. Its results are not read, and that is all: legitimate
        forwarded mail looks exactly like this.
    *forged*
        The ``authserv-id`` names one of the organisation's **own** declared servers, asserts a
        pass, and the chain does not show the message passing that server. Nothing legitimate has
        that shape — it is an attempt to borrow the organisation's own authentication verdict —
        so this, and only this, raises the tampering signal of ТЗ 1.0.1 §4.4.
    """
    extra = {entry.strip().lower() for entry in extra_allowlist if entry.strip()}
    allowlist = verification.trusted_authserv_ids() | extra
    configured = verification.configured_authserv_ids() | extra
    trust = AuthResultsTrust(allowlist=allowlist)
    if not configured:
        trust.trusted_headers = list(headers)
        return trust

    for header in headers:
        authserv = _authserv_id(header)
        if _matches(authserv, allowlist):
            trust.trusted_headers.append(header)
            continue
        trust.untrusted_headers.append(header)
        claims_pass = any(token in header.lower().replace(" ", "") for token in _PASS_TOKENS)
        if claims_pass and _matches(authserv, configured):
            trust.forged_pass_claims.append(header[:300])
    return trust


def _matches(authserv: str, allowlist: set[str]) -> bool:
    """Whether an ``authserv-id`` is one of the listed servers, or a host beneath one."""
    if not authserv:
        return False
    return any(authserv == entry or authserv.endswith("." + entry) for entry in allowlist)
