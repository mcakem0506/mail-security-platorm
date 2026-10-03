"""Containment must be label- and word-aligned, not substring (ТЗ 1.0.4 §3).

Two defects of the same shape, both found by the short-domain corpus:

* ``find_lookalike`` reported ``ccorp.example`` as **subdomain deception** — "corp.example
  appears outside the registrable domain" — because the characters of ``corp.example`` happen to
  sit inside ``ccorp.example``. An analyst reading that explanation would look for
  ``corp.example.attacker.test`` and find nothing of the sort.
* ``display_name_claims_organization`` fired for a real vendor called "Corps Security", because
  ``corp`` is inside ``corps``.

The verdict in the first case was arguably right for the wrong reason, and in the second it was
simply wrong. Both matter equally here: the platform promises that the reason behind a verdict is
the real one, so a true verdict with a false explanation is still a defect.
"""

from __future__ import annotations

from msp_detection.context import AnalysisContext
from msp_detection.similarity import find_lookalike

CORPORATE = {"corp.example": "organization"}
CORPORATE_LABELS = {"corp": "corp.example"}


def _match(host: str, registrable: str, label: str):  # type: ignore[no-untyped-def]
    return find_lookalike(host, registrable, label, CORPORATE, CORPORATE_LABELS)


class TestSubdomainDeceptionIsLabelAligned:
    def test_a_longer_label_is_not_subdomain_deception(self) -> None:
        """``ccorp.example`` may well be a lookalike, but not by this technique."""
        match = _match("mx.ccorp.example", "ccorp.example", "ccorp")
        if match is not None:
            assert match.technique != "subdomain_deception", match.detail

    def test_an_unrelated_longer_name_is_not_matched_at_all(self) -> None:
        """A different company whose name contains ours is a different company."""
        match = _match("mail.supercorp.example", "supercorp.example", "supercorp")
        assert match is None or match.technique != "subdomain_deception"

    def test_real_subdomain_deception_is_still_caught(self) -> None:
        """The technique the branch exists for: our domain pushed out of the registrable part."""
        match = _match("corp.example.attacker.test", "attacker.test", "attacker")
        assert match is not None
        assert match.technique == "subdomain_deception"

    def test_deception_deeper_in_the_host_is_caught(self) -> None:
        match = _match("mail.corp.example.evil.test", "evil.test", "evil")
        assert match is not None
        assert match.technique == "subdomain_deception"

    def test_our_own_domain_is_not_deception(self) -> None:
        assert _match("mx.corp.example", "corp.example", "corp") is None


class TestDisplayNameClaimIsWordAligned:
    def _facts(self, display_name: str) -> set[str]:
        from msp_detection.facts import build_facts
        from msp_mail_parser import parse_message

        raw = (
            f'From: "{display_name}" <sales@vendor.test>\r\n'
            f"To: buh@corp.example\r\n"
            "Subject: Договор\r\n"
            "\r\n"
            "Добрый день, направляем договор.\r\n"
        ).encode()
        context = AnalysisContext(
            organization_name="Corp",
            corporate_domains=("corp.example",),
        )
        facts = build_facts(parse_message(raw), context)
        return set(facts.truthy())

    def test_a_vendor_whose_name_merely_starts_the_same_is_not_a_claim(self) -> None:
        assert "display_name_claims_organization" not in self._facts("Corps Security")

    def test_claiming_the_organisation_as_a_word_is_a_claim(self) -> None:
        assert "display_name_claims_organization" in self._facts("Corp Бухгалтерия")

    def test_concatenation_is_still_a_claim(self) -> None:
        """``CorpSecurity`` is the organisation's name glued to a word, and the capital letter
        says so. Lower-casing first is what made ``Corps`` indistinguishable from ``Corp`` + s."""
        assert "display_name_claims_organization" in self._facts("CorpSecurity")

    def test_an_unrelated_name_is_not_a_claim(self) -> None:
        assert "display_name_claims_organization" not in self._facts("Fern Logistics")
