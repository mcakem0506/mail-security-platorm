"""Fact extraction: engines turn a ParsedMessage + context into a flat, explainable fact set.

Facts are *observations*, never verdicts. Rules (rules/*.yaml) map facts to signals so detection
logic can be versioned and tuned without code changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from msp_contracts import Indicator, IOCType, ScanCompleteness
from msp_mail_parser import ParsedMessage, category_for_extension, split_domain, to_ascii
from msp_mail_parser.filetype import MACRO_EXT, SHORTCUT_EXT

from .auth import AuthResults, parse_authentication_results, parse_received_spf, received_chain_facts
from .bec import bec_facts
from .context import AnalysisContext
from .gateway import gateway_facts
from .similarity import (
    find_lookalike,
    has_homoglyph,
    has_mixed_script_token,
    homoglyph_chars,
    is_mixed_script,
    is_personal_name,
    name_similarity,
    script_names,
    skeleton,
)

_URL_SHORTENERS = frozenset(
    [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bitly.com",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "s.id",
        "clck.ru",
        "vk.cc",
        "u.to",
        "qps.ru",
        "gg.gg",
        "lnkd.in",
        "t.ly",
        "shorte.st",
        "soo.gd",
        "v.gd",
        "x.co",
    ]
)
_SUSPICIOUS_TLDS = frozenset(
    [
        "zip",
        "mov",
        "top",
        "xyz",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "click",
        "link",
        "work",
        "live",
        "icu",
        "rest",
        "cam",
        "surf",
        "monster",
        "bar",
        "quest",
        "cyou",
        "sbs",
        "shop",
        "online",
        "store",
        "site",
        "space",
        "website",
        "fun",
        "pw",
        "cc",
        "ws",
    ]
)
_CREDENTIAL_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:login|signin|sign-in|log-in|auth|authenticate|sso|oauth|verify|verification|"
    r"account|password|passwd|credential|session|secure|update-?info|confirm|validate|owa|webmail|"
    r"mailbox|office365|o365|microsoft|wp-login|admin|unlock|recover|reset)(?:[/._\-]|$)"
)
_DANGEROUS_CATEGORIES = {"executable", "script", "shortcut", "disk_image"}


@dataclass
class UrlFinding:
    url_index: int
    flags: list[str] = field(default_factory=list)
    lookalike: dict[str, Any] | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class FactSet:
    facts: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    indicators: list[Indicator] = field(default_factory=list)
    url_findings: list[UrlFinding] = field(default_factory=list)
    attachment_flags: dict[str, list[str]] = field(default_factory=dict)
    auth: AuthResults = field(default_factory=AuthResults)
    missing_evidence: list[str] = field(default_factory=list)

    def set(self, key: str, value: Any, **evidence: Any) -> None:
        self.facts[key] = value
        if evidence:
            self.evidence[key] = {k: v for k, v in evidence.items() if v not in (None, "", [], {})}

    def flag(self, key: str, **evidence: Any) -> None:
        self.set(key, True, **evidence)

    def get(self, key: str, default: Any = None) -> Any:
        return self.facts.get(key, default)

    def truthy(self) -> dict[str, Any]:
        return {k: v for k, v in self.facts.items() if v}

    def add_indicator(self, ioc_type: IOCType, value: str, context: str = "") -> None:
        if not value:
            return
        ind = Indicator(ioc_type=ioc_type, value=value.lower()[:1024], context=context)
        if ind not in self.indicators:
            self.indicators.append(ind)


def _sender_facts(msg: ParsedMessage, ctx: AnalysisContext, fs: FactSet) -> None:
    frm = msg.from_
    if frm is None or not frm.address:
        fs.flag("from_missing")
        fs.missing_evidence.append("From header is missing or unparseable")
        return
    fs.set("from_address", frm.address)
    fs.set("from_domain", frm.domain)
    fs.set("from_display_name", frm.display_name)
    fs.add_indicator(IOCType.EMAIL, frm.address, "from")
    if frm.domain:
        fs.add_indicator(IOCType.DOMAIN, frm.domain_ascii or frm.domain, "from")

    internal_sender = ctx.is_corporate_domain(frm.domain)
    fs.set("sender_internal", internal_sender)
    fs.set("sender_external", not internal_sender)

    dom = split_domain(frm.domain)
    if dom.is_idn:
        fs.flag("from_domain_punycode", domain=frm.domain, punycode=frm.domain_ascii)
    # A single-script name/domain is legitimate (e.g. a fully Cyrillic name or IDN); only the
    # mixing of scripts with ASCII-lookalike characters indicates deliberate visual spoofing.
    if is_mixed_script(frm.domain):
        fs.flag("from_domain_mixed_script", domain=frm.domain, scripts=sorted(script_names(frm.domain)))
        if has_homoglyph(frm.domain):
            fs.flag("from_domain_homoglyph", domain=frm.domain, chars=homoglyph_chars(frm.domain))
    # Per *word*, not per string: "Отдел продаж Partner" is an ordinary Russian company name
    # with a Latin brand in it, while "Аpple" hides a Cyrillic А inside a Latin word. Only the
    # second is spoofing, and testing the whole string cannot tell them apart.
    if has_mixed_script_token(frm.display_name) and has_homoglyph(frm.display_name):
        fs.flag(
            "display_name_homoglyph",
            display_name=frm.display_name,
            chars=homoglyph_chars(frm.display_name),
        )

    # lookalike of the corporate domain / known services
    if not internal_sender and frm.domain:
        corp = find_lookalike(
            frm.domain_ascii, dom.registrable_ascii, dom.label, ctx.corporate_targets, ctx.corporate_labels
        )
        if corp is not None:
            fs.flag(
                "from_domain_lookalike_corporate",
                domain=frm.domain,
                target=corp.target,
                technique=corp.technique,
                detail=corp.detail,
                confidence=corp.confidence,
            )
        svc = find_lookalike(
            frm.domain_ascii, dom.registrable_ascii, dom.label, ctx.service_targets, ctx.service_labels
        )
        if svc is not None and corp is None:
            fs.flag(
                "from_domain_lookalike_service",
                domain=frm.domain,
                target=svc.target,
                technique=svc.technique,
                detail=svc.detail,
                confidence=svc.confidence,
            )

    # Reply-To / Return-Path / Sender mismatch
    reply_to = msg.reply_to[0] if msg.reply_to else None
    if reply_to is not None and reply_to.address and reply_to.address != frm.address:
        fs.add_indicator(IOCType.EMAIL, reply_to.address, "reply_to")
        same_domain = to_ascii(reply_to.domain) == to_ascii(frm.domain)
        fs.set("reply_to_address", reply_to.address)
        if not same_domain:
            fs.flag(
                "reply_to_domain_mismatch",
                from_address=frm.address,
                reply_to=reply_to.address,
            )
            if internal_sender and not ctx.is_corporate_domain(reply_to.domain):
                fs.flag(
                    "reply_to_external_for_internal_sender",
                    from_address=frm.address,
                    reply_to=reply_to.address,
                )
        else:
            fs.flag("reply_to_local_mismatch", from_address=frm.address, reply_to=reply_to.address)
    if msg.return_path and frm.address and msg.return_path != frm.address:
        rp_domain = msg.return_path.rsplit("@", 1)[1] if "@" in msg.return_path else ""
        if to_ascii(rp_domain) != to_ascii(frm.domain) and not ctx.is_trusted_infrastructure(rp_domain):
            fs.flag("return_path_mismatch", from_address=frm.address, return_path=msg.return_path)
    if (
        msg.sender
        and msg.sender.address
        and msg.sender.address != frm.address
        and not ctx.is_trusted_infrastructure(msg.sender.domain)
    ):
        fs.flag("sender_header_mismatch", from_address=frm.address, sender=msg.sender.address)

    # header-level anomalies
    if len(msg.header_all("From")) > 1 or "MULTIPLE_FROM" in msg.errors:
        fs.flag("multiple_from_headers")
    if not msg.message_id:
        fs.flag("message_id_missing")
    elif frm.domain:
        mid_domain = msg.message_id.strip("<>").rsplit("@", 1)[-1].lower()
        if mid_domain and to_ascii(mid_domain) != to_ascii(frm.domain):
            fs.set("message_id_domain_mismatch", True, message_id_domain=mid_domain, from_domain=frm.domain)
    if not msg.date:
        fs.flag("date_missing")


def _identity_facts(msg: ParsedMessage, ctx: AnalysisContext, fs: FactSet) -> None:
    frm = msg.from_
    if frm is None:
        return
    display = frm.display_name
    internal_sender = bool(fs.get("sender_internal"))

    # A display name that itself contains a different email address.
    embedded = re.findall(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+", display)
    for addr in embedded:
        if addr.lower() != frm.address:
            fs.flag("display_name_contains_other_address", display_name=display, embedded=addr.lower())
            fs.add_indicator(IOCType.EMAIL, addr, "display_name")
            if ctx.is_corporate_domain(addr.rsplit("@", 1)[1]):
                fs.flag("display_name_claims_corporate_address", embedded=addr.lower())

    if not display:
        return

    protected_exact = ctx.protected_by_email(frm.address)
    if protected_exact is not None:
        fs.set("sender_is_protected_identity", True, identity=protected_exact.identity_id)

    # An internal, authenticated sender whose display name matches their own directory entry is
    # the person themselves, not an impersonation of themselves. People routinely hold more than
    # one mailbox — an administrator has a user account and a privileged one — and treating the
    # second as an attack on the first flags ordinary internal correspondence.
    own_directory_entry = ctx.directory_by_email(frm.address)
    sends_under_own_name = (
        internal_sender
        and own_directory_entry is not None
        and name_similarity(display, own_directory_entry.display_name) >= 0.85
    )
    if sends_under_own_name:
        fs.set(
            "sender_uses_own_directory_name",
            True,
            display_name=display,
            directory_user=own_directory_entry.email if own_directory_entry else "",
        )

    # Display-name impersonation of a protected identity from a non-matching address.
    candidates = ctx.protected_by_name(display)
    best: tuple[float, Any] | None = None
    if not sends_under_own_name:
        for pi in candidates or ():
            if frm.address in {e.lower() for e in pi.all_emails}:
                continue
            best = (1.0, pi)
            break
        if best is None:
            for pi in ctx.protected_identities:
                if not pi.enabled or frm.address in {e.lower() for e in pi.all_emails}:
                    continue
                sim = max((name_similarity(display, n) for n in pi.all_names if n), default=0.0)
                if sim >= 0.75 and (best is None or sim > best[0]):
                    best = (sim, pi)
    if best is not None:
        sim, pi = best
        approved = frm.address in {d.lower() for d in pi.approved_delegates} or any(
            to_ascii(frm.domain) == to_ascii(s) or to_ascii(frm.domain).endswith("." + to_ascii(s))
            for s in pi.approved_external_systems
        )
        ev = {
            "display_name": display,
            "identity": pi.display_name,
            "identity_email": pi.email,
            "actual_sender": frm.address,
            "similarity": round(sim, 2),
            "categories": [c.value for c in pi.categories],
            "risk_class": pi.risk_class,
            "vip": pi.vip,
        }
        if approved:
            fs.set("protected_identity_approved_delegate", True, **ev)
        else:
            fs.set("protected_identity_impersonation", True, **ev)
            if not internal_sender:
                fs.set("protected_identity_impersonation_external", True, **ev)
            cats = {c.value for c in pi.categories}
            if "executive" in cats:
                fs.set("executive_impersonation", True, **ev)
            if cats & {"finance", "procurement"}:
                fs.set("finance_identity_impersonation", True, **ev)
            if "security" in cats or "administrator" in cats:
                fs.set("it_identity_impersonation", True, **ev)
            fs.set("impersonated_identity_risk_class", pi.risk_class, **ev)
            if pi.risk_class == "critical":
                fs.set("critical_identity_impersonation", True, **ev)
            if pi.vip:
                fs.set("vip_identity_impersonation", True, **ev)

    # Display name matching any directory user while the address is external.
    #
    # Only *personal* names are compared. Generic role names — "Бухгалтерия", "Отдел продаж",
    # "Техподдержка" — are shared by every organisation, so matching them against the directory
    # flags a contractor's accounting department as impersonating ours. A personal name is
    # recognised by shape (given name plus surname), not by a maintained list, because every
    # such list is incomplete in a different language.
    if not internal_sender and not fs.get("protected_identity_impersonation") and is_personal_name(display):
        for du in ctx.directory_by_name(display):
            if frm.address != du.email.lower() and is_personal_name(du.display_name):
                fs.set(
                    "internal_display_name_from_external_sender",
                    True,
                    display_name=display,
                    directory_user=du.email,
                    actual_sender=frm.address,
                )
                break
    elif not internal_sender and display and not is_personal_name(display):
        # Recorded so the absence of a signal is explainable: the name was compared and
        # deliberately not treated as a person's name.
        fs.set("display_name_is_generic_role", True, display_name=display)

    # Display name claiming the organisation or a known brand while sending externally.
    if not internal_sender:
        sk_display = skeleton(display)
        org_sk = skeleton(ctx.organization_name)
        if org_sk and len(org_sk) >= 4 and org_sk in sk_display:
            fs.set(
                "display_name_claims_organization",
                True,
                display_name=display,
                organization=ctx.organization_name,
            )
        for corp in ctx.corporate_domains_ascii:
            label = split_domain(corp).label
            if len(label) >= 4 and skeleton(label) in sk_display:
                fs.set("display_name_claims_organization", True, display_name=display, matched=label)
                break


def _url_facts(msg: ParsedMessage, ctx: AnalysisContext, fs: FactSet) -> None:
    if not msg.urls:
        return
    fs.set("url_count", len(msg.urls))
    hosts: set[str] = set()
    for idx, u in enumerate(msg.urls):
        finding = UrlFinding(url_index=idx)
        if u.scheme in {"javascript", "data", "vbscript", "file"}:
            finding.flags.append("DANGEROUS_SCHEME")
            fs.flag("url_dangerous_scheme", scheme=u.scheme, url=u.redacted)
            fs.url_findings.append(finding)
            continue
        if u.parse_error:
            finding.flags.append("UNPARSEABLE")
            fs.url_findings.append(finding)
            continue
        if not u.host:
            fs.url_findings.append(finding)
            continue
        hosts.add(u.host_ascii)
        dom = split_domain(u.host_ascii)
        fs.add_indicator(IOCType.URL, u.normalized, f"url:{u.source}")
        if u.is_ip_literal:
            fs.add_indicator(IOCType.IPV6 if ":" in u.host_ascii else IOCType.IPV4, u.host_ascii, "url_host")
            finding.flags.append("IP_LITERAL")
            fs.flag("url_ip_literal", url=u.redacted, host=u.host_ascii)
        else:
            fs.add_indicator(IOCType.DOMAIN, dom.registrable_ascii, "url_host")
        if u.port and u.port not in (80, 443):
            finding.flags.append("NON_STANDARD_PORT")
            fs.flag("url_non_standard_port", url=u.redacted, port=u.port)
        if u.has_userinfo:
            finding.flags.append("USERINFO")
            fs.flag("url_misleading_userinfo", url=u.redacted)
        if dom.registrable_ascii in _URL_SHORTENERS or dom.host_ascii in _URL_SHORTENERS:
            finding.flags.append("SHORTENER")
            fs.flag("url_shortener", url=u.redacted, host=u.host_ascii)
        if u.subdomain and u.subdomain.count(".") >= 3:
            finding.flags.append("EXCESSIVE_SUBDOMAINS")
            fs.flag("url_excessive_subdomains", url=u.redacted, subdomain=u.subdomain)
        if dom.is_idn:
            finding.flags.append("PUNYCODE")
            fs.flag("url_punycode", url=u.redacted, host=u.host, punycode=u.host_ascii)
        if is_mixed_script(u.host) and has_homoglyph(u.host):
            finding.flags.append("HOMOGLYPH")
            fs.flag("url_homoglyph", url=u.redacted, host=u.host, chars=homoglyph_chars(u.host))
        if dom.suffix and dom.suffix.split(".")[-1] in _SUSPICIOUS_TLDS:
            finding.flags.append("SUSPICIOUS_TLD")
            fs.flag("url_suspicious_tld", url=u.redacted, tld=dom.suffix)
        if _CREDENTIAL_PATH_RE.search(u.path) or any(_CREDENTIAL_PATH_RE.search(k) for k in u.query_keys):
            finding.flags.append("CREDENTIAL_PATH")
            fs.flag("url_credential_path", url=u.redacted)
        if u.source in {"form", "attachment:form"}:
            finding.flags.append("FORM_ACTION")
            if not ctx.is_corporate_domain(u.host) and not ctx.is_trusted_infrastructure(u.host):
                fs.flag("html_form_posts_external", url=u.redacted, host=u.host)

        # visible text vs href mismatch
        if u.visible_text:
            vis = u.visible_text.strip()
            vis_urls = re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{4,}", vis)
            vis_hosts = []
            for v in vis_urls:
                v_host = re.sub(r"(?i)^(?:https?://)?", "", v).split("/")[0].split("?")[0].strip().lower()
                if v_host:
                    vis_hosts.append(to_ascii(v_host))
            if vis_hosts:
                actual = dom.registrable_ascii
                if all(split_domain(h).registrable_ascii != actual for h in vis_hosts):
                    finding.flags.append("VISIBLE_HREF_MISMATCH")
                    fs.flag(
                        "url_visible_href_mismatch",
                        visible=vis_hosts[0],
                        actual_host=u.host,
                        url=u.redacted,
                    )
            elif re.search(r"(?i)\b(?:click here|войти|login|sign in|подтвердить|open document)\b", vis):
                finding.flags.append("ACTION_TEXT")

        # lookalike hosts
        if not ctx.is_corporate_domain(u.host):
            corp = find_lookalike(
                u.host_ascii, dom.registrable_ascii, dom.label, ctx.corporate_targets, ctx.corporate_labels
            )
            if corp is not None:
                finding.lookalike = {"target": corp.target, "technique": corp.technique, "scope": "corporate"}
                fs.flag(
                    "url_lookalike_corporate",
                    url=u.redacted,
                    host=u.host,
                    target=corp.target,
                    technique=corp.technique,
                    detail=corp.detail,
                )
            svc = find_lookalike(
                u.host_ascii, dom.registrable_ascii, dom.label, ctx.service_targets, ctx.service_labels
            )
            if svc is not None and corp is None:
                finding.lookalike = {"target": svc.target, "technique": svc.technique, "scope": "service"}
                fs.flag(
                    "url_lookalike_service",
                    url=u.redacted,
                    host=u.host,
                    target=svc.target,
                    technique=svc.technique,
                    detail=svc.detail,
                )
        fs.url_findings.append(finding)
    fs.set("url_host_count", len(hosts))
    if msg.html_stats.get("password_inputs"):
        fs.flag("html_password_input", count=msg.html_stats["password_inputs"])
    if msg.html_stats.get("scripts"):
        fs.flag("html_script_present", count=msg.html_stats["scripts"])


def _attachment_facts(msg: ParsedMessage, ctx: AnalysisContext, fs: FactSet) -> None:
    if not msg.attachments:
        return
    top = [a for a in msg.attachments if a.meta.depth == 0]
    fs.set("attachment_count", len(top))
    for att in msg.attachments:
        m = att.meta
        flags = list(m.flags)
        fs.add_indicator(IOCType.SHA256, m.sha256, f"attachment:{m.normalized_filename}")
        cat_by_ext = category_for_extension(m.extension)
        ev = {"filename": m.normalized_filename, "sha256": m.sha256, "type": m.detected_type}
        exts = [e for e in m.normalized_filename.lower().split(".")[1:] if e]
        if len(exts) >= 2 and category_for_extension(exts[-1]) in _DANGEROUS_CATEGORIES:
            benign_first = category_for_extension(exts[-2]) in {"document", "office", "image", "text"}
            if benign_first or exts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
                flags.append("DOUBLE_EXTENSION")
                fs.flag("attachment_double_extension", **ev, extensions=exts)
        if cat_by_ext == "executable" or m.detected_type in {
            "pe_executable",
            "elf_executable",
            "macho_executable",
            "jar",
            "apk",
        }:
            flags.append("EXECUTABLE")
            fs.flag("attachment_executable", **ev)
        if cat_by_ext == "script" or m.detected_type == "script":
            flags.append("SCRIPT")
            fs.flag("attachment_script", **ev)
        if cat_by_ext == "shortcut" or m.detected_type == "lnk" or m.extension in SHORTCUT_EXT:
            flags.append("SHORTCUT")
            fs.flag("attachment_shortcut", **ev)
        if m.detected_type in {"ole_macro", "ooxml_macro"} or m.extension in MACRO_EXT:
            flags.append("MACRO_ENABLED")
            fs.flag("attachment_macro_enabled", **ev)
        if "EMBEDDED_OBJECTS" in m.flags or "ACTIVEX" in m.flags:
            fs.flag("attachment_embedded_objects", **ev)
        if cat_by_ext == "disk_image" or m.detected_type in {"iso", "vhd", "vhdx"}:
            flags.append("DISK_IMAGE")
            fs.flag("attachment_disk_image", **ev)
        if "EXTENSION_MISMATCH" in m.flags:
            fs.flag("attachment_extension_mismatch", **ev, extension=m.extension)
        if "RTLO_FILENAME" in m.flags:
            fs.flag("attachment_rtlo_filename", **ev)
        if m.encrypted or "ENCRYPTED_ARCHIVE" in m.flags:
            flags.append("ENCRYPTED_ARCHIVE")
            fs.flag("attachment_encrypted_archive", **ev)
            fs.missing_evidence.append(f"Archive '{m.normalized_filename}' is password-protected")
        for bomb in ("ZIP_BOMB", "EXCESSIVE_COMPRESSION_RATIO", "TOO_MANY_FILES", "EXTRACTION_LIMIT"):
            if bomb in m.flags:
                fs.flag("attachment_archive_bomb", **ev, indicator=bomb)
                break
        if "NESTED_ARCHIVE" in m.flags:
            fs.flag("attachment_nested_archive", **ev)
        if "PATH_TRAVERSAL" in m.flags or "ABSOLUTE_PATH" in m.flags or "SYMLINK" in m.flags:
            fs.flag("attachment_unsafe_paths", **ev)
        if "UNSUPPORTED_ARCHIVE_FORMAT" in m.flags:
            fs.missing_evidence.append(f"Archive format '{m.detected_type}' not statically inspected")
        if m.detected_type in {"html", "svg"} and m.depth == 0:
            fs.flag("attachment_html", **ev)
        if "HTML_PASSWORD_FORM" in m.flags:
            fs.flag("attachment_html_credential_form", **ev)
        if "HTML_SMUGGLING_PATTERN" in m.flags:
            fs.flag("attachment_html_smuggling", **ev)
        if m.depth > 0 and any(f in flags for f in ("EXECUTABLE", "SCRIPT", "SHORTCUT", "DOUBLE_EXTENSION")):
            fs.flag("archive_contains_dangerous_file", **ev, depth=m.depth)
        if flags:
            fs.attachment_flags[m.sha256] = sorted(set(flags))
    if msg.encrypted:
        fs.flag("message_encrypted")
        fs.missing_evidence.append("Message content is encrypted and cannot be analysed")


def build_facts(msg: ParsedMessage, ctx: AnalysisContext) -> FactSet:
    fs = FactSet()
    fs.set("subject", msg.subject)
    fs.set("source", ctx.source.value)
    if ctx.reported_by:
        fs.flag("user_reported", reported_by=ctx.reported_by)
    fs.set("recipient_count", len(msg.to) + len(msg.cc))
    if ctx.recipient_is_protected:
        fs.flag("recipient_is_protected_identity", department=ctx.recipient_department)
    if ctx.recipient_department:
        fs.set("recipient_department", ctx.recipient_department.lower())

    # Only Authentication-Results written by a verified authentication server are interpreted:
    # a spoofed header claiming spf=pass would otherwise suppress the very signals that catch
    # sender spoofing (ТЗ 1.0.1 §4.4). Without a gateway layer every header is read, as before.
    findings = ctx.gateway_findings
    auth_headers = (
        findings.trusted_auth_results
        if findings is not None and findings.present
        else msg.authentication_results
    )
    fs.auth = parse_authentication_results(auth_headers)
    spf_headers = parse_received_spf(msg.received_spf)
    fs.auth.merge_received_spf(spf_headers)
    for key, value in fs.auth.as_facts().items():
        fs.set(key, value, **fs.auth.evidence.get(key, {}))
    if not auth_headers and not msg.received_spf:
        fs.missing_evidence.append("No trusted Authentication-Results header available")
        if msg.authentication_results:
            fs.missing_evidence.append(
                "Authentication-Results present but not written by a verified authentication server"
            )
    if msg.dkim_signatures == 0:
        fs.set("dkim_signature_absent", True)

    for key, value, ev in received_chain_facts(msg.received):
        fs.set(key, value, **ev)

    _sender_facts(msg, ctx, fs)
    _identity_facts(msg, ctx, fs)
    _url_facts(msg, ctx, fs)
    _attachment_facts(msg, ctx, fs)
    for key, value, ev in bec_facts(msg, ctx, fs.facts):
        fs.set(key, value, **ev)

    # Verdicts from an upstream gateway (KSMG and others) are an additional source, never the
    # final word: a clean gateway verdict does not lower the platform's own risk (ТЗ 2.1).
    for key, value, ev in gateway_facts(ctx.gateway_findings):
        fs.set(key, value, **ev)

    hist = ctx.sender_history
    if hist.known_sender:
        fs.set("sender_known", True, message_count=hist.message_count)
    elif fs.get("sender_external"):
        fs.set("sender_first_time", True)
    if hist.previously_malicious:
        fs.set("sender_previously_malicious", True, count=hist.previously_malicious)
    if hist.previously_reported:
        fs.set("sender_previously_reported", True, count=hist.previously_reported)

    _limit_facts(msg, fs)
    if not msg.parse_ok:
        fs.flag("message_unparseable", errors=msg.errors[:5])
        fs.missing_evidence.append("Message could not be fully parsed")
    elif any(e.startswith("MIME_DEFECT") for e in msg.errors):
        fs.flag("malformed_mime", errors=sorted({e for e in msg.errors if e.startswith("MIME_DEFECT")})[:5])
    return fs


#: Each parser limit becomes its own fact, so exceeding one produces its own explainable signal
#: rather than a single opaque "limits reached" note (ТЗ 1.0.1 §4.2).
_LIMIT_FACTS: dict[str, str] = {
    "MAX_MESSAGE_SIZE": "limit_message_size_exceeded",
    "MAX_ATTACHMENT_SIZE": "limit_attachment_size_exceeded",
    "MAX_ATTACHMENTS": "limit_attachment_count_exceeded",
    "MAX_PARTS": "limit_mime_parts_exceeded",
    "MAX_MIME_DEPTH": "limit_mime_depth_exceeded",
    "MAX_URLS": "limit_url_count_exceeded",
    "PARSER_TIMEOUT": "limit_parser_timeout",
}
#: Archive limits are reported per attachment rather than on the message.
_ARCHIVE_LIMIT_FLAGS: dict[str, str] = {
    "EXTRACTION_LIMIT": "limit_decompressed_size_exceeded",
    "NESTING_LIMIT": "limit_archive_depth_exceeded",
    "TOO_MANY_FILES": "limit_archive_file_count_exceeded",
}
#: What each limit means for the analyst, in one clause.
_LIMIT_EVIDENCE: dict[str, str] = {
    "MAX_MESSAGE_SIZE": "письмо превышает максимальный размер для анализа",
    "MAX_ATTACHMENT_SIZE": "вложение превышает максимальный размер для анализа",
    "MAX_ATTACHMENTS": "во вложениях больше файлов, чем платформа разбирает",
    "MAX_PARTS": "в письме больше MIME-частей, чем платформа разбирает",
    "MAX_MIME_DEPTH": "вложенность MIME-структуры превышает допустимую",
    "MAX_URLS": "в письме больше ссылок, чем платформа разбирает",
    "PARSER_TIMEOUT": "разбор письма не завершился за отведённое время",
}


def _limit_facts(msg: ParsedMessage, fs: FactSet) -> None:
    """Record every limit that was hit, plus the resulting completeness of the scan.

    A limit is not a detection, but it is never silence either: the parts that were not examined
    are recorded as missing evidence, which keeps the verdict out of LOW_RISK (ТЗ 1.0.1 §4.2).
    """
    hit: list[str] = list(msg.limits_hit)
    for meta in (a.meta for a in msg.attachments):
        for flag in meta.flags:
            if flag in _ARCHIVE_LIMIT_FLAGS and flag not in hit:
                hit.append(flag)

    if not hit:
        fs.set("scan_completeness", ScanCompleteness.COMPLETE.value)
        return

    fs.set("parser_limits_hit", hit)
    for code in hit:
        fact = _LIMIT_FACTS.get(code) or _ARCHIVE_LIMIT_FLAGS.get(code)
        if fact is None:
            continue
        evidence: dict[str, Any] = {"limit": code}
        if code == "MAX_MESSAGE_SIZE":
            evidence["actual_size_bytes"] = msg.size
        fs.set(fact, True, **evidence)
        fs.missing_evidence.append(_LIMIT_EVIDENCE.get(code, f"limit reached: {code}"))

    # A message the parser refused outright was never examined at all; one that merely lost an
    # oversized attachment was examined in part. The distinction reaches the employee view,
    # where "проверено" must not be said about either.
    completeness = (
        ScanCompleteness.UNSCANNABLE
        if "MAX_MESSAGE_SIZE" in hit or not msg.parse_ok
        else ScanCompleteness.LIMIT_EXCEEDED
    )
    fs.set("scan_completeness", completeness.value)
    fs.flag("scan_incomplete", completeness=completeness.value, limits=hit[:6])
