"""SMTP TLS Reporting (TLSRPT) record lookup and validation (RFC 8460).

TLSRPT allows receiving domains to publish a reporting endpoint where
sending MTAs can submit JSON reports about TLS negotiation failures.
The record is a TXT record at ``_smtp._tls.<domain>``.
"""

from __future__ import annotations

import re

from mailvalidator.dns_utils import resolve
from mailvalidator.models import CheckResult, Status, TLSRPTResult

# RFC 8460 §3.1 — at most two URIs in the rua= list.
_MAX_RUA_URIS = 2

# RFC 8460 §3.1 — v=TLSRPTv1 must be the first tag in the record.
_FIRST_TAG_RE = re.compile(r"^\s*v\s*=\s*TLSRPTv1", re.IGNORECASE)


def check_tlsrpt(domain: str) -> TLSRPTResult:
    """Look up and validate the TLSRPT record at ``_smtp._tls.<domain>``.

    :param domain: The domain whose TLSRPT record should be validated.
    :type domain: str
    :returns: Result containing the raw record and
        :class:`~mailvalidator.models.CheckResult` items for the version tag
        and each reporting URI in the ``rua=`` tag.
    :rtype: TLSRPTResult
    """
    result = TLSRPTResult(domain=domain)
    tlsrpt_name = f"_smtp._tls.{domain}"

    records = resolve(tlsrpt_name, "TXT")
    tls_records = [r.strip('"') for r in records if "v=TLSRPTv1" in r]

    if not tls_records:
        result.checks.append(
            CheckResult(
                name="TLSRPT Record",
                status=Status.NOT_FOUND,
                details=[
                    f"No TLSRPT record found at {tlsrpt_name}. SMTP TLS Reporting is not configured."
                ],
            )
        )
        return result

    # T1: Multiple TLSRPT records matching v=TLSRPTv1 are undefined behaviour
    # per RFC 8460 §3 — flag as ERROR.
    if len(tls_records) > 1:
        result.checks.append(
            CheckResult(
                name="TLSRPT Record",
                status=Status.ERROR,
                details=[
                    f"Multiple TLSRPT records found at {tlsrpt_name}. "
                    "RFC 8460 §3 states behaviour is undefined when more than one "
                    "matching record exists; remove all but one.",
                ],
            )
        )
        return result

    record = tls_records[0]
    result.record = record
    result.checks.append(
        CheckResult(name="TLSRPT Record", status=Status.OK, details=[record])
    )

    tags = _parse_tags(record)
    _warn_unknown_tags(tags, result)
    _validate(tags, record, result)
    return result


def _parse_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited ``tag=value`` pairs from a TLSRPT record string.

    :param record: Raw TLSRPT TXT record value.
    :type record: str
    :returns: Mapping of tag names to their string values.
    :rtype: dict[str, str]
    """
    tags: dict[str, str] = {}
    for part in re.split(r"\s*;\s*", record):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip()] = v.strip()
    return tags


_KNOWN_TAGS: frozenset[str] = frozenset({"v", "rua"})


def _warn_unknown_tags(tags: dict[str, str], result: TLSRPTResult) -> None:
    """T4: Surface unknown tags that may indicate typos (e.g. ``ru=`` instead of ``rua=``).

    :param tags: Parsed TLSRPT tag dictionary.
    :param result: Result object to append check items to.
    """
    unknown = [k for k in tags if k not in _KNOWN_TAGS]
    if unknown:
        result.checks.append(
            CheckResult(
                name="Unknown Tags",
                status=Status.WARNING,
                details=[
                    f"Unknown tag(s) found: {', '.join(unknown)}. "
                    "RFC 8460 §3.1 defines only v= and rua=; check for typos.",
                ],
            )
        )


def _validate(tags: dict[str, str], raw_record: str, result: TLSRPTResult) -> None:
    """Validate TLSRPT tag values and append :class:`~mailvalidator.models.CheckResult` items to *result*.

    :param tags: Parsed TLSRPT tag dictionary from :func:`_parse_tags`.
    :type tags: dict[str, str]
    :param raw_record: The original raw record string (used for ordering check).
    :type raw_record: str
    :param result: Result object to which check items are appended.
    :type result: TLSRPTResult
    """
    v = tags.get("v", "")
    if v != "TLSRPTv1":
        result.checks.append(
            CheckResult(name="Version", status=Status.ERROR, value=v or "(missing)")
        )
    else:
        # T5: v=TLSRPTv1 must be the first tag (RFC 8460 §3.1).
        if not _FIRST_TAG_RE.match(raw_record):
            result.checks.append(
                CheckResult(
                    name="Version",
                    status=Status.WARNING,
                    value="TLSRPTv1",
                    details=[
                        "v=TLSRPTv1 is not the first tag in the record. "
                        "RFC 8460 §3.1 requires v= to appear first."
                    ],
                )
            )
        else:
            result.checks.append(
                CheckResult(name="Version", status=Status.OK, value="TLSRPTv1")
            )

    rua = tags.get("rua", "")
    if not rua:
        result.checks.append(
            CheckResult(
                name="Reporting URI (rua=)",
                status=Status.ERROR,
                details=["rua= is required by RFC 8460."],
            )
        )
        return

    uris = [u.strip() for u in rua.split(",")]

    # T2: RFC 8460 §3.1 permits at most two URIs in the rua= list.
    if len(uris) > _MAX_RUA_URIS:
        result.checks.append(
            CheckResult(
                name="Reporting URI (rua=)",
                status=Status.WARNING,
                details=[
                    f"{len(uris)} URIs found in rua=; RFC 8460 §3.1 permits at most {_MAX_RUA_URIS}.",
                ],
            )
        )

    for uri in uris:
        if uri.startswith("mailto:"):
            # T3: Validate syntactic correctness of mailto: URIs.
            address = uri[len("mailto:") :]
            if not address or "@" not in address:
                result.checks.append(
                    CheckResult(
                        name="Reporting URI",
                        status=Status.WARNING,
                        value=uri,
                        details=["mailto: URI does not contain a valid email address."],
                    )
                )
            else:
                result.checks.append(
                    CheckResult(name="Reporting URI", status=Status.OK, value=uri)
                )
        elif uri.startswith("https://"):
            result.checks.append(
                CheckResult(name="Reporting URI", status=Status.OK, value=uri)
            )
        else:
            result.checks.append(
                CheckResult(
                    name="Reporting URI",
                    status=Status.WARNING,
                    value=uri,
                    details=["URI should be mailto: or https:// per RFC 8460."],
                )
            )
