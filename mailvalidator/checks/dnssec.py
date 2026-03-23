"""DNSSEC chain-of-trust checks for the email domain and its MX servers.

Two subjects are assessed independently:

**Email address domain** (the domain itself, e.g. ``example.com``)
    Is the SOA record signed and is the chain of trust fully valid?

**Mail server domain(s)** (the right-hand side of each MX record)
    Is the SOA record of each MX exchange hostname signed and valid?

For both subjects, CNAME chains are followed: if a name delegates via
CNAME, every link in the chain must be signed/valid, otherwise the
result is negative.  Only the first responding nameserver is tested;
nameservers with inconsistent configurations may produce varying results
between runs.

Each subject produces **one** :class:`~mailvalidator.models.CheckResult`
whose ``status`` reflects the combined existence + validity outcome:

+---------------------+----------+--------------------------------------------+
| chainvalidator      | status   | meaning                                    |
+=====================+==========+============================================+
| SECURE              | OK       | Signed and chain of trust fully valid      |
| INSECURE            | WARNING  | Signed but chain not anchored to root      |
| BOGUS               | ERROR    | Signatures present but cryptographically   |
|                     |          | broken                                     |
| not signed          | NOT_FOUND| No DNSSEC records found                    |
| lookup failure      | ERROR    | Could not complete the check               |
+---------------------+----------+--------------------------------------------+

.. note:: **DANE dependency**

    DNSSEC is a hard prerequisite for DANE (RFC 7671).  The DNSSEC check
    for each MX domain is therefore also a gate for DANE:

    * If the MX domain is unsigned, any TLSA record lookup is unprotected
      and DANE validation will fail.
    * If the MX domain is signed but the chain is BOGUS, validating
      resolvers will refuse to return TLSA records, causing DANE to fail
      even if the TLSA records themselves are correct.
    * A signed domain that returns an authenticated *Denial of Existence*
      (NSEC/NSEC3) for a TLSA query proves that no DANE record is
      published — this is a valid and secure negative result.
    * If a signed TLSA record exists but is simultaneously accompanied by
      an insecure NXDOMAIN for the same name (due to a faulty signer),
      DANE validation will fail.
"""

from __future__ import annotations

from chainvalidator.assessor import assess
from chainvalidator.models import DNSSECReport
from chainvalidator.models import Status as CVStatus

from mailvalidator.models import CheckResult, DNSSECResult, Status

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _assess_soa(domain: str, timeout: float = 5.0) -> DNSSECReport:
    """Run a chainvalidator SOA assessment for *domain*.

    Wraps :func:`chainvalidator.assessor.assess` and absorbs any
    unexpected exception so a failed lookup never crashes the caller.

    :param domain: Domain name to assess.
    :type domain: str
    :param timeout: Per-query UDP/TCP timeout in seconds.
    :type timeout: float
    :returns: Fully populated :class:`~chainvalidator.models.DNSSECReport`.
    :rtype: chainvalidator.models.DNSSECReport
    """
    try:
        return assess(domain, record_type="SOA", timeout=timeout)
    except Exception as exc:
        r = DNSSECReport(domain=domain, record_type="SOA", status=CVStatus.ERROR)
        r.errors.append(str(exc))
        return r


def _dnssec_check(
    report: DNSSECReport,
    subject: str,
    *,
    dane_note: bool = False,
) -> CheckResult:
    """Build a single combined DNSSEC :class:`~mailvalidator.models.CheckResult`.

    Collapses existence and validity into one row.  The ``value`` field
    shows a short verdict token; ``details`` provides the human-readable
    explanation together with chain-path and trust-anchor information when
    available.

    :param report: Chainvalidator report for the domain being checked.
    :type report: chainvalidator.models.DNSSECReport
    :param subject: Human-readable subject label used in the check name and
        detail messages (typically the domain being assessed).
    :type subject: str
    :param dane_note: When ``True``, append a DANE-consequence note to the
        details of unsigned or broken results.  Set for MX domain checks.
    :type dane_note: bool
    :returns: A single :class:`~mailvalidator.models.CheckResult` reflecting
        the combined existence + validity outcome.
    :rtype: ~mailvalidator.models.CheckResult
    """
    name = f"DNSSEC ({subject})"

    # ── SECURE: signed and chain fully anchored to IANA root ─────────────────
    if report.status is CVStatus.SECURE:
        details = [f"Chain of trust fully validated for {subject}."]
        details.append(f"Zone path: {' → '.join(report.zone_path)}")
        if report.trust_anchor_keys:
            details.append(f"Trust anchor: {', '.join(report.trust_anchor_keys)}")
        return CheckResult(
            name=name,
            status=Status.OK,
            value="signed — secure",
            details=details,
        )

    # ── INSECURE: signed but delegation not anchored to root ─────────────────
    if report.status is CVStatus.INSECURE:
        details = report.warnings[:] or [
            f"{subject} has DNSSEC records but the delegation chain is not "
            "anchored to the IANA root trust anchor (insecure island of security)."
        ]
        if dane_note:
            details.append(
                "DANE requires a fully secure chain; an insecure delegation "
                "means TLSA records for this domain are unprotected."
            )
        return CheckResult(
            name=name,
            status=Status.WARNING,
            value="signed — insecure",
            details=details,
        )

    # ── BOGUS: signatures present but cryptographically broken ───────────────
    if report.status is CVStatus.BOGUS:
        details = report.errors[:] or [
            f"Cryptographic DNSSEC validation failed for {subject}."
        ]
        if dane_note:
            details.append(
                "DANE requires a valid DNSSEC chain. "
                "Validating resolvers will refuse to return TLSA records for "
                "this domain until the broken signature is repaired."
            )
        return CheckResult(
            name=name,
            status=Status.ERROR,
            value="bogus",
            details=details,
        )

    # ── ERROR: lookup or network failure (no chain built at all) ─────────────
    if report.status is CVStatus.ERROR and not report.chain:
        details = report.errors[:] or [
            f"DNSSEC check could not be completed for {subject}."
        ]
        if dane_note:
            details.append("DANE check skipped: DNSSEC status could not be determined.")
        return CheckResult(
            name=name,
            status=Status.ERROR,
            value="lookup failed",
            details=details,
        )

    # ── unsigned: no DNSSEC records found ────────────────────────────────────
    details = [
        f"{subject} is not DNSSEC-signed. "
        "Senders that validate DNSSEC cannot verify the authenticity of DNS "
        "replies for this domain."
    ]
    if dane_note:
        details.append(
            "DNSSEC is required for DANE (RFC 7671). "
            "Without a valid DNSSEC chain, TLSA records for this domain are "
            "unprotected and DANE validation will fail."
        )
    return CheckResult(
        name=name,
        status=Status.NOT_FOUND,
        value="unsigned",
        details=details,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_dnssec_domain(domain: str, timeout: float = 5.0) -> DNSSECResult:
    """Check DNSSEC existence and validity for the email address *domain*.

    Assesses the SOA record of *domain* via the full chainvalidator
    chain-of-trust validation, including CNAME following.  Produces one
    :class:`~mailvalidator.models.CheckResult` whose status reflects the
    combined existence + validity outcome.

    :param domain: Email address domain to assess (e.g. ``"example.com"``).
    :type domain: str
    :param timeout: Per-query UDP/TCP timeout passed to chainvalidator.
    :type timeout: float
    :returns: Result containing a single combined
        :class:`~mailvalidator.models.CheckResult`.
    :rtype: ~mailvalidator.models.DNSSECResult
    """
    result = DNSSECResult(domain=domain)
    report = _assess_soa(domain, timeout=timeout)
    result.checks.append(_dnssec_check(report, subject=domain))
    return result


def check_dnssec_mx(
    mx_domains: list[str],
    email_domain: str = "",
    timeout: float = 5.0,
) -> DNSSECResult:
    """Check DNSSEC existence and validity for each MX server domain.

    Each MX exchange hostname is assessed independently.  One combined
    :class:`~mailvalidator.models.CheckResult` is appended per MX domain.

    Only the MX exchange hostnames are checked — there is no fallback to
    A/AAAA records when the MX list is empty, in accordance with the
    specification that MX-based mail delivery does not fall back to
    address records for DNSSEC purposes.

    Unsigned or broken MX domains receive an additional DANE-consequence
    note in their details, because DNSSEC is a hard prerequisite for DANE
    (RFC 7671).

    :param mx_domains: List of MX exchange hostnames to assess
        (e.g. ``["mx1.example.com", "mx2.example.com"]``).
    :type mx_domains: list[str]
    :param email_domain: Email address domain the MX records belong to.
        Used as the :attr:`~mailvalidator.models.DNSSECResult.domain` label
        on the returned result.  Defaults to the first entry of
        *mx_domains* when not supplied.
    :type email_domain: str
    :param timeout: Per-query UDP/TCP timeout passed to chainvalidator.
    :type timeout: float
    :returns: Result containing one combined
        :class:`~mailvalidator.models.CheckResult` per MX domain.
    :rtype: ~mailvalidator.models.DNSSECResult
    """
    domain_label = email_domain or (mx_domains[0] if mx_domains else "")
    result = DNSSECResult(domain=domain_label)

    if not mx_domains:
        result.checks.append(
            CheckResult(
                name="DNSSEC (MX)",
                status=Status.NA,
                value="no MX records",
                details=["No MX records found; DNSSEC check skipped."],
            )
        )
        return result

    for mx_domain in mx_domains:
        report = _assess_soa(mx_domain, timeout=timeout)
        result.checks.append(_dnssec_check(report, subject=mx_domain, dane_note=True))

    return result
