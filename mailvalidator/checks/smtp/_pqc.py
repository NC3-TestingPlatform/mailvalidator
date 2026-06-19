"""Post-quantum cryptography (PQC) key exchange and certificate readiness checks."""

from __future__ import annotations

from quantumvalidator.assessor import assess
from quantumvalidator.constants import SAFE_GROUPS
from quantumvalidator.models import CheckResult as QVCheckResult
from quantumvalidator.models import QuantumReport
from quantumvalidator.models import Status as QVStatus
from quantumvalidator.models import Verdict

from mailvalidator.models import CheckResult, Status, TLSDetails

# Signature algorithm OIDs for standardised and provisional PQC schemes.
# Sources: NIST FIPS 204 (ML-DSA), NIST FIPS 205 (SLH-DSA),
#          Open Quantum Safe / IETF draft OIDs (FN-DSA / Falcon).
_PQC_SIG_OIDS: dict[str, str] = {
    # ML-DSA (CRYSTALS-Dilithium) — NIST FIPS 204
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    # SLH-DSA (SPHINCS+) — NIST FIPS 205, SHA-2 variants
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    # SLH-DSA (SPHINCS+) — NIST FIPS 205, SHAKE variants
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    # FN-DSA (Falcon) — IETF draft provisional OIDs (Open Quantum Safe project)
    "1.3.9999.3.6": "FN-DSA-512",
    "1.3.9999.3.9": "FN-DSA-1024",
}


def _assess_pqc(host: str, port: int, timeout: int = 10) -> QuantumReport:
    """Run a quantumvalidator PQC assessment for *host*:*port*.

    Wraps :func:`quantumvalidator.assessor.assess` and absorbs any unexpected
    exception so a failed probe never crashes the caller.

    :param host: Mail server hostname or IP address.
    :type host: str
    :param port: TCP port to probe (e.g. 25, 587, 465).
    :type port: int
    :param timeout: Connection timeout in seconds.
    :type timeout: int
    :returns: Populated :class:`~quantumvalidator.models.QuantumReport`.
    :rtype: quantumvalidator.models.QuantumReport
    """
    try:
        return assess(host, port=port, timeout=timeout)
    except Exception as exc:
        report = QuantumReport(
            target=host,
            detected_starttls=None,
            port=port,
            tls_version=None,
            negotiated_group=None,
            verdict=Verdict.UNSAFE,
        )
        report.checks.append(
            QVCheckResult(
                name="connection",
                status=QVStatus.ERROR,
                value=None,
                reason=str(exc),
            )
        )
        return report


def _check_pqc(
    negotiated_group: str | None,
    checks: list[CheckResult],
    *,
    probe_available: bool = True,
) -> None:
    """Evaluate post-quantum hybrid key exchange readiness from a pre-computed group.

    Consumes the *negotiated_group* returned by
    :func:`~mailvalidator.checks.smtp._tls_probe._probe_openssl_combined` and
    appends a single :class:`~mailvalidator.models.CheckResult` to *checks*.

    Status mapping:

    +-------------------------------+---------+-------------------------------------+
    | condition                     | status  | meaning                             |
    +===============================+=========+=====================================+
    | group in SAFE_GROUPS          | GOOD    | PQC hybrid group negotiated         |
    | group not in SAFE_GROUPS      | WARNING | Classical key exchange only         |
    | probe_available is False      | INFO    | openssl unavailable or SSRF blocked |
    +-------------------------------+---------+-------------------------------------+

    :param negotiated_group: TLS 1.3 group name from the combined probe, or ``None``.
    :type negotiated_group: str or None
    :param checks: List to which the new :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    :param probe_available: ``False`` when openssl was not found or the SSRF guard
        blocked the target; skips the check with ``INFO``.
    :type probe_available: bool
    """
    if not probe_available:
        checks.append(
            CheckResult(
                name="PQC Key Exchange",
                status=Status.INFO,
                value="probe unavailable",
                details=["openssl binary not found; cannot probe for PQC key exchange."],
            )
        )
        return

    if negotiated_group and negotiated_group in SAFE_GROUPS:
        checks.append(
            CheckResult(
                name="PQC Key Exchange",
                status=Status.GOOD,
                value=negotiated_group,
            )
        )
    else:
        detail = (
            f"No post-quantum hybrid group negotiated; got {negotiated_group}. Enable X25519MLKEM768."
            if negotiated_group
            else "No post-quantum hybrid group negotiated."
        )
        checks.append(
            CheckResult(
                name="PQC Key Exchange",
                status=Status.WARNING,
                value=negotiated_group or "none",
                details=[detail],
            )
        )


def _check_pqc_certificate(details: TLSDetails, checks: list[CheckResult]) -> None:
    """Check whether the mail server certificate uses a post-quantum signature algorithm.

    Reads the DER-encoded certificate stashed in *details* by ``_probe_tls`` and
    looks up its ``signatureAlgorithm`` OID against :data:`_PQC_SIG_OIDS`.

    Status mapping:

    +--------------------+---------+-----------------------------------------------+
    | Outcome            | status  | meaning                                       |
    +====================+=========+===============================================+
    | PQC OID matched    | GOOD    | Certificate signed with ML-DSA / SLH-DSA /    |
    |                    |         | FN-DSA                                        |
    | Classical OID      | INFO    | RSA or ECDSA — no penalty; PQC certs are not  |
    |                    |         | yet widely issued by public CAs               |
    | No cert / error    | INFO    | Certificate unavailable or could not be parsed|
    +--------------------+---------+-----------------------------------------------+

    :param details: TLS session details with the certificate DER stash.
    :type details: ~mailvalidator.models.TLSDetails
    :param checks: List to which the new :class:`~mailvalidator.models.CheckResult`
        is appended.
    :type checks: list[~mailvalidator.models.CheckResult]
    """
    cert_der: bytes | None = getattr(details, "_cert_der", None)
    if not cert_der:
        checks.append(
            CheckResult(name="PQC Certificate", status=Status.INFO, value="not available")
        )
        return

    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
        oid = cert.signature_algorithm_oid.dotted_string
    except Exception:
        checks.append(
            CheckResult(
                name="PQC Certificate",
                status=Status.INFO,
                value="not available",
                details=["Certificate could not be parsed for PQC assessment."],
            )
        )
        return

    pqc_name = _PQC_SIG_OIDS.get(oid)
    if pqc_name:
        checks.append(
            CheckResult(name="PQC Certificate", status=Status.GOOD, value=pqc_name)
        )
        return

    pk = details.cert_pubkey_type
    checks.append(
        CheckResult(
            name="PQC Certificate",
            status=Status.INFO,
            value=f"Classical ({pk})" if pk else "Classical",
            details=[
                "Certificate uses a classical signature algorithm. "
                "PQC certificates (ML-DSA / SLH-DSA) are not yet widely issued by public CAs."
            ],
        )
    )
