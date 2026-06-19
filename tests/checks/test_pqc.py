"""Tests for mailvalidator.checks.smtp._pqc."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mailvalidator.checks.smtp import (
    _assess_pqc,
    _check_pqc,
    _check_pqc_certificate,
    _PQC_SIG_OIDS,
)
from mailvalidator.models import Status, TLSDetails

from quantumvalidator.models import (
    CheckResult as QVCheckResult,
    QuantumReport,
    Status as QVStatus,
    Verdict,
)


def _make_report(
    verdict: Verdict,
    negotiated_group: str | None = None,
    tls_version: str | None = "TLSv1.3",
    checks: list | None = None,
) -> QuantumReport:
    return QuantumReport(
        target="mail.example.com",
        detected_starttls="smtp",
        port=25,
        tls_version=tls_version,
        negotiated_group=negotiated_group,
        verdict=verdict,
        checks=checks or [],
    )


def _qv_kex(
    status: QVStatus,
    value: str | None,
    reason: str,
    standard: str | None = None,
) -> QVCheckResult:
    return QVCheckResult(
        name="key_exchange", status=status, value=value, reason=reason, standard=standard
    )


def _qv_error(reason: str) -> QVCheckResult:
    return QVCheckResult(
        name="connection", status=QVStatus.ERROR, value=None, reason=reason
    )


class TestAssessPqc:
    def test_returns_report_on_success(self):
        report = _make_report(Verdict.SAFE, negotiated_group="X25519MLKEM768")
        with patch("mailvalidator.checks.smtp._pqc.assess", return_value=report) as mock:
            result = _assess_pqc("mail.example.com", 25)
        mock.assert_called_once_with("mail.example.com", port=25, timeout=10)
        assert result is report

    def test_absorbs_exception_returns_error_report(self):
        with patch(
            "mailvalidator.checks.smtp._pqc.assess",
            side_effect=RuntimeError("openssl not found"),
        ):
            result = _assess_pqc("mail.example.com", 25)
        assert result.verdict == Verdict.UNSAFE
        assert len(result.checks) == 1
        assert result.checks[0].status == QVStatus.ERROR
        assert "openssl not found" in result.checks[0].reason

    def test_passes_port_to_assess(self):
        report = _make_report(Verdict.UNSAFE)
        with patch("mailvalidator.checks.smtp._pqc.assess", return_value=report) as mock:
            _assess_pqc("mx1.example.com", 587)
        mock.assert_called_once_with("mx1.example.com", port=587, timeout=10)


class TestCheckPqcSafe:
    def test_good_status_x25519mlkem768(self):
        """X25519MLKEM768 is in SAFE_GROUPS → GOOD."""
        checks: list = []
        _check_pqc("X25519MLKEM768", checks)
        cr = checks[0]
        assert cr.name == "PQC Key Exchange"
        assert cr.status == Status.GOOD
        assert cr.value == "X25519MLKEM768"
        assert cr.details == []

    def test_good_status_secp256r1mlkem768(self):
        """SecP256r1MLKEM768 is in SAFE_GROUPS → GOOD."""
        checks: list = []
        _check_pqc("SecP256r1MLKEM768", checks)
        assert checks[0].status == Status.GOOD
        assert checks[0].value == "SecP256r1MLKEM768"

    def test_good_status_secp384r1mlkem1024(self):
        """SecP384r1MLKEM1024 is in SAFE_GROUPS → GOOD."""
        checks: list = []
        _check_pqc("SecP384r1MLKEM1024", checks)
        assert checks[0].status == Status.GOOD

    def test_probe_available_defaults_to_true(self):
        """probe_available defaults to True — safe group still yields GOOD."""
        checks: list = []
        _check_pqc("X25519MLKEM768", checks)
        assert checks[0].status == Status.GOOD


class TestCheckPqcUnsafe:
    def test_warning_classical_group_with_detail(self):
        """Classical group (x25519) → WARNING with group name in details."""
        checks: list = []
        _check_pqc("x25519", checks)
        cr = checks[0]
        assert cr.name == "PQC Key Exchange"
        assert cr.status == Status.WARNING
        assert cr.value == "x25519"
        assert "x25519" in cr.details[0]

    def test_warning_none_group(self):
        """No group negotiated → WARNING with value 'none'."""
        checks: list = []
        _check_pqc(None, checks)
        cr = checks[0]
        assert cr.status == Status.WARNING
        assert cr.value == "none"
        assert "No post-quantum" in cr.details[0]

    def test_warning_classical_p256_group(self):
        """P-256 is a classical group → WARNING."""
        checks: list = []
        _check_pqc("P-256", checks)
        assert checks[0].status == Status.WARNING


class TestCheckPqcError:
    def test_info_when_probe_unavailable(self):
        """probe_available=False → INFO 'probe unavailable'."""
        checks: list = []
        _check_pqc(None, checks, probe_available=False)
        cr = checks[0]
        assert cr.name == "PQC Key Exchange"
        assert cr.status == Status.INFO
        assert cr.value == "probe unavailable"
        assert cr.details != []

    def test_info_ignores_group_when_probe_unavailable(self):
        """Even a safe group is ignored when probe_available=False."""
        checks: list = []
        _check_pqc("X25519MLKEM768", checks, probe_available=False)
        assert checks[0].status == Status.INFO
        assert checks[0].value == "probe unavailable"


# ---------------------------------------------------------------------------
# _check_pqc_certificate
# ---------------------------------------------------------------------------


def _make_details_with_der(der: bytes, pubkey_type: str = "RSA") -> TLSDetails:
    """Return a TLSDetails with a stashed cert DER and cert_pubkey_type."""
    d = TLSDetails(cert_subject="CN=mail.example.com", cert_pubkey_type=pubkey_type)
    d._cert_der = der  # type: ignore[attr-defined]
    return d


def _mock_cert(oid_dotted: str) -> MagicMock:
    """Return a mock x509 certificate whose signature_algorithm_oid.dotted_string is *oid_dotted*."""
    cert = MagicMock()
    cert.signature_algorithm_oid.dotted_string = oid_dotted
    return cert


class TestCheckPqcCertificate:
    def test_no_cert_der_returns_info(self):
        """No _cert_der stash → INFO 'not available'."""
        checks: list = []
        _check_pqc_certificate(TLSDetails(), checks)
        assert checks[0].name == "PQC Certificate"
        assert checks[0].status == Status.INFO
        assert checks[0].value == "not available"

    def test_classical_rsa_cert(self):
        """Real RSA DER → INFO 'Classical (RSA)'."""
        from tests.conftest import make_rsa_cert_der

        checks: list = []
        _check_pqc_certificate(_make_details_with_der(make_rsa_cert_der(), "RSA"), checks)
        assert checks[0].status == Status.INFO
        assert "RSA" in checks[0].value

    def test_classical_ec_cert(self):
        """Real EC DER → INFO 'Classical (EC)'."""
        from tests.conftest import make_ec_cert_der

        checks: list = []
        _check_pqc_certificate(_make_details_with_der(make_ec_cert_der(), "EC"), checks)
        assert checks[0].status == Status.INFO
        assert "EC" in checks[0].value

    def test_pqc_ml_dsa_44(self):
        """ML-DSA-44 OID → GOOD 'ML-DSA-44'."""
        checks: list = []
        cert = _mock_cert("2.16.840.1.101.3.4.3.17")
        with patch("cryptography.x509.load_der_x509_certificate", return_value=cert):
            _check_pqc_certificate(_make_details_with_der(b"fake"), checks)
        assert checks[0].status == Status.GOOD
        assert checks[0].value == "ML-DSA-44"

    def test_pqc_ml_dsa_65(self):
        """ML-DSA-65 OID → GOOD 'ML-DSA-65'."""
        checks: list = []
        cert = _mock_cert("2.16.840.1.101.3.4.3.18")
        with patch("cryptography.x509.load_der_x509_certificate", return_value=cert):
            _check_pqc_certificate(_make_details_with_der(b"fake"), checks)
        assert checks[0].status == Status.GOOD
        assert checks[0].value == "ML-DSA-65"

    def test_pqc_slh_dsa(self):
        """SLH-DSA-SHA2-128s OID → GOOD."""
        checks: list = []
        cert = _mock_cert("2.16.840.1.101.3.4.3.20")
        with patch("cryptography.x509.load_der_x509_certificate", return_value=cert):
            _check_pqc_certificate(_make_details_with_der(b"fake"), checks)
        assert checks[0].status == Status.GOOD
        assert checks[0].value == "SLH-DSA-SHA2-128s"

    def test_pqc_fn_dsa(self):
        """FN-DSA-512 provisional OID → GOOD."""
        checks: list = []
        cert = _mock_cert("1.3.9999.3.6")
        with patch("cryptography.x509.load_der_x509_certificate", return_value=cert):
            _check_pqc_certificate(_make_details_with_der(b"fake"), checks)
        assert checks[0].status == Status.GOOD
        assert checks[0].value == "FN-DSA-512"

    def test_all_pqc_oids_covered(self):
        """Every OID in _PQC_SIG_OIDS returns GOOD status."""
        for oid, name in _PQC_SIG_OIDS.items():
            checks: list = []
            cert = _mock_cert(oid)
            with patch("cryptography.x509.load_der_x509_certificate", return_value=cert):
                _check_pqc_certificate(_make_details_with_der(b"fake"), checks)
            assert checks[0].status == Status.GOOD, f"OID {oid} ({name}) did not return GOOD"
            assert checks[0].value == name

    def test_parse_error_returns_info(self):
        """DER parse failure → INFO 'not available'."""
        checks: list = []
        with patch(
            "cryptography.x509.load_der_x509_certificate",
            side_effect=ValueError("bad DER"),
        ):
            _check_pqc_certificate(_make_details_with_der(b"garbage"), checks)
        assert checks[0].status == Status.INFO
        assert checks[0].value == "not available"
