"""Tests for mailvalidator/checks/dnssec.py."""

from __future__ import annotations

from unittest.mock import patch

from chainvalidator.models import (
    ChainLink,
    DNSSECReport,
)
from chainvalidator.models import (
    Status as CVStatus,
)

from mailvalidator.checks.dnssec import (
    _assess_soa,
    _dnssec_check,
    check_dnssec_domain,
    check_dnssec_mx,
)
from mailvalidator.models import Status

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _report(
    domain: str = "example.com",
    cv_status: CVStatus = CVStatus.SECURE,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
    chain: bool = True,
    trust_anchor_keys: list[str] | None = None,
) -> DNSSECReport:
    """Build a minimal DNSSECReport for a given chainvalidator status."""
    r = DNSSECReport(
        domain=domain,
        record_type="SOA",
        status=cv_status,
    )
    r.errors = errors or []
    r.warnings = warnings or []
    r.trust_anchor_keys = trust_anchor_keys or ["DS=20326/SHA-256"]
    if chain:
        r.chain.append(ChainLink(zone=".", status=CVStatus.SECURE))
        r.chain.append(ChainLink(zone="com.", status=CVStatus.SECURE))
        r.chain.append(ChainLink(zone=f"{domain}.", status=cv_status))
    return r


# ---------------------------------------------------------------------------
# _assess_soa
# ---------------------------------------------------------------------------


class TestAssessSoa:
    def test_returns_report_on_success(self):
        report = _report()
        with patch(
            "mailvalidator.checks.dnssec.assess", return_value=report
        ) as mock_assess:
            result = _assess_soa("example.com", timeout=3.0)
        mock_assess.assert_called_once_with(
            "example.com", record_type="SOA", timeout=3.0
        )
        assert result is report

    def test_absorbs_exception_and_returns_error_report(self):
        with patch(
            "mailvalidator.checks.dnssec.assess", side_effect=RuntimeError("boom")
        ):
            result = _assess_soa("example.com")
        assert result.status is CVStatus.ERROR
        assert any("boom" in e for e in result.errors)


# ---------------------------------------------------------------------------
# _dnssec_check — all CVStatus branches
# ---------------------------------------------------------------------------


class TestDnssecCheck:
    def test_secure_gives_ok(self):
        check = _dnssec_check(_report(cv_status=CVStatus.SECURE), "example.com")
        assert check.status == Status.OK
        assert "secure" in check.value

    def test_secure_includes_zone_path_in_details(self):
        check = _dnssec_check(_report(cv_status=CVStatus.SECURE), "example.com")
        assert any("→" in d for d in check.details)

    def test_secure_includes_trust_anchor_when_present(self):
        check = _dnssec_check(
            _report(cv_status=CVStatus.SECURE, trust_anchor_keys=["DS=20326/SHA-256"]),
            "example.com",
        )
        assert any("DS=20326/SHA-256" in d for d in check.details)

    def test_insecure_gives_warning(self):
        check = _dnssec_check(
            _report(cv_status=CVStatus.INSECURE, warnings=["no DS in parent"]),
            "example.com",
        )
        assert check.status == Status.WARNING
        assert "insecure" in check.value
        assert "no DS in parent" in check.details

    def test_insecure_without_warnings_uses_fallback_detail(self):
        check = _dnssec_check(
            _report(cv_status=CVStatus.INSECURE, warnings=[]), "example.com"
        )
        assert check.status == Status.WARNING
        assert len(check.details) > 0

    def test_bogus_gives_error(self):
        check = _dnssec_check(
            _report(cv_status=CVStatus.BOGUS, errors=["sig mismatch"]),
            "example.com",
        )
        assert check.status == Status.ERROR
        assert check.value == "bogus"
        assert "sig mismatch" in check.details

    def test_bogus_without_errors_uses_fallback_detail(self):
        check = _dnssec_check(
            _report(cv_status=CVStatus.BOGUS, errors=[]), "example.com"
        )
        assert check.status == Status.ERROR
        assert len(check.details) > 0

    def test_error_with_no_chain_gives_error(self):
        r = _report(cv_status=CVStatus.ERROR, errors=["network error"], chain=False)
        check = _dnssec_check(r, "example.com")
        assert check.status == Status.ERROR
        assert check.value == "lookup failed"
        assert "network error" in check.details

    def test_error_with_no_chain_uses_fallback_when_no_errors(self):
        r = _report(cv_status=CVStatus.ERROR, errors=[], chain=False)
        check = _dnssec_check(r, "example.com")
        assert check.status == Status.ERROR
        assert len(check.details) > 0

    def test_unsigned_gives_not_found(self):
        """ERROR with a chain present is treated as unsigned."""
        r = _report(cv_status=CVStatus.ERROR, chain=True)
        check = _dnssec_check(r, "example.com")
        assert check.status == Status.NOT_FOUND
        assert check.value == "unsigned"

    def test_subject_appears_in_check_name(self):
        check = _dnssec_check(_report(), "mx1.example.com")
        assert "mx1.example.com" in check.name

    def test_dane_note_added_for_unsigned_when_dane_note_true(self):
        r = _report(cv_status=CVStatus.ERROR, chain=True)
        check = _dnssec_check(r, "mx1.example.com", dane_note=True)
        assert any("DANE" in d for d in check.details)

    def test_dane_note_added_for_bogus_when_dane_note_true(self):
        r = _report(cv_status=CVStatus.BOGUS)
        check = _dnssec_check(r, "mx1.example.com", dane_note=True)
        assert any("DANE" in d for d in check.details)

    def test_dane_note_added_for_insecure_when_dane_note_true(self):
        r = _report(cv_status=CVStatus.INSECURE)
        check = _dnssec_check(r, "mx1.example.com", dane_note=True)
        assert any("DANE" in d for d in check.details)

    def test_dane_note_added_for_lookup_failed_when_dane_note_true(self):
        r = _report(cv_status=CVStatus.ERROR, chain=False)
        check = _dnssec_check(r, "mx1.example.com", dane_note=True)
        assert any("DANE" in d for d in check.details)

    def test_no_dane_note_when_secure(self):
        """DANE note is never appended on SECURE results."""
        r = _report(cv_status=CVStatus.SECURE)
        check = _dnssec_check(r, "mx1.example.com", dane_note=True)
        assert not any("DANE" in d for d in check.details)

    def test_no_dane_note_by_default(self):
        """dane_note defaults to False."""
        r = _report(cv_status=CVStatus.BOGUS)
        check = _dnssec_check(r, "example.com")
        assert not any("DANE" in d for d in check.details)


# ---------------------------------------------------------------------------
# check_dnssec_domain
# ---------------------------------------------------------------------------


class TestCheckDnssecDomain:
    def _patch(self, cv_status: CVStatus = CVStatus.SECURE, **kwargs):
        return patch(
            "mailvalidator.checks.dnssec._assess_soa",
            return_value=_report(cv_status=cv_status, **kwargs),
        )

    def test_returns_dnssec_result_with_correct_domain(self):
        with self._patch():
            result = check_dnssec_domain("example.com")
        assert result.domain == "example.com"

    def test_produces_exactly_one_check(self):
        with self._patch():
            result = check_dnssec_domain("example.com")
        assert len(result.checks) == 1

    def test_check_name_contains_domain(self):
        with self._patch():
            result = check_dnssec_domain("example.com")
        assert "example.com" in result.checks[0].name

    def test_secure_gives_ok(self):
        with self._patch(CVStatus.SECURE):
            result = check_dnssec_domain("example.com")
        assert result.checks[0].status == Status.OK

    def test_insecure_gives_warning(self):
        with self._patch(CVStatus.INSECURE):
            result = check_dnssec_domain("example.com")
        assert result.checks[0].status == Status.WARNING

    def test_bogus_gives_error(self):
        with self._patch(CVStatus.BOGUS):
            result = check_dnssec_domain("example.com")
        assert result.checks[0].status == Status.ERROR

    def test_unsigned_gives_not_found(self):
        with self._patch(CVStatus.ERROR):
            result = check_dnssec_domain("example.com")
        assert result.checks[0].status == Status.NOT_FOUND

    def test_passes_timeout(self):
        with patch(
            "mailvalidator.checks.dnssec._assess_soa", return_value=_report()
        ) as mock_soa:
            check_dnssec_domain("example.com", timeout=8.0)
        mock_soa.assert_called_once_with("example.com", timeout=8.0)


# ---------------------------------------------------------------------------
# check_dnssec_mx
# ---------------------------------------------------------------------------


class TestCheckDnssecMx:
    def _patch_multi(self, statuses: list[CVStatus]):
        reports = [
            _report(domain=f"mx{i}.example.com", cv_status=s)
            for i, s in enumerate(statuses, 1)
        ]
        return patch("mailvalidator.checks.dnssec._assess_soa", side_effect=reports)

    def test_empty_mx_domains_produces_single_na_check(self):
        result = check_dnssec_mx([])
        assert len(result.checks) == 1
        assert result.checks[0].status == Status.NA

    def test_empty_domain_field_when_no_mx(self):
        result = check_dnssec_mx([])
        assert result.domain == ""

    def test_email_domain_used_as_domain_label(self):
        with self._patch_multi([CVStatus.SECURE]):
            result = check_dnssec_mx(["mx1.example.com"], email_domain="example.com")
        assert result.domain == "example.com"

    def test_domain_falls_back_to_first_mx_when_no_email_domain(self):
        with self._patch_multi([CVStatus.SECURE]):
            result = check_dnssec_mx(["mx1.example.com"])
        assert result.domain == "mx1.example.com"

    def test_single_mx_produces_one_check(self):
        with self._patch_multi([CVStatus.SECURE]):
            result = check_dnssec_mx(["mx1.example.com"])
        assert len(result.checks) == 1

    def test_two_mx_produces_two_checks(self):
        with self._patch_multi([CVStatus.SECURE, CVStatus.INSECURE]):
            result = check_dnssec_mx(["mx1.example.com", "mx2.example.com"])
        assert len(result.checks) == 2

    def test_each_check_name_contains_its_mx_domain(self):
        with self._patch_multi([CVStatus.SECURE, CVStatus.BOGUS]):
            result = check_dnssec_mx(["mx1.example.com", "mx2.example.com"])
        assert "mx1.example.com" in result.checks[0].name
        assert "mx2.example.com" in result.checks[1].name

    def test_each_mx_assessed_independently(self):
        with patch(
            "mailvalidator.checks.dnssec._assess_soa", return_value=_report()
        ) as mock_soa:
            check_dnssec_mx(["mx1.example.com", "mx2.example.com"])
        assert mock_soa.call_count == 2

    def test_mixed_statuses_reflected_per_domain(self):
        with self._patch_multi([CVStatus.SECURE, CVStatus.BOGUS]):
            result = check_dnssec_mx(["mx1.example.com", "mx2.example.com"])
        assert result.checks[0].status == Status.OK
        assert result.checks[1].status == Status.ERROR

    def test_dane_note_present_on_bogus_mx(self):
        with self._patch_multi([CVStatus.BOGUS]):
            result = check_dnssec_mx(["mx1.example.com"])
        assert any("DANE" in d for d in result.checks[0].details)

    def test_dane_note_present_on_unsigned_mx(self):
        with self._patch_multi([CVStatus.ERROR]):
            result = check_dnssec_mx(["mx1.example.com"])
        assert any("DANE" in d for d in result.checks[0].details)

    def test_dane_note_absent_on_secure_mx(self):
        with self._patch_multi([CVStatus.SECURE]):
            result = check_dnssec_mx(["mx1.example.com"])
        assert not any("DANE" in d for d in result.checks[0].details)

    def test_passes_timeout_to_each_call(self):
        with patch(
            "mailvalidator.checks.dnssec._assess_soa", return_value=_report()
        ) as mock_soa:
            check_dnssec_mx(["mx1.example.com"], timeout=7.0)
        mock_soa.assert_called_once_with("mx1.example.com", timeout=7.0)

    def test_no_fallback_to_a_record_when_mx_empty(self):
        """Spec: no fallback to A/AAAA records when MX is absent."""
        with patch("mailvalidator.checks.dnssec._assess_soa") as mock_soa:
            check_dnssec_mx([])
        mock_soa.assert_not_called()
