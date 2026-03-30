"""Tests for mailvalidator/checks/bimi.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.bimi import check_bimi
from mailvalidator.models import Status


class TestBIMI:
    def test_valid_record(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(c.status == Status.OK and "Logo" in c.name for c in result.checks)

    def test_http_logo_error(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=http://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(c.status == Status.ERROR and "Logo" in c.name for c in result.checks)


class TestBIMIExtra:
    def test_not_found(self):
        with patch("mailvalidator.checks.bimi.resolve", return_value=[]):
            result = check_bimi("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_unknown_version_not_found(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI2; l=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_bad_version_via_internal_validator(self):
        from mailvalidator.checks.bimi import _validate
        from mailvalidator.models import BIMIResult

        result = BIMIResult(domain="example.com")
        _validate({"v": "BIMI2", "l": "https://example.com/logo.svg"}, result)
        assert any(
            c.name == "Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_logo_url_warns(self):
        with patch("mailvalidator.checks.bimi.resolve", return_value=['"v=BIMI1"']):
            result = check_bimi("example.com")
        assert any(
            c.name == "Logo URL (l=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_non_svg_logo_warns(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.png"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Logo URL (l=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_svg_gz_logo_ok(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.svg.gz"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Logo URL (l=)" and c.status == Status.OK for c in result.checks
        )

    def test_authority_evidence_present(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"'
            ],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Authority Evidence (a=)" and c.value for c in result.checks
        )

    def test_authority_evidence_missing_info(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Authority Evidence (a=)" and c.status == Status.INFO
            for c in result.checks
        )


class TestBIMIRFCFixes:
    """Tests for BIMI spec compliance fixes B1–B4."""

    # B1: Multiple BIMI records must be flagged as ERROR.
    def test_multiple_bimi_records_error(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg"',
                '"v=BIMI1; l=https://other.example.com/logo.svg"',
            ],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "BIMI Record" and c.status == Status.ERROR for c in result.checks
        )
        assert any("Multiple" in d for c in result.checks for d in c.details)

    # B2: Explicit empty l= (VMC-only) must be INFO, not WARNING.
    def test_explicit_empty_l_with_a_is_info(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; l=; a=https://example.com/cert.pem"'],
        ):
            result = check_bimi("example.com")
        logo_check = next(c for c in result.checks if c.name == "Logo URL (l=)")
        assert logo_check.status == Status.INFO
        assert any("VMC-only" in d for d in logo_check.details)

    # B3: Unknown tags must be flagged as WARNING.
    def test_unknown_tag_warns(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=['"v=BIMI1; logo=https://example.com/logo.svg"'],
        ):
            result = check_bimi("example.com")
        assert any(
            c.name == "Unknown Tags" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_known_tags_no_unknown_warning(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"'
            ],
        ):
            result = check_bimi("example.com")
        assert not any(c.name == "Unknown Tags" for c in result.checks)

    # B4: a= must use HTTPS and a VMC-compatible extension.
    def test_a_tag_http_scheme_warns(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=http://example.com/cert.pem"'
            ],
        ):
            result = check_bimi("example.com")
        a_check = next(c for c in result.checks if c.name == "Authority Evidence (a=)")
        assert a_check.status == Status.WARNING
        assert any("HTTPS" in d for d in a_check.details)

    def test_a_tag_bad_extension_warns(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.der"'
            ],
        ):
            result = check_bimi("example.com")
        a_check = next(c for c in result.checks if c.name == "Authority Evidence (a=)")
        assert a_check.status == Status.WARNING
        assert any(".pem" in d or ".crt" in d for d in a_check.details)

    def test_a_tag_valid_pem_is_info_no_issues(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"'
            ],
        ):
            result = check_bimi("example.com")
        a_check = next(c for c in result.checks if c.name == "Authority Evidence (a=)")
        assert a_check.status == Status.INFO
        assert not a_check.details  # no validation issues

    def test_a_tag_valid_crt_is_info_no_issues(self):
        with patch(
            "mailvalidator.checks.bimi.resolve",
            return_value=[
                '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.crt"'
            ],
        ):
            result = check_bimi("example.com")
        a_check = next(c for c in result.checks if c.name == "Authority Evidence (a=)")
        assert a_check.status == Status.INFO
