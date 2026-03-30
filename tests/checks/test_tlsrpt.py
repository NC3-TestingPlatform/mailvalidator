"""Tests for mailvalidator/checks/tlsrpt.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.tlsrpt import check_tlsrpt
from mailvalidator.models import Status


class TestTLSRPT:
    def test_valid(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("mailvalidator.checks.tlsrpt.resolve", return_value=[]):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)


class TestTLSRPTExtra:
    def test_unknown_version_not_found(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv2; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_bad_version_via_internal_validator(self):
        from mailvalidator.checks.tlsrpt import _validate
        from mailvalidator.models import TLSRPTResult

        result = TLSRPTResult(domain="example.com")
        _validate(
            {"v": "TLSRPTv2", "rua": "mailto:tls@example.com"},
            "v=TLSRPTv2; rua=mailto:tls@example.com",
            result,
        )
        assert any(
            c.name == "Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_missing_rua_error(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve", return_value=['"v=TLSRPTv1"']
        ):
            result = check_tlsrpt("example.com")
        assert any(
            "rua" in c.name.lower() and c.status == Status.ERROR for c in result.checks
        )

    def test_https_rua_ok(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=https://reports.example.com/tls"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.OK for c in result.checks
        )

    def test_invalid_rua_scheme_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=http://reports.example.com/tls"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_multiple_rua_uris(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=[
                '"v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/tls"'
            ],
        ):
            result = check_tlsrpt("example.com")
        assert len([c for c in result.checks if c.name == "Reporting URI"]) == 2


class TestTLSRPTRFCFixes:
    """Tests for RFC 8460 compliance fixes T1–T5."""

    # T1: Multiple records are undefined behaviour — must be flagged as ERROR.
    def test_multiple_records_error(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=[
                '"v=TLSRPTv1; rua=mailto:tls@example.com"',
                '"v=TLSRPTv1; rua=mailto:other@example.com"',
            ],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "TLSRPT Record" and c.status == Status.ERROR
            for c in result.checks
        )
        assert any("Multiple" in d for c in result.checks for d in c.details)

    # T2: More than 2 URIs in rua= must produce a WARNING.
    def test_too_many_rua_uris_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=[
                '"v=TLSRPTv1; rua=mailto:a@example.com,https://b.example.com,https://c.example.com"'
            ],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI (rua=)" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_two_rua_uris_no_warning(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=[
                '"v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/tls"'
            ],
        ):
            result = check_tlsrpt("example.com")
        assert not any(
            c.name == "Reporting URI (rua=)" and c.status == Status.WARNING
            for c in result.checks
        )

    # T3: Syntactically invalid mailto: URIs must produce a WARNING.
    def test_bare_mailto_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_mailto_without_at_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:notanemail"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_valid_mailto_ok(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Reporting URI" and c.status == Status.OK for c in result.checks
        )

    # T4: Unknown tags (e.g. typos) must be surfaced as WARNING.
    def test_unknown_tag_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; ru=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Unknown Tags" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_known_tags_no_unknown_warning(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert not any(c.name == "Unknown Tags" for c in result.checks)

    # T5: v= must be the first tag (RFC 8460 §3.1).
    def test_v_not_first_warns(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"rua=mailto:tls@example.com; v=TLSRPTv1"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(
            c.name == "Version" and c.status == Status.WARNING for c in result.checks
        )

    def test_v_first_ok(self):
        with patch(
            "mailvalidator.checks.tlsrpt.resolve",
            return_value=['"v=TLSRPTv1; rua=mailto:tls@example.com"'],
        ):
            result = check_tlsrpt("example.com")
        assert any(c.name == "Version" and c.status == Status.OK for c in result.checks)
