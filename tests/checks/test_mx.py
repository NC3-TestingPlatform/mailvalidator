"""Tests for mailvalidator/checks/mx.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.mx import check_mx
from mailvalidator.models import Status


class TestMX:
    def test_found(self):
        with patch(
            "mailvalidator.checks.mx.resolve", return_value=["10 mail.example.com."]
        ):
            with patch("mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]):
                with patch(
                    "mailvalidator.checks.mx.get_authoritative_ns", return_value=[]
                ):
                    result = check_mx("example.com")
        assert len(result.records) == 1
        assert result.records[0].priority == 10
        assert result.records[0].exchange == "mail.example.com"
        assert any(c.status == Status.OK for c in result.checks)

    def test_not_found(self):
        with patch("mailvalidator.checks.mx.resolve", return_value=[]):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("nodomain.invalid")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_sorted_by_priority(self):
        records_raw = ["20 mail2.example.com.", "10 mail1.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch(
                    "mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]
                ):
                    result = check_mx("example.com")
        assert result.records[0].priority == 10
        assert result.records[1].priority == 20


class TestMXTargetResolution:
    @staticmethod
    def _run(records_raw: list[str], resolve_a_side_effect):
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch(
                    "mailvalidator.checks.mx.resolve_a",
                    side_effect=resolve_a_side_effect,
                ):
                    return check_mx("example.com")

    @staticmethod
    def _resolution_check(result):
        return next(c for c in result.checks if c.name == "MX Target Resolution")

    def test_all_targets_resolve_gives_ok(self):
        result = self._run(["10 mail.example.com."], [["1.2.3.4"]])
        check = self._resolution_check(result)
        assert check.status == Status.OK
        assert check.value == "1/1 target(s) resolve"

    def test_no_target_resolves_gives_error(self):
        """Single dangling MX — mail is undeliverable."""
        result = self._run(["0 dead.mail.protection.example."], [[]])
        check = self._resolution_check(result)
        assert check.status == Status.ERROR
        assert check.value == "0/1 target(s) resolve"
        assert any("dangling MX" in d for d in check.details)
        assert any("dead.mail.protection.example" in d for d in check.details)

    def test_partial_resolution_gives_warning(self):
        result = self._run(
            ["10 mail1.example.com.", "20 dead.example.com."],
            [["1.2.3.4"], []],
        )
        check = self._resolution_check(result)
        assert check.status == Status.WARNING
        assert check.value == "1/2 target(s) resolve"
        assert any("dead.example.com" in d for d in check.details)


class TestMXExtra:
    def test_malformed_entry_skipped(self):
        records_raw = ["10 mail.example.com.", "badentry"]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch(
                    "mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]
                ):
                    result = check_mx("example.com")
        assert len(result.records) == 1

    def test_duplicate_priority_is_informational(self):
        records_raw = ["10 mail1.example.com.", "10 mail2.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                with patch(
                    "mailvalidator.checks.mx.resolve_a", return_value=["1.2.3.4"]
                ):
                    result = check_mx("example.com")
        dup = next(c for c in result.checks if c.name == "Duplicate Priorities")
        assert dup.status == Status.INFO
        assert any("RFC 5321" in d for d in dup.details)

    def test_non_integer_priority_error(self):
        records_raw = ["abc mail.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("example.com")
        assert any(c.status == Status.ERROR for c in result.checks)
        assert any(
            "abc" in (d or "") for c in result.checks for d in (c.details or [])
        )

    def test_out_of_range_priority_error(self):
        records_raw = ["65536 mail.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("example.com")
        assert any(c.status == Status.ERROR for c in result.checks)
        assert any(
            "65536" in (d or "") for c in result.checks for d in (c.details or [])
        )

    def test_negative_priority_error(self):
        records_raw = ["-1 mail.example.com."]
        with patch("mailvalidator.checks.mx.resolve", return_value=records_raw):
            with patch("mailvalidator.checks.mx.get_authoritative_ns", return_value=[]):
                result = check_mx("example.com")
        assert any(c.status == Status.ERROR for c in result.checks)
