"""Tests for mailvalidator/assessor.py."""

from __future__ import annotations

import socket as _socket
from unittest.mock import MagicMock, patch

from mailvalidator.assessor import (
    _primary_ip,
    _provider_zone,
    _select_probe_records,
    assess,
)
from mailvalidator.models import (
    BIMIResult,
    DKIMResult,
    DMARCResult,
    MailReport,
    MTASTSResult,
    MXRecord,
    SPFResult,
    TLSRPTResult,
)
from tests.conftest import make_mx_result, make_simple_result


class TestProviderZone:
    def test_last_two_labels(self):
        assert _provider_zone("aspmx.l.google.com") == "google.com"

    def test_trailing_dot_and_case(self):
        assert _provider_zone("MX2.Mail.OVH.NET.") == "ovh.net"

    def test_single_label(self):
        assert _provider_zone("localhost") == "localhost"

    def test_multi_label_public_suffix(self):
        assert _provider_zone("mx1.acme.co.uk") == "acme.co.uk"

    def test_distinct_providers_under_same_public_suffix(self):
        assert _provider_zone("mx1.acme.co.uk") != _provider_zone(
            "mx1.othercorp.co.uk"
        )

    def test_bare_public_suffix(self):
        assert _provider_zone("co.uk") == "co.uk"


class TestSelectProbeRecords:
    @staticmethod
    def _rec(priority: int, exchange: str) -> MXRecord:
        return MXRecord(priority=priority, exchange=exchange, ip_addresses=[])

    def test_covers_distinct_providers_before_filling(self):
        records = [
            self._rec(1, "aspmx.l.google.com"),
            self._rec(5, "alt1.aspmx.l.google.com"),
            self._rec(5, "alt2.aspmx.l.google.com"),
            self._rec(10, "alt3.aspmx.l.google.com"),
            self._rec(50, "mx2.mail.ovh.net"),
            self._rec(100, "mx3.mail.ovh.net"),
        ]
        selected = _select_probe_records(records)
        exchanges = [r.exchange for r in selected]
        assert exchanges == [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "mx2.mail.ovh.net",
        ]

    def test_preserves_priority_order(self):
        records = [
            self._rec(1, "a.one.example"),
            self._rec(2, "b.two.example"),
            self._rec(3, "c.three.example"),
            self._rec(4, "d.four.example"),
        ]
        selected = _select_probe_records(records)
        assert [r.exchange for r in selected] == [
            "a.one.example",
            "b.two.example",
            "c.three.example",
        ]

    def test_fewer_records_than_limit(self):
        records = [self._rec(10, "mail.example.com")]
        assert _select_probe_records(records) == records

    def test_empty(self):
        assert _select_probe_records([]) == []

    def test_custom_limit(self):
        records = [self._rec(i, f"mx{i}.example.com") for i in range(1, 5)]
        assert len(_select_probe_records(records, limit=2)) == 2

    def test_cctld_providers_treated_as_distinct(self):
        records = [
            self._rec(10, "mx1.acme.co.uk"),
            self._rec(20, "mx2.acme.co.uk"),
            self._rec(30, "mx1.othercorp.co.uk"),
        ]
        selected = _select_probe_records(records, limit=2)
        assert [r.exchange for r in selected] == [
            "mx1.acme.co.uk",
            "mx1.othercorp.co.uk",
        ]


class TestPrimaryIp:
    def test_prefers_ipv4(self):
        rec = MXRecord(
            priority=10,
            exchange="mail.example.com",
            ip_addresses=["2001:db8::1", "1.2.3.4"],
        )
        assert _primary_ip(rec) == "1.2.3.4"

    def test_falls_back_to_ipv6(self):
        rec = MXRecord(
            priority=10, exchange="mail.example.com", ip_addresses=["2001:db8::1"]
        )
        assert _primary_ip(rec) == "2001:db8::1"

    def test_no_addresses(self):
        rec = MXRecord(priority=10, exchange="mail.example.com", ip_addresses=[])
        assert _primary_ip(rec) is None


class TestAssess:
    def _patches(self):
        return dict(
            check_mx=make_mx_result(),
            check_spf=make_simple_result(SPFResult),
            check_dmarc=make_simple_result(DMARCResult),
            check_dkim=make_simple_result(DKIMResult),
            check_bimi=make_simple_result(BIMIResult),
            check_tlsrpt=make_simple_result(TLSRPTResult),
            check_mta_sts=make_simple_result(MTASTSResult),
        )

    def _ctx(self, extra=None):
        """Return a context manager that patches all check functions."""
        p = self._patches()
        if extra:
            p.update(extra)
        # patch.multiple needs callables; wrap plain objects in MagicMock(return_value=...)
        mocks = {}
        for k, v in p.items():
            if isinstance(v, MagicMock):
                mocks[k] = v
            else:
                mocks[k] = MagicMock(return_value=v)
        return patch.multiple("mailvalidator.assessor", **mocks)

    def test_returns_full_report(self):
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            report = assess("example.com")
        assert isinstance(report, MailReport)
        assert report.domain == "example.com"

    def test_progress_cb_called(self):
        calls = []
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            assess("example.com", progress_cb=calls.append)
        assert len(calls) > 0
        assert all(isinstance(c, str) for c in calls)

    def test_smtp_skipped_when_run_smtp_false(self):
        mock_smtp = MagicMock()
        with self._ctx(
            {
                "check_smtp": mock_smtp,
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            assess("example.com", run_smtp=False)
        mock_smtp.assert_not_called()

    def test_blacklist_skipped_when_run_blacklist_false(self):
        mock_bl = MagicMock()
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            assess("example.com", run_blacklist=False)
        mock_bl.assert_not_called()

    def test_smtp_called_for_at_most_three_mx(self):
        records = [
            MXRecord(
                priority=i * 10,
                exchange=f"mx{i}.example.com",
                ip_addresses=[f"1.2.3.{i}"],
            )
            for i in range(1, 5)
        ]
        mock_smtp = MagicMock(return_value=MagicMock())
        with self._ctx(
            {
                "check_smtp": mock_smtp,
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                assess("example.com")
        assert mock_smtp.call_count == 3

    def test_blacklist_uses_first_mx_ip(self):
        records = [
            MXRecord(priority=10, exchange="mail.example.com", ip_addresses=["9.9.9.9"])
        ]
        mock_bl = MagicMock(return_value=MagicMock())
        mock_smtp = MagicMock(return_value=MagicMock())
        with self._ctx({"check_smtp": mock_smtp, "check_blacklist": mock_bl}):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                assess("example.com")
        mock_bl.assert_called_once_with("9.9.9.9", max_workers=50)

    def test_blacklist_checks_one_ip_per_provider(self):
        records = [
            MXRecord(
                priority=1, exchange="aspmx.l.google.com", ip_addresses=["1.1.1.1"]
            ),
            MXRecord(
                priority=5,
                exchange="alt1.aspmx.l.google.com",
                ip_addresses=["2.2.2.2"],
            ),
            MXRecord(
                priority=50, exchange="mx2.mail.ovh.net", ip_addresses=["3.3.3.3"]
            ),
        ]
        mock_bl = MagicMock(return_value=MagicMock())
        with self._ctx(
            {"check_smtp": MagicMock(return_value=MagicMock()), "check_blacklist": mock_bl}
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                report = assess("example.com")
        checked = {call.args[0] for call in mock_bl.call_args_list}
        assert checked == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
        assert len(report.blacklist) == 3
        # The DNSBL thread budget is split across the three targets.
        assert all(
            call.kwargs["max_workers"] == 16 for call in mock_bl.call_args_list
        )

    def test_blacklist_deduplicates_shared_ips(self):
        records = [
            MXRecord(priority=10, exchange="mx1.example.com", ip_addresses=["9.9.9.9"]),
            MXRecord(priority=20, exchange="mx2.example.com", ip_addresses=["9.9.9.9"]),
        ]
        mock_bl = MagicMock(return_value=MagicMock())
        with self._ctx(
            {"check_smtp": MagicMock(return_value=MagicMock()), "check_blacklist": mock_bl}
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                assess("example.com")
        mock_bl.assert_called_once_with("9.9.9.9", max_workers=50)

    def test_one_failing_blacklist_target_does_not_discard_report(self):
        records = [
            MXRecord(
                priority=1, exchange="aspmx.l.google.com", ip_addresses=["1.1.1.1"]
            ),
            MXRecord(
                priority=50, exchange="mx2.mail.ovh.net", ip_addresses=["3.3.3.3"]
            ),
        ]
        ok_result = MagicMock()
        mock_bl = MagicMock(side_effect=[ok_result, RuntimeError("resolver down")])
        with self._ctx(
            {"check_smtp": MagicMock(return_value=MagicMock()), "check_blacklist": mock_bl}
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                report = assess("example.com")
        assert report.blacklist == [ok_result]
        assert isinstance(report, MailReport)

    def test_smtp_receives_resolved_mx_ip(self):
        records = [
            MXRecord(priority=10, exchange="mail.example.com", ip_addresses=["9.9.9.9"])
        ]
        mock_smtp = MagicMock(return_value=MagicMock())
        with self._ctx(
            {
                "check_smtp": mock_smtp,
                "check_blacklist": MagicMock(return_value=MagicMock()),
            }
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                assess("example.com")
        mock_smtp.assert_called_once_with("mail.example.com", 25, ip="9.9.9.9")

    def test_blacklist_falls_back_to_a_record(self):
        """When MX has no IPv4 IPs, blacklist uses gethostbyname(domain)."""
        mock_bl = MagicMock(return_value=MagicMock())
        # make_mx_result() returns empty records → no IPv4 → fallback path
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            with patch(
                "mailvalidator.assessor.socket.gethostbyname", return_value="3.3.3.3"
            ):
                assess("example.com")
        mock_bl.assert_called_once_with("3.3.3.3", max_workers=50)

    def test_blacklist_skip_is_recorded_when_gethostbyname_fails(self):
        mock_bl = MagicMock()
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            with patch(
                "mailvalidator.assessor.socket.gethostbyname",
                side_effect=_socket.gaierror("no address"),
            ):
                report = assess("example.com")
        mock_bl.assert_not_called()
        # The skip is recorded, never silent.
        assert len(report.blacklist) == 1
        skip = report.blacklist[0].checks[0]
        assert skip.name == "Blacklist Status"
        assert skip.value == "skipped"
        assert report.blacklist[0].total_checked == 0

    def test_blacklist_falls_back_to_domain_a_when_mx_targets_dangling(self):
        """MX records exist but none resolve (dangling MX) → fall back to the
        domain's own A record instead of silently skipping (0.3.0 regression)."""
        records = [
            MXRecord(
                priority=0,
                exchange="dead.mail.protection.example",
                ip_addresses=[],
            )
        ]
        mock_bl = MagicMock(return_value=MagicMock())
        with self._ctx(
            {
                "check_smtp": MagicMock(return_value=MagicMock()),
                "check_blacklist": mock_bl,
            }
        ):
            with patch(
                "mailvalidator.assessor.check_mx", return_value=make_mx_result(records)
            ):
                with patch(
                    "mailvalidator.assessor.socket.gethostbyname",
                    return_value="7.7.7.7",
                ):
                    assess("example.com")
        mock_bl.assert_called_once_with("7.7.7.7", max_workers=50)
