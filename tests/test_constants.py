"""Tests for mailvalidator/constants.py."""

from __future__ import annotations

from mailvalidator.constants import (
    DNS_TIMEOUT,
    HTTP_TIMEOUT,
    SMTP_DEFAULT_PORT,
    SMTP_TIMEOUT,
)


class TestConstants:
    def test_smtp_default_port(self):
        assert SMTP_DEFAULT_PORT == 25

    def test_dns_timeout(self):
        assert DNS_TIMEOUT == 5.0

    def test_smtp_timeout(self):
        assert SMTP_TIMEOUT == 10.0

    def test_http_timeout(self):
        assert HTTP_TIMEOUT == 10.0
