"""High-level assessment API – orchestrates all per-domain checks.

Typical usage::

    from mailvalidator.assessor import assess

    report = assess("example.com", progress_cb=print)
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from mailvalidator.checks.bimi import check_bimi
from mailvalidator.checks.blacklist import check_blacklist
from mailvalidator.checks.dkim import check_dkim
from mailvalidator.checks.dmarc import check_dmarc
from mailvalidator.checks.dnssec import check_dnssec_domain, check_dnssec_mx
from mailvalidator.checks.mta_sts import check_mta_sts
from mailvalidator.checks.mx import check_mx
from mailvalidator.checks.smtp import check_smtp
from mailvalidator.checks.spf import check_spf
from mailvalidator.checks.tlsrpt import check_tlsrpt
from mailvalidator.models import MailReport, MXRecord

logger = logging.getLogger("mailvalidator")


def _resolve_mx_ips(records: list[MXRecord]) -> list[str]:
    """Return unique IPv4 addresses collected from a list of MX records.

    :param records: MX records to extract IP addresses from.
    :returns: Deduplicated list of IPv4 address strings.
    :rtype: list[str]
    """
    ips: list[str] = []
    for rec in records:
        for ip in rec.ip_addresses:
            if ip not in ips and "." in ip:  # simple IPv4 filter
                ips.append(ip)
    return ips


def assess(
    domain: str,
    *,
    smtp_port: int = 25,
    run_blacklist: bool = True,
    run_smtp: bool = True,
    run_dnssec: bool = True,
    progress_cb: Callable[[str], None] | None = None,
    timeout: float = 5.0,
) -> MailReport:
    """Run all mail server checks for *domain* and return a :class:`~mailvalidator.models.MailReport`.

    :param domain: The target domain name to assess (e.g. ``"example.com"``).
    :param smtp_port: TCP port used for SMTP diagnostics.  Defaults to ``25``.
    :param run_blacklist: When ``True`` (default), check the first MX IP
        against 100+ DNSBLs.  This step is parallelised but can take up to
        ~30 s on slow networks.
    :param run_smtp: When ``True`` (default), probe each MX server via SMTP
        and STARTTLS.  Requires outbound TCP access to *smtp_port*.
    :param run_dnssec: When ``True`` (default), validate the DNSSEC chain of
        trust for the email address domain and each MX server domain.
    :param progress_cb: Optional callable invoked with a short status string
        before each check group.  Useful for driving a progress spinner in
        the CLI.
    :param timeout: DNS/network timeout in seconds.  Defaults to ``5.0``.
    :returns: Populated :class:`~mailvalidator.models.MailReport`; individual
        fields are ``None`` when the corresponding check was skipped.
    :rtype: ~mailvalidator.models.MailReport
    """

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    report = MailReport(domain=domain)

    _cb("Checking MX records…")
    report.mx = check_mx(domain, timeout=timeout)

    # Submit blacklist immediately — it takes ~30 s and only needs the first
    # MX IP, available now.  Runs concurrently with all remaining checks.
    _bl_pool = None
    _bl_future = None
    if run_blacklist:
        _bl_mx_ips = _resolve_mx_ips(report.mx.records) if report.mx else []
        if _bl_mx_ips:
            _bl_target: str | None = _bl_mx_ips[0]
        else:
            try:
                _bl_target = socket.gethostbyname(domain)
            except socket.gaierror:
                _bl_target = None
        if _bl_target:
            _cb(f"Blacklist check on {_bl_target} (running in background…)")
            _bl_pool = ThreadPoolExecutor(max_workers=1)
            _bl_future = _bl_pool.submit(check_blacklist, _bl_target)

    _cb("Checking DNS records (SPF, DMARC, DKIM, BIMI, TLSRPT, MTA-STS, DNSSEC) in parallel…")
    _dns_tasks: dict[str, Any] = {
        "spf":     lambda: check_spf(domain),
        "dmarc":   lambda: check_dmarc(domain),
        "dkim":    lambda: check_dkim(domain),
        "bimi":    lambda: check_bimi(domain),
        "tlsrpt":  lambda: check_tlsrpt(domain),
        "mta_sts": lambda: check_mta_sts(domain, timeout=timeout),
    }
    if run_dnssec:
        _dns_tasks["dnssec_domain"] = lambda: check_dnssec_domain(domain, timeout=timeout)
        if report.mx and report.mx.records:
            _dnssec_mx_domains = [r.exchange for r in report.mx.records]
            _dns_tasks["dnssec_mx"] = lambda: check_dnssec_mx(_dnssec_mx_domains, email_domain=domain, timeout=timeout)
    with ThreadPoolExecutor(max_workers=len(_dns_tasks)) as _pool:
        _futures: dict[Any, str] = {_pool.submit(fn): attr for attr, fn in _dns_tasks.items()}
        for _fut in as_completed(_futures):
            setattr(report, _futures[_fut], _fut.result())

    if run_smtp and report.mx and report.mx.records:
        _mx_to_probe = report.mx.records[:3]
        with ThreadPoolExecutor(max_workers=len(_mx_to_probe)) as _smtp_pool:
            _smtp_futures = [
                _smtp_pool.submit(check_smtp, rec.exchange, smtp_port)
                for rec in _mx_to_probe
            ]
            report.smtp = [f.result() for f in _smtp_futures]

    # Collect blacklist result (started right after MX; likely already done).
    if _bl_future is not None and _bl_pool is not None:
        report.blacklist = _bl_future.result()
        _bl_pool.shutdown(wait=False)

    return report
