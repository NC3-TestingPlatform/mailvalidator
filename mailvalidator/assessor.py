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
from mailvalidator.models import (
    BlacklistResult,
    CheckResult,
    MailReport,
    MXRecord,
    Status,
)

logger = logging.getLogger("mailvalidator")


# Common multi-label public suffixes under which the registrable domain is
# three labels long (e.g. "acme.co.uk").  Not a full Public Suffix List —
# a pragmatic subset covering the ccTLDs most often seen in MX hostnames.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
    "co.za", "co.in", "co.kr", "co.id", "co.th",
    "com.pl", "com.ua", "in.ua",
})

# Total concurrent DNSBL query threads across all blacklist targets.
_BLACKLIST_TOTAL_WORKERS = 50


def _provider_zone(exchange: str) -> str:
    """Return a coarse provider-zone key for an MX exchange hostname.

    Uses the registrable domain as a heuristic for the operating mail
    provider so probe selection can cover distinct providers rather than
    several hosts of the same one: the last two DNS labels
    (``"aspmx.l.google.com"`` → ``"google.com"``), or the last three when
    the two-label tail is a known multi-label public suffix
    (``"mx1.acme.co.uk"`` → ``"acme.co.uk"``).  :data:`_MULTI_LABEL_SUFFIXES`
    is a pragmatic subset of the Public Suffix List, not a replacement.

    :param exchange: MX exchange hostname.
    :type exchange: str
    :returns: Lower-case provider-zone key.
    :rtype: str
    """
    labels = exchange.rstrip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else exchange.lower()


def _select_probe_records(records: list[MXRecord], limit: int = 3) -> list[MXRecord]:
    """Pick up to *limit* MX records covering distinct provider zones.

    Records are examined in priority order.  A first pass keeps one record
    per provider zone so backup MX hosts run by a different provider (often
    the weakest link) are always probed; remaining slots are then filled by
    priority.  The returned list preserves the original priority order.

    :param records: MX records sorted by priority (ascending).
    :type records: list[~mailvalidator.models.MXRecord]
    :param limit: Maximum number of records to select.
    :type limit: int
    :returns: Selected records in priority order.
    :rtype: list[~mailvalidator.models.MXRecord]
    """
    selected: set[int] = set()
    seen_zones: set[str] = set()
    for idx, rec in enumerate(records):  # one host per provider zone first
        if len(selected) >= limit:
            break
        zone = _provider_zone(rec.exchange)
        if zone not in seen_zones:
            seen_zones.add(zone)
            selected.add(idx)
    for idx in range(len(records)):  # fill remaining slots by priority
        if len(selected) >= limit:
            break
        selected.add(idx)
    return [records[i] for i in sorted(selected)]


def _primary_ip(rec: MXRecord) -> str | None:
    """Return the first IPv4 address of *rec*, falling back to any address.

    :param rec: MX record with resolved addresses.
    :type rec: ~mailvalidator.models.MXRecord
    :returns: Preferred address string, or ``None`` when the record has none.
    :rtype: str or None
    """
    for ip in rec.ip_addresses:
        if "." in ip:  # simple IPv4 filter
            return ip
    return rec.ip_addresses[0] if rec.ip_addresses else None


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
    :param run_blacklist: When ``True`` (default), check one MX IP per
        distinct mail provider (up to three) against 100+ DNSBLs.  This step
        is parallelised but can take up to ~30 s on slow networks.
    :param run_smtp: When ``True`` (default), probe up to three MX servers —
        selected to cover distinct mail providers — via SMTP and STARTTLS.
        Requires outbound TCP access to *smtp_port*.
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

    # Submit blacklist checks immediately — they take ~30 s and only need the
    # MX IPs, available now.  One IP per selected provider zone is checked so
    # backup MX hosts of a different provider are covered too.  Runs
    # concurrently with all remaining checks.
    _bl_pool = None
    _bl_futures: list[Any] = []
    if run_blacklist:
        _bl_targets: list[str] = []
        _bl_fallback_note: str | None = None
        if report.mx and report.mx.records:
            for _rec in _select_probe_records(report.mx.records):
                _ip = _primary_ip(_rec)
                if _ip and _ip not in _bl_targets:
                    _bl_targets.append(_ip)
        if not _bl_targets:
            # No MX records, or none of the MX targets resolve (dangling MX)
            # — fall back to the domain's own address record.  The note makes
            # the report self-explanatory about whose IP is being checked.
            try:
                _fallback_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                _fallback_ip = None
            if _fallback_ip:
                _bl_targets = [_fallback_ip]
                if report.mx and report.mx.records:
                    _bl_fallback_note = (
                        f"{_fallback_ip} is the domain's own A record, checked "
                        "as a fallback because no MX target resolves. RFC 5321 "
                        "implicit-MX does not apply when an MX record exists, "
                        "so this IP is not in the actual mail path."
                    )
                else:
                    _bl_fallback_note = (
                        f"{_fallback_ip} is the domain's own A record — the "
                        "implicit MX destination (RFC 5321 §5.1) since the "
                        "domain publishes no MX records."
                    )
        if not _bl_targets:
            # Never skip silently: record why no DNSBL lookup ran.
            _skipped = BlacklistResult(ip=domain, total_checked=0)
            _skipped.checks.append(
                CheckResult(
                    name="Blacklist Status",
                    status=Status.NA,
                    value="skipped",
                    details=[
                        "No resolvable MX target IP and no A record for the "
                        "domain itself; DNSBL check skipped."
                    ],
                )
            )
            report.blacklist.append(_skipped)
        if _bl_targets:
            _cb(f"Blacklist check on {', '.join(_bl_targets)} (running in background…)")
            # Split the global DNSBL thread budget across targets so fanning
            # out to several IPs does not multiply the total thread count.
            _bl_workers = max(1, _BLACKLIST_TOTAL_WORKERS // len(_bl_targets))
            _bl_pool = ThreadPoolExecutor(max_workers=len(_bl_targets))
            _bl_futures = [
                (t, _bl_pool.submit(check_blacklist, t, max_workers=_bl_workers))
                for t in _bl_targets
            ]

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
        _mx_to_probe = _select_probe_records(report.mx.records)
        with ThreadPoolExecutor(max_workers=len(_mx_to_probe)) as _smtp_pool:
            _smtp_futures = [
                _smtp_pool.submit(
                    check_smtp, rec.exchange, smtp_port, ip=_primary_ip(rec)
                )
                for rec in _mx_to_probe
            ]
            report.smtp = [f.result() for f in _smtp_futures]

    # Collect blacklist results (started right after MX; likely already done).
    # One failing target must not discard the rest of the report.
    if _bl_futures and _bl_pool is not None:
        for _target, _fut in _bl_futures:
            try:
                _bl_result = _fut.result()
            except Exception:
                logger.warning(
                    "Blacklist check failed for %s; skipping this target",
                    _target,
                    exc_info=True,
                )
                continue
            if _bl_fallback_note:
                for _chk in _bl_result.checks:
                    _chk.details.append(_bl_fallback_note)
            report.blacklist.append(_bl_result)
        _bl_pool.shutdown(wait=False)

    return report
