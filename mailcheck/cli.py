"""mailcheck CLI – mail server configuration assessment."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from mailcheck import __version__
from mailcheck.assessor import assess
from mailcheck.checks.bimi import check_bimi
from mailcheck.checks.blacklist import check_blacklist
from mailcheck.checks.dkim import check_dkim
from mailcheck.checks.dmarc import check_dmarc
from mailcheck.checks.mta_sts import check_mta_sts
from mailcheck.checks.mx import check_mx
from mailcheck.checks.smtp import check_smtp
from mailcheck.checks.spf import check_spf
from mailcheck.checks.tlsrpt import check_tlsrpt
from mailcheck.reporter import (
    print_bimi,
    print_blacklist,
    print_dkim,
    print_dmarc,
    print_full_report,
    print_mta_sts,
    print_mx,
    print_smtp,
    print_spf,
    print_tlsrpt,
)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="mailcheck",
    help="Assess mail server configuration: MX, SPF, DKIM, DMARC, BIMI, TLSRPT, MTA-STS, blacklists and more.",
    add_completion=False,
)

# ---------------------------------------------------------------------------
# Input validators
# ---------------------------------------------------------------------------

# A valid fully-qualified domain name: at least two labels, each 1-63 chars,
# optional trailing dot.  Single-label names (e.g. "localhost") are rejected.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}\.?$"
)

# A hostname or bare IP: accepts single-label names (e.g. "mailserver") as
# well as fully-qualified hostnames, because `smtp` targets need not be FQDNs.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"(?:[a-zA-Z0-9-]{1,63})\.?$"
)


def _validate_domain(value: str) -> str:
    """Reject input that is not a valid domain name (requires ≥2 DNS labels)."""
    if not _DOMAIN_RE.match(value):
        raise typer.BadParameter(f"'{value}' is not a valid domain name")
    return value


def _validate_host(value: str) -> str:
    """Accept a bare IPv4/IPv6 address or a hostname / domain name."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(value):
        raise typer.BadParameter(f"'{value}' is not a valid IP address or hostname")
    return value


def _validate_ip(value: str) -> str:
    """Reject input that is not a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise typer.BadParameter(f"'{value}' is not a valid IP address")


# ---------------------------------------------------------------------------
# App-level callback (--version flag)
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mailcheck {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """mailcheck – Mail server configuration assessment."""


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


@app.command("check")
def cmd_check(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name to assess.", callback=_validate_domain),
    ],
    smtp_port: Annotated[
        int,
        typer.Option("--smtp-port", help="SMTP port to probe."),
    ] = 25,
    no_smtp: Annotated[
        bool,
        typer.Option("--no-smtp", help="Skip SMTP diagnostics."),
    ] = False,
    no_blacklist: Annotated[
        bool,
        typer.Option("--no-blacklist", help="Skip DNS blacklist check."),
    ] = False,
) -> None:
    """Run all mail server checks for DOMAIN and print a full report."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        def _progress_cb(msg: str) -> None:
            progress.update(task, description=msg)

        report = assess(
            domain,
            smtp_port=smtp_port,
            run_smtp=not no_smtp,
            run_blacklist=not no_blacklist,
            progress_cb=_progress_cb,
        )

    print_full_report(report)


# ---------------------------------------------------------------------------
# Individual sub-commands
# ---------------------------------------------------------------------------


@app.command("mx")
def cmd_mx(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Look up MX records for DOMAIN."""
    print_mx(check_mx(domain))


@app.command("smtp")
def cmd_smtp(
    host: Annotated[
        str,
        typer.Argument(
            help="Mail server hostname or IP address.", callback=_validate_host
        ),
    ],
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="SMTP port."),
    ] = 25,
) -> None:
    """Run SMTP diagnostics against HOST."""
    print_smtp([check_smtp(host, port=port)])


@app.command("spf")
def cmd_spf(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Look up and validate the SPF record for DOMAIN."""
    print_spf(check_spf(domain))


@app.command("dmarc")
def cmd_dmarc(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Look up and validate the DMARC record for DOMAIN."""
    print_dmarc(check_dmarc(domain))


@app.command("dkim")
def cmd_dkim(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Look up and validate the DKIM record for DOMAIN."""
    print_dkim(check_dkim(domain))


@app.command("bimi")
def cmd_bimi(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Look up and validate the BIMI record for DOMAIN."""
    print_bimi(check_bimi(domain))


@app.command("tlsrpt")
def cmd_tlsrpt(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Check the SMTP TLS Reporting (TLSRPT) record for DOMAIN."""
    print_tlsrpt(check_tlsrpt(domain))


@app.command("mta-sts")
def cmd_mta_sts(
    domain: Annotated[
        str,
        typer.Argument(help="Domain name.", callback=_validate_domain),
    ],
) -> None:
    """Check the MTA-STS DNS record and policy file for DOMAIN."""
    print_mta_sts(check_mta_sts(domain))


@app.command("blacklist")
def cmd_blacklist(
    ip: Annotated[
        str,
        typer.Argument(help="IPv4 or IPv6 address to check.", callback=_validate_ip),
    ],
    workers: Annotated[
        int,
        typer.Option("--workers", "-w", help="Number of parallel DNS workers."),
    ] = 50,
) -> None:
    """Check IP against 100+ DNS blacklists."""
    print_blacklist(check_blacklist(ip, max_workers=workers))


if __name__ == "__main__":
    app()
