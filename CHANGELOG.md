# Changelog

All notable changes to **mailvalidator** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.2.6] — 2026-06-24

### Changed
- `checks/smtp/_check`: removed the separate `SMTP Port Fallback` check row.
  When port 25 is unreachable and a fallback port (587 or 465) succeeds, the
  fallback detail (`Port 25 unreachable; fell back to port <N>.`) is appended
  to the `SMTP Connect` check description instead of appearing as its own row.

---

## [0.2.5] — 2026-06-24

### Fixed
- `checks/smtp/_tls_checks`: all key-exchange check results now use the
  single consistent name `Key Exchange` (previously four variants existed:
  `Key Exchange – EC Curve`, `Key Exchange – Group`, `Key Exchange – DH Group`,
  and `Key Exchange`).  The mechanism (`ECDHE (x25519)`,
  `Hybrid KEM (X25519MLKEM768)`, `DHE – 3072 bit`, `RSA (…)`) is shown in the
  `value` field.
- `checks/smtp/_tls_checks`: when TLS 1.3 negotiates a PQC hybrid key-exchange
  group (e.g. `X25519MLKEM768`), the value is now `Hybrid KEM (X25519MLKEM768)`
  instead of the misleading `ECDHE (X25519MLKEM768)`.  PQC hybrid groups are
  KEMs (X25519 + ML-KEM-768), not EC curves, and the key exchange is not ECDHE.
- `CHANGELOG.md`: removed duplicate `[Unreleased]` comparison link introduced
  in v0.2.3.

---

## [0.2.4] — 2026-06-24

### Fixed
- `checks/smtp/_classify`: PQC hybrid key-exchange groups (`X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) were incorrectly classified as
  `INSUFFICIENT`.  They are now rated `GOOD` — the highest tier — per NIST
  FIPS 203 (2024), CNSA 2.0, and BSI TR-02102-2.  The draft alias
  `X25519Kyber768Draft00` (OpenSSL 3.2/3.3, codepoint `0xfe30`) is also
  treated as `GOOD` to avoid false negatives on servers that have not yet
  upgraded to OpenSSL ≥ 3.4.
- `checks/smtp/_tls_checks`: PHASE_OUT and INSUFFICIENT key-exchange detail
  messages now recommend `X25519MLKEM768` as the preferred group alongside
  the classical `x25519`/`secp256r1` options.

---

## [0.2.3] — 2026-06-19

### Fixed
- Bumped `vendor/quantumvalidator` submodule to v0.6.0 so that
  `quantumvalidator.tls_utils.probe_raw` is present at runtime.  The prior
  vendor pointer (v0.5.2) caused an `ImportError` when running
  `mailvalidator check <domain>`.

---

## [0.2.2] — 2026-06-19

### Changed
- `checks/smtp/_tls_probe`: `_probe_openssl_combined` now delegates its
  subprocess invocation to `quantumvalidator.tls_utils.probe_raw` instead of
  calling `openssl s_client` directly.  The SSRF guard (private/loopback/RFC
  6598 IP rejection) is retained in mailvalidator.  The vendored
  `quantumvalidator` is bumped to v0.6.0 which adds `probe_raw`.
- `checks/smtp/_tls_probe`: Merged the separate `_probe_zero_rtt` and
  `_assess_pqc` openssl subprocess calls into a single
  `_probe_openssl_combined` call per MX host.  One `openssl s_client -starttls
  smtp -ign_eof -groups <PQC_GROUPS>` invocation now captures both
  `Max Early Data:` (0-RTT) and `Negotiated TLS1.3 group:` (PQC), halving the
  number of subprocesses and up to halving the extra wall-clock latency per MX
  host (saved ≤ 10 s per host).
- `checks/smtp/_tls_checks`: `_check_zero_rtt` now accepts a pre-computed
  `accepted: bool | None` instead of `(host, port, sni_hostname)`.
- `checks/smtp/_pqc`: `_check_pqc` now accepts a pre-computed
  `negotiated_group: str | None` and `probe_available: bool` instead of
  calling `_assess_pqc` internally; `_assess_pqc` is preserved for direct use.

### Fixed
- `checks/smtp/_tls_probe`: SSRF guard in `_probe_openssl_combined` now uses
  `not ip.is_global` instead of the three-predicate check, blocking RFC 6598
  Shared Address Space (`100.64.0.0/10`) and IPv4 multicast (`224.0.0.0/4`)
  in addition to the already-blocked private/loopback/link-local ranges.
- `checks/smtp/_tls_probe`: Replaced magic `timeout=10` literal in the
  `subprocess.run` call with the `_TIMEOUT` constant imported from
  `_connection.py`.
- `checks/smtp/_tls_probe`: `_probe_openssl_combined` docstring now documents
  the STARTTLS-only constraint (ports 25/587; not suitable for implicit-TLS
  port 465) and casts `_TIMEOUT` to `float` at the `probe_raw` call site to
  match the `float`-annotated parameter.
- `checks/smtp/_tls_probe`: inline comment added to SSRF guard explaining that
  `not ip.is_global` also covers RFC 6598 shared address space and
  documentation ranges beyond the RFC 1918/loopback/link-local set.
- `tests/checks/test_smtp.py`: `TestProbeZeroRTT` and `TestProbeOpenSSLCombined`
  docstrings now explain why `quantumvalidator.tls_utils.probe_raw` is the
  correct patch target (function-body import — patching the module attribute
  intercepts the call; a module-level name does not exist to patch).

---

## [0.2.1] — 2026-06-19

### Fixed
- `checks/smtp/_tls_probe`: `_probe_zero_rtt` now sends the correct SNI hostname
  via `openssl s_client -servername`; previously the flag was absent, causing
  multi-certificate SMTP servers to present the wrong leaf certificate.
- `checks/smtp/_tls_probe`: Added a private/loopback/link-local IP guard;
  literal private IP addresses are rejected before the subprocess is spawned,
  preventing SSRF via attacker-controlled MX records.
- `checks/smtp/_tls_probe`: TLS 1.3 fallback detection is now scoped to output
  lines containing both `"Protocol"` and `"TLSv1.3"`, preventing a false `False`
  result when `"TLSv1.3"` appears only in an error message.  A non-zero
  `openssl` exit code also suppresses the fallback so partial output from a
  crashed probe does not produce a misleading "not accepted" verdict.
- `checks/smtp/_tls_probe`: Removed dead `IndexError` from the `Max Early Data:`
  parser's except clause; `split(":", 1)` always produces two parts so only
  `ValueError` is reachable.
- `checks/smtp/_tls_probe`: Subprocess timeout reduced from 15 s to 10 s to
  limit worst-case per-MX latency.
- `checks/smtp/_tls_probe` / `_tls_checks`: Removed dead `helo_domain` parameter;
  `_probe_zero_rtt` now accepts `sni_hostname` (keyword-only, default `None`) and
  `_check_zero_rtt` passes it through from the call site in `_check.py`.

### Tests
- `TestProbeZeroRTT`: added `test_returns_none_on_oserror` — verifies
  `subprocess.run` raising `OSError` returns `None`.
- `TestProbeZeroRTT`: added `test_sni_hostname_adds_servername_flag` — verifies
  that a non-`None` `sni_hostname` inserts `-servername <host>` into the openssl
  command.
- `TestProbeZeroRTT`: added `test_returns_none_for_private_ip` — verifies that a
  private IP address (e.g. `192.168.1.1`) is blocked before the subprocess is
  spawned.

---

## [0.2.0] — 2026-06-19

### Added
- `checks/smtp/_tls_probe`: `_probe_zero_rtt(host, port, helo_domain)` — detects
  TLS 1.3 early data (0-RTT) support by running `openssl s_client -starttls smtp`
  and parsing the `Max Early Data:` value from the `NewSessionTicket` block.
  Returns `True` (0-RTT accepted), `False` (not accepted / TLS 1.3 but no early
  data), or `None` (openssl binary absent or probe failed).
- `checks/smtp/_tls_checks`: `_check_zero_rtt(host, port, helo_domain, details,
  checks)` — emits `WARNING` when `max_early_data_size > 0` (replay-attack risk,
  RFC 8446 §8), `GOOD` when not accepted, `INFO` when probe unavailable, `NA`
  for TLS < 1.3.  Registered as `VerdictSeverity.MEDIUM` in `verdict.py`.
- `checks/smtp/_pqc`: new `_check_pqc_certificate` check — detects whether the
  mail server certificate uses a post-quantum signature algorithm (ML-DSA, SLH-DSA,
  FN-DSA) by parsing the `signatureAlgorithm` OID against NIST FIPS 204/205 and
  provisional IETF/OQS OIDs.  Classical certs (RSA/ECDSA) yield `INFO` — no grade
  penalty since PQC certs are not yet widely issued by public CAs.  OID table
  (`_PQC_SIG_OIDS`) exported for tests and external consumers.
- `checks/smtp/_tls_probe`: TLS 1.3 key-exchange group detection via pyOpenSSL
  (`SSL_get0_group_name`).  A dedicated STARTTLS probe using `OpenSSL.SSL.Connection`
  runs as a fallback when the stdlib `ssl` module does not expose the group (current
  Python/OpenSSL builds).  `pyopenssl>=24.3` added as a runtime dependency.

---

## [0.1.8] — 2026-05-15

### Added
- `mailvalidator/constants.py` — new module exposing `SMTP_DEFAULT_PORT`,
  `DNS_TIMEOUT`, `SMTP_TIMEOUT`, and `HTTP_TIMEOUT` constants, consistent
  with the platform-wide `constants.py` convention.
- `pytest-mock>=3.12` added to dev extras.

### Changed
- `models`: `FullReport` deprecated alias removed; use `MailReport` directly.
- `assessor`: `assess()` parameters after the first positional are now
  keyword-only (enforced by `*,`); logger moved below all imports to fix
  E402 linting errors.
- `cli`: `check` command gains a `--timeout / -T` option (default `5.0 s`);
  exit code `1` is now raised when the calculated grade is D or F.
- `reporter`: console renamed to private `_console` with a public alias;
  `Console` created with `highlight=False`; all `print_*` functions accept
  `*, console: Console | None = None`; `save_report()` always writes from
  `_console`.
- `print_verdict` signature changed from `(actions, grade)` to
  `(report, *, console=None)` — verdict actions and grade are now extracted
  internally, consistent with all other platform modules.
- `verdict`: `VerdictSeverity` gains `LOW` (1 pt penalty) and `INFO`
  (0 pt penalty) members, aligning the enum with `headersvalidator`.

---

## [0.1.7] — 2026-05-15

### Changed
- `__init__`: added `NullHandler` on the `"mailvalidator"` logger so library
  users do not see spurious "No handler found" warnings (consistent with all
  other platform modules).
- CLI: internal variable `as_json` renamed to `json_output` across all
  sub-commands, aligning with the platform-wide naming convention.

---

## [0.1.6] — 2026-04-30

### Added
- **PQC Key Exchange check** — the TLS section now reports post-quantum
  cryptography readiness for each SMTP server. Uses the vendored
  `quantumvalidator` module (same pattern as `chainvalidator`) to probe
  whether a PQC hybrid key exchange group (e.g. X25519MLKEM768) was
  negotiated. Result status: `GOOD` (PQC-ready), `WARNING` (classical
  key exchange only), or `INFO` (probe unavailable — requires OpenSSL ≥ 3.0).
  Appears as a MEDIUM verdict action when the server is not PQC-ready.
- **`quantumvalidator` vendored dependency** — added as a git submodule
  under `vendor/quantumvalidator` (CNSA 2.0, BSI TR-02102-2 standards).

---

## [0.1.5] — 2026-04-29

### Added
- **SMTP port fallback** — when port 25 is refused, times out, or drops the
  connection after the TCP handshake (banner-read timeout), the tool now
  automatically retries on port **587** (RFC 6409 Mail Submission) and then
  port **465** (RFC 8314 Implicit-TLS SMTP) before reporting failure.
- New `SMTP Port Fallback` (`INFO`) check result records which fallback port
  was actually used, visible in both the terminal report and `--json` output.

### Fixed
- `smtplib.SMTPServerDisconnected` exceptions (e.g. "Connection unexpectedly
  closed: timed out") now correctly trigger the port fallback instead of
  failing immediately without retrying.

### Changed
- `check_smtp` docstring updated to document the automatic port-retry
  behaviour.
- `SMTP Connect` CRITICAL entry in `docs/SECURITY_VERDICT.md` updated to
  describe the three-port probe sequence; new `SMTP Port Fallback` INFO entry
  added.
- `README.md` SMTP check section updated to describe the port fallback.

### Tests
- `TestConnectOrFallback` — 8 new unit tests covering all fallback branches:
  primary success, fallback to 587, fallback to 465, all-ports-fail,
  non-refusal `OSError` (no retry), `TimeoutError`, `SMTPServerDisconnected`,
  and empty-fallback-tuple guard.

---

## [0.1.4] — 2026-04-08

### Added
- `--json` flag on all CLI sub-commands (`check`, `smtp`, `spf`, `dmarc`,
  `dkim`, `bimi`, `tlsrpt`, `mta-sts`, `blacklist`, `dnssec`) — prints the
  full result as machine-readable JSON to stdout.

### Fixed
- Verdict panel no longer emits cipher-suite or cipher-order action items for
  deprecated TLS versions (TLS 1.0/1.1); those issues are already covered by
  the TLS-version action.

### Changed
- Repository moved to the
  [NC3-TestingPlatform](https://github.com/NC3-TestingPlatform) GitHub
  organisation; all internal URLs updated.
- `vendor/chainvalidator` declared as a local path dependency in
  `pyproject.toml`.

---

## [0.1.3] — 2026-03-30

### Added
- `docs/SECURITY_VERDICT.md` — CISO-facing reference explaining the
  penalty-point grading model and the rationale for each check's severity.

### Changed
- Terminal reporter: check tables wrapped in Rich panels with `ROUNDED` style;
  inner SMTP section panels use `bright_white`/`white` colour scheme for
  readability.
- Security Verdict panel aligned with headersvalidator style (consistent
  cross-tool look).

---

## [0.1.0] — 2026-03-13

### Added
- Initial release of **mailvalidator**.
- Checks: MX records, SPF, DMARC, DKIM base node, BIMI, TLSRPT, MTA-STS,
  SMTP diagnostics (Protocol, TLS, Certificate, DNS sections), 104 DNSBL
  blacklist zones, DNSSEC chain-of-trust.
- Deep TLS inspection: TLS 1.0–1.3 version probing, 34 cipher suites graded
  per NCSC-NL guidelines, cipher order enforcement, ECDHE/DHE/RSA key
  exchange, CRIME compression, RFC 5746 renegotiation.
- DNS checks per MX server: reverse PTR, CAA, DANE/TLSA.
- CLI entry points: `mailvalidator check`, `mailvalidator smtp`,
  `mailvalidator spf`, `mailvalidator dmarc`, `mailvalidator dkim`,
  `mailvalidator bimi`, `mailvalidator tlsrpt`, `mailvalidator mta-sts`,
  `mailvalidator blacklist`, `mailvalidator dnssec`.
- `--output` flag for `.txt` / `.svg` / `.html` report export.
- 685 unit tests, 100% coverage.

---

[Unreleased]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.6...HEAD
[0.2.6]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.8...v0.2.0
[0.1.8]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/NC3-TestingPlatform/mailvalidator/compare/v0.1.0...v0.1.3
[0.1.0]: https://github.com/NC3-TestingPlatform/mailvalidator/releases/tag/v0.1.0
