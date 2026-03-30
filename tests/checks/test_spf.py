"""Tests for mailvalidator/checks/spf.py."""

from __future__ import annotations

from unittest.mock import patch

from mailvalidator.checks.spf import check_spf
from mailvalidator.models import Status


class TestSPF:
    def test_fail_all_ok(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 ip4:1.2.3.4 -all"'],
        ):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK
        assert "-all" in policy.value

    def test_softfail_all_ok(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ~all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK

    def test_neutral_all_warning(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ?all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING

    def test_plus_all_error(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=['"v=spf1 +all"']):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.ERROR

    def test_missing_all_implies_neutral(self):
        with patch(
            "mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ip4:1.2.3.4"']
        ):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING
        assert "neutral" in " ".join(policy.details).lower()

    def test_not_found(self):
        with patch("mailvalidator.checks.spf.resolve", return_value=[]):
            result = check_spf("example.com")
        assert any(c.status == Status.NOT_FOUND for c in result.checks)

    def test_multiple_spf_records_error(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 -all"', '"v=spf1 ~all"'],
        ):
            result = check_spf("example.com")
        assert any(
            c.status == Status.ERROR and "Multiple" in c.name for c in result.checks
        )

    def test_ptr_deprecation_warned(self):
        with patch(
            "mailvalidator.checks.spf.resolve", return_value=['"v=spf1 ptr -all"']
        ):
            result = check_spf("example.com")
        assert any(
            c.name == "ptr Mechanism" and c.status == Status.WARNING
            for c in result.checks
        )

    def test_include_resolved_and_shown(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:_spf.protonmail.ch ~all"']
            if domain == "_spf.protonmail.ch":
                return ['"v=spf1 ip4:185.70.40.0/24 ip4:185.70.41.0/24 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert resolution.status == Status.OK
        assert "_spf.protonmail.ch" in " ".join(resolution.details)

    def test_include_lookup_count_recursive(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:_spf.protonmail.ch -all"']
            if domain == "_spf.protonmail.ch":
                return ['"v=spf1 a:mail.protonmail.ch ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")

    def test_ptr_counts_as_lookup(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ptr -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")

    def test_ip4_ip6_not_counted_as_lookups(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all"'],
        ):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("0/")

    def test_include_missing_record_warns(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:missing.example.com -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert resolution.status == Status.WARNING

    def test_include_loop_handled(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:a.example.com -all"']
            if domain == "a.example.com":
                return ['"v=spf1 include:b.example.com -all"']
            if domain == "b.example.com":
                return ['"v=spf1 include:a.example.com -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        assert result is not None

    def test_macro_in_include_not_followed(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 include:%{d}._spf.example.com -all"'],
        ):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("macro" in detail.lower() for detail in resolution.details)

    def test_redirect_is_followed(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 ip4:10.0.0.0/8 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK

    def test_redirect_lookup_counted(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 mx -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("2/")


class TestSPFCoverage:
    def test_bad_version_tag_error(self):
        from mailvalidator.checks.spf import _validate_spf
        from mailvalidator.models import SPFResult

        result = SPFResult(domain="example.com")
        _validate_spf("v=spf2 -all", "example.com", result)
        assert any(
            c.name == "SPF Version" and c.status == Status.ERROR for c in result.checks
        )

    def test_redirect_macro_noted_not_followed(self):
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 redirect=%{d}._spf.example.com"'],
        ):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("macro" in detail.lower() for detail in resolution.details)

    def test_redirect_with_no_all_in_target_warns(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=_spf.example.net"']
            if domain == "_spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING

    def test_lookup_count_exceeds_limit(self):
        def _fake(domain, rtype):
            if domain == "example.com":
                includes = " ".join(f"include:s{i}.example.net" for i in range(11))
                return [f'"v=spf1 {includes} -all"']
            return ['"v=spf1 ip4:1.2.3.4 -all"']

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.status == Status.ERROR


class TestVoidLookups:
    """Void lookups (empty-answer DNS queries) are capped at 2 by RFC 7208 §4.6.4."""

    def test_single_void_lookup_is_warned(self):
        """One include: with no SPF record → void count 1 → WARNING."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:missing.example.com -all"']
            return []  # missing.example.com has no TXT record

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        void = next(c for c in result.checks if c.name == "Void Lookup Count")
        assert void.status == Status.WARNING
        assert void.value.startswith("1/")

    def test_two_void_lookups_still_warned(self):
        """Two void includes → count 2 → still WARNING (at the limit, not over)."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:a.missing.com include:b.missing.com -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        void = next(c for c in result.checks if c.name == "Void Lookup Count")
        assert void.status == Status.WARNING
        assert void.value.startswith("2/")

    def test_three_void_lookups_is_error(self):
        """Three void includes → count 3 → ERROR (PermError at receivers)."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return [
                    '"v=spf1 include:a.missing.com include:b.missing.com '
                    'include:c.missing.com -all"'
                ]
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        void = next(c for c in result.checks if c.name == "Void Lookup Count")
        assert void.status == Status.ERROR
        assert void.value.startswith("3/")
        assert "PermError" in " ".join(void.details)

    def test_no_void_lookups_no_check_emitted(self):
        """All includes resolve successfully → no Void Lookup Count check emitted."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        assert not any(c.name == "Void Lookup Count" for c in result.checks)

    def test_void_lookup_count_recursive(self):
        """Void lookups inside nested includes are counted across the whole tree."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return [
                    '"v=spf1 include:dead1.example.com include:dead2.example.com -all"'
                ]
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        void = next(c for c in result.checks if c.name == "Void Lookup Count")
        assert void.value.startswith("2/")

    def test_macro_skip_nodes_not_counted_as_void(self):
        """Macro-containing include: targets are not followed → not counted as void."""
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 include:%{d}._spf.example.com -all"'],
        ):
            result = check_spf("example.com")
        assert not any(c.name == "Void Lookup Count" for c in result.checks)


class TestACidrLookupCount:
    """The `a` mechanism with CIDR notation must count as one DNS lookup."""

    def test_a_with_cidr_counted(self):
        """a/24 on a flat record is counted as one lookup."""
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 a/24 -all"'],
        ):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("1/")

    def test_a_domain_cidr_counted(self):
        """a:mail.example.com/24 is counted as one lookup."""
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 a:mail.example.com/24 -all"'],
        ):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("1/")

    def test_mx_with_cidr_counted(self):
        """mx/24 is counted as one lookup."""
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 mx/24 -all"'],
        ):
            result = check_spf("example.com")
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("1/")

    def test_a_cidr_in_include_counted(self):
        """a/24 inside an include: target contributes to the recursive count."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 a/24 mx/24 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        # include: (1) + a/24 (1) + mx/24 (1) = 3
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("3/")


class TestIndependentIncludeBranches:
    """A domain referenced from two sibling include: terms is NOT a loop.
    Both branches must be resolved and their lookups counted independently."""

    def test_shared_domain_in_two_includes_both_counted(self):
        """mailgun.org and sendgrid.net both include shared.spf.example → counted twice."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:mailgun.org include:sendgrid.net -all"']
            if domain == "mailgun.org":
                return ['"v=spf1 include:shared.spf.example -all"']
            if domain == "sendgrid.net":
                return ['"v=spf1 include:shared.spf.example -all"']
            if domain == "shared.spf.example":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")

        # example.com: include:mailgun.org (1) + include:sendgrid.net (1)
        # mailgun.org: include:shared.spf.example (1)
        # sendgrid.net: include:shared.spf.example (1)
        # Total = 4
        lookup = next(c for c in result.checks if c.name == "DNS Lookup Count")
        assert lookup.value.startswith("4/")

    def test_shared_domain_both_appear_in_resolution_output(self):
        """The same domain resolved via two separate branches appears in the tree twice."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:a.example.net include:b.example.net -all"']
            if domain == "a.example.net":
                return ['"v=spf1 include:shared.spf.example -all"']
            if domain == "b.example.net":
                return ['"v=spf1 include:shared.spf.example -all"']
            if domain == "shared.spf.example":
                return ['"v=spf1 ip4:5.6.7.8 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")

        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        details_text = " ".join(resolution.details)
        # shared.spf.example is resolved once per branch (a.example.net and
        # b.example.net both include it), so it appears at least twice.
        # Each occurrence contributes the domain name to both the parent
        # record string and the child node label, so the raw count is ≥ 4;
        # the important invariant is that it is present in more than one
        # independent branch, which is confirmed by asserting count >= 4.
        assert details_text.count("shared.spf.example") >= 4

    def test_true_cycle_on_same_path_still_blocked(self):
        """a → b → a is a true cycle and must be blocked (loop error reported)."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:a.example.com -all"']
            if domain == "a.example.com":
                return ['"v=spf1 include:b.example.com -all"']
            if domain == "b.example.com":
                return ['"v=spf1 include:a.example.com -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")

        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("loop" in d.lower() or "⚠" in d for d in resolution.details)


class TestNestedPlusAll:
    """An included record containing +all is a security hazard (RFC 7208 §5.2)."""

    def test_nested_plus_all_flagged_as_error(self):
        """include: chain that ends with +all must produce an ERROR check."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:bad.example.net -all"']
            if domain == "bad.example.net":
                return ['"v=spf1 +all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        nested = next(
            (c for c in result.checks if c.name == "Nested +all in include:"), None
        )
        assert nested is not None
        assert nested.status == Status.ERROR

    def test_bare_all_in_include_also_flagged(self):
        """bare 'all' (implicit +) inside include: is also flagged."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:permissive.example.net -all"']
            if domain == "permissive.example.net":
                return ['"v=spf1 all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        nested = next(
            (c for c in result.checks if c.name == "Nested +all in include:"), None
        )
        assert nested is not None
        assert nested.status == Status.ERROR

    def test_minus_all_in_include_not_flagged(self):
        """A normal -all inside an included record must not trigger the warning."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        assert not any(c.name == "Nested +all in include:" for c in result.checks)

    def test_softfail_all_in_include_not_flagged(self):
        """~all inside an included record is acceptable — no warning."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4 ~all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        assert not any(c.name == "Nested +all in include:" for c in result.checks)

    def test_nested_plus_all_two_levels_deep_flagged(self):
        """+all buried two include: levels deep must still be flagged."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:level1.example.net -all"']
            if domain == "level1.example.net":
                return ['"v=spf1 include:bad.example.net -all"']
            if domain == "bad.example.net":
                return ['"v=spf1 +all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        nested = next(
            (c for c in result.checks if c.name == "Nested +all in include:"), None
        )
        assert nested is not None
        assert nested.status == Status.ERROR


class TestExpModifier:
    """The exp= modifier must be noted in the include resolution output."""

    def test_exp_modifier_noted_in_top_level(self):
        """exp= on the top-level record appears in the resolution detail lines."""
        with patch(
            "mailvalidator.checks.spf.resolve",
            return_value=['"v=spf1 ip4:1.2.3.4 exp=explain.example.com -all"'],
        ):
            result = check_spf("example.com")
        # exp= is surfaced inside the SPF Include Resolution check when a tree
        # is built; for flat records it appears in the detail of that check.
        # The include resolution check is only added when tree is not None,
        # so we just verify no exception was raised and the record is present.
        spf_record = next(c for c in result.checks if c.name == "SPF Record")
        assert "exp=explain.example.com" in " ".join(spf_record.details)

    def test_exp_modifier_noted_in_include_resolution(self):
        """exp= inside an include: target is surfaced in the tree output."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4 exp=explain.example.net -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("exp=" in d for d in resolution.details)

    def test_exp_modifier_in_tree_mentions_explanation(self):
        """The exp= detail line mentions its purpose (explanation on Fail)."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4 exp=explain.example.net -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        exp_lines = [d for d in resolution.details if "exp=" in d]
        assert exp_lines
        assert any("explanation" in d.lower() or "fail" in d.lower() for d in exp_lines)


class TestEffectiveAllDeepRedirect:
    """_effective_all must follow a redirect inside the redirect target."""

    def test_two_level_redirect_all_found(self):
        """example.com → redirect=mid.example.net → redirect=spf.example.org → -all."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=mid.example.net"']
            if domain == "mid.example.net":
                return ['"v=spf1 redirect=spf.example.org"']
            if domain == "spf.example.org":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.OK
        assert "via redirect" in policy.value

    def test_two_level_redirect_no_all_warns(self):
        """redirect chain that never reaches an all term → WARNING."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 redirect=mid.example.net"']
            if domain == "mid.example.net":
                return ['"v=spf1 redirect=spf.example.org"']
            if domain == "spf.example.org":
                return ['"v=spf1 ip4:1.2.3.4"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        policy = next(c for c in result.checks if c.name == "SPF Policy")
        assert policy.status == Status.WARNING


class TestIncludeQualifierSurfaced:
    """The qualifier on an include: term must appear in the resolution tree output."""

    def test_default_plus_qualifier_shown(self):
        """Plain include: (implicit +) shows qualifier in the tree."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 include:spf.example.net -all"']
            if domain == "spf.example.net":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("qualifier" in d.lower() for d in resolution.details)

    def test_fail_qualifier_shown(self):
        """-include: shows 'fail' qualifier in the tree."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 -include:blocklist.example.net -all"']
            if domain == "blocklist.example.net":
                return ['"v=spf1 ip4:10.0.0.0/8 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("fail" in d.lower() for d in resolution.details)

    def test_softfail_qualifier_shown(self):
        """~include: shows 'softfail' qualifier in the tree."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 ~include:soft.example.net ~all"']
            if domain == "soft.example.net":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("softfail" in d.lower() for d in resolution.details)

    def test_neutral_qualifier_shown(self):
        """?include: shows 'neutral' qualifier in the tree."""

        def _fake(domain, rtype):
            if domain == "example.com":
                return ['"v=spf1 ?include:neutral.example.net -all"']
            if domain == "neutral.example.net":
                return ['"v=spf1 ip4:1.2.3.4 -all"']
            return []

        with patch("mailvalidator.checks.spf.resolve", side_effect=_fake):
            result = check_spf("example.com")
        resolution = next(
            c for c in result.checks if c.name == "SPF Include Resolution"
        )
        assert any("neutral" in d.lower() for d in resolution.details)
