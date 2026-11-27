from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import dns.exception
import dns.resolver
import pytest

from dns_sentinel.auditor import Auditor, normalize_domain


class Answer(list[str]):
    @property
    def rrset(self) -> object:
        return self if self else None


class Resolver:
    def __init__(self, data: dict[tuple[str, str], list[str] | Exception]):
        self.data = data
        self.queries: list[tuple[str, str]] = []

    def resolve(self, name: str, kind: str, **kwargs: object) -> Answer:
        self.queries.append((name, kind))
        value = self.data.get((name, kind), [])
        if isinstance(value, Exception):
            raise value
        return Answer(value)


def auditor(
    data: Mapping[tuple[str, str], list[str] | Exception],
) -> Auditor:
    return Auditor(resolver=Resolver(dict(data)))


@pytest.mark.parametrize(
    "value,expected", [("Example.COM.", "example.com"), ("bücher.de", "xn--bcher-kva.de")]
)
def test_domain_normalization(value: str, expected: str) -> None:
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value", ["", "https://example.com", "127.0.0.1", "localhost", "-bad.example", "a..b"]
)
def test_domain_rejects_invalid_input(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_spf_requires_one_policy_and_rejects_duplicates() -> None:
    a = auditor({("example.com", "TXT"): ['"v=spf1 -all"', '"hello"']})
    assert a.audit("example.com").findings[0].status == "pass"
    b = auditor({("example.com", "TXT"): ['"v=spf1 -all"', '"v=spf1 ~all"']})
    result = b.audit("example.com").findings[0]
    assert result.status == "fail" and result.severity == "error"


def test_spf_rejects_malformed_mechanism() -> None:
    a = auditor({("example.com", "TXT"): ['"v=spf1 ip4:not-an-ip -all"']})
    assert a.audit("example.com").findings[0].status == "fail"


@pytest.mark.parametrize(
    "mechanism,expected",
    [
        # Valid literal domains
        ("a:example.com", "pass"),
        ("a:mail.example.com", "pass"),
        ("mx:example.com", "pass"),
        ("mx:mail.example.com", "pass"),
        ("include:example.com", "pass"),
        ("exists:example.com", "pass"),
        # Empty labels and consecutive dots
        ("a:a..example.com", "fail"),
        ("mx:a..example.com", "fail"),
        ("include:a..example.com", "fail"),
        ("exists:a..example.com", "fail"),
        # Leading and trailing empty labels
        ("a:.example.com", "fail"),
        ("mx:example.com.", "pass"),
        ("include:.example.com", "fail"),
        ("exists:example.com.", "pass"),
        ("a:example.com.", "pass"),
        ("include:example.com.", "pass"),
    ],
)
def test_spf_literal_domain_validation(mechanism: str, expected: str) -> None:
    policy = f"v=spf1 {mechanism} -all"
    result = auditor({("example.com", "TXT"): [f'"{policy}"']}).audit("example.com").findings[0]

    assert result.status == expected


@pytest.mark.parametrize(
    "policy,expected",
    [
        ("v=spf1 a/32 mx//128 ptr:example.com -all", "pass"),
        ("v=spf1 a/33 -all", "fail"),
        ("v=spf1 mx//129 -all", "fail"),
        ("v=spf1 ptr/24 -all", "fail"),
        ("v=spf1 --all", "fail"),
        ("v=spf1 ??all", "fail"),
        ("v=spf1 +redirect:example.com -all", "fail"),
        ("v=spf1 ~exp=errors.example.com -all", "fail"),
    ],
)
def test_spf_rejects_out_of_range_prefixes_and_qualifiers(policy: str, expected: str) -> None:
    result = auditor({("example.com", "TXT"): [f'"{policy}"']}).audit("example.com").findings[0]
    assert result.status == expected


@pytest.mark.parametrize(
    "record,expected",
    [
        ("v=DMARC1; p=reject; pct=100", "pass"),
        ("v=DMARC1; p=invalid", "fail"),
        ("v=DMARC1; p=none; pct=101", "fail"),
        ("v=DMARC1; p=none; p=reject", "fail"),
    ],
)
def test_dmarc_policy_validation(record: str, expected: str) -> None:
    result = (
        auditor({("_dmarc.example.com", "TXT"): [f'"{record}"']}).audit("example.com").findings[1]
    )
    assert result.status == expected


def test_dmarc_requires_version_first_and_accepts_rua_size() -> None:
    wrong_order = (
        auditor({("_dmarc.example.com", "TXT"): ['"p=reject; v=DMARC1"']})
        .audit("example.com")
        .findings[1]
    )
    assert wrong_order.status == "fail"
    valid_uri = (
        auditor(
            {
                ("_dmarc.example.com", "TXT"): [
                    '"v=DMARC1; p=reject; rua=mailto:reports@example.com!10m"'
                ]
            }
        )
        .audit("example.com")
        .findings[1]
    )
    assert valid_uri.status == "pass"


def test_caa_mx_ns_checks() -> None:
    data = {
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
    }
    findings = auditor(data).audit("example.com").findings
    assert [findings[i].status for i in (2, 3, 4)] == ["pass", "pass", "pass"]


def test_null_mx_and_malformed_caa() -> None:
    data = {("example.com", "MX"): ["0 ."], ("example.com", "CAA"): ["999 nonsense value"]}
    findings = auditor(data).audit("example.com").findings
    assert findings[2].status == "fail"
    assert findings[3].status == "pass"


def test_dnssec_is_explicitly_presence_only() -> None:
    data = {("example.com", "DNSKEY"): ["256 3 13 abc"], ("example.com", "DS"): ["1 1 1 abc"]}
    result = auditor(data).audit("example.com").findings[-1]
    assert result.status == "pass"
    assert "not cryptographically validated" in result.message


def test_dns_errors_do_not_abort_other_checks() -> None:
    data = {
        ("example.com", "TXT"): cast(Any, dns.resolver.NXDOMAIN)(),
        ("example.com", "CAA"): cast(Any, dns.exception.Timeout)(),
        ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
    }
    findings = auditor(data).audit("example.com").findings
    assert len(findings) == 6
    assert findings[2].severity == "warning"
    assert findings[4].status == "pass"


@pytest.mark.parametrize(
    "failure",
    [
        cast(Any, dns.resolver.LifetimeTimeout)(timeout=1, errors=[]),
        cast(Any, dns.resolver.NoNameservers)(),
    ],
)
def test_resolver_failures_are_reported_as_warnings(failure: Exception) -> None:
    result = auditor({("example.com", "CAA"): failure}).audit("example.com").findings[2]
    assert result.severity == "warning"
    assert "Could not query" in result.message


@pytest.mark.parametrize(
    "failure",
    [
        cast(Any, dns.resolver.NoResolverConfiguration)(),
        OSError("network unreachable"),
    ],
)
def test_resolver_config_and_os_errors_warn_and_continue(failure: Exception) -> None:
    data: dict[tuple[str, str], list[str] | Exception] = {
        ("example.com", "CAA"): failure,
        ("example.com", "NS"): ["ns1.example.net.", "ns2.example.net."],
    }
    findings = auditor(data).audit("example.com").findings
    assert len(findings) == 6
    assert findings[2].status == "error"
    assert findings[2].severity == "warning"
    assert "DNS resolver unavailable" in findings[2].message
    assert findings[4].status == "pass"


def test_mx_rejects_invalid_preference() -> None:
    result = (
        auditor({("example.com", "MX"): ["70000 mail.example.com."]})
        .audit("example.com")
        .findings[3]
    )
    assert result.status == "fail"


def test_ns_duplicate_target_does_not_fake_redundancy() -> None:
    result = (
        auditor({("example.com", "NS"): ["ns1.example.net.", "NS1.example.net."]})
        .audit("example.com")
        .findings[4]
    )
    assert result.status == "fail"


def test_report_json_shape() -> None:
    report = auditor({}).audit("example.com")
    assert report.to_dict()["domain"] == "example.com"
    assert len(report.to_dict()["findings"]) == 6


def test_caa_inherits_parent_policy() -> None:
    data: dict[tuple[str, str], list[str] | Exception] = {
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
    }
    resolver = Resolver(data)
    findings = Auditor(resolver=resolver).audit("sub.example.com").findings

    caa = next(finding for finding in findings if finding.check == "caa")

    assert caa.status == "pass"
    assert "example.com" in caa.message
    assert [query for query in resolver.queries if query[1] == "CAA"] == [
        ("sub.example.com", "CAA"),
        ("example.com", "CAA"),
    ]


def test_caa_missing_policy_stops_before_root() -> None:
    resolver = Resolver({})
    findings = Auditor(resolver=resolver).audit("sub.example.com").findings

    caa = next(finding for finding in findings if finding.check == "caa")

    assert caa.status == "fail"
    assert [query for query in resolver.queries if query[1] == "CAA"] == [
        ("sub.example.com", "CAA"),
        ("example.com", "CAA"),
        ("com", "CAA"),
    ]


def test_caa_ancestor_lookup_handles_dns_error() -> None:
    data: dict[tuple[str, str], list[str] | Exception] = {
        ("example.com", "CAA"): cast(Any, dns.exception.Timeout)(),
    }
    resolver = Resolver(data)
    findings = Auditor(resolver=resolver).audit("sub.example.com").findings

    caa = next(finding for finding in findings if finding.check == "caa")

    assert caa.status == "error"
    assert "example.com" in caa.message
    assert [query for query in resolver.queries if query[1] == "CAA"] == [
        ("sub.example.com", "CAA"),
        ("example.com", "CAA"),
    ]
