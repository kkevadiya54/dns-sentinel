"""DNS record checks with explicit limits and per-query failure isolation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any

import dns.exception
import dns.resolver


@dataclass(frozen=True, slots=True)
class Finding:
    check: str
    status: str
    severity: str
    message: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Report:
    domain: str
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "findings": [asdict(item) for item in self.findings]}

    @property
    def passed(self) -> bool:
        return not any(f.severity == "error" for f in self.findings)


def normalize_domain(domain: str) -> str:
    """Validate and normalize a DNS hostname; reject URL/path inputs and IP literals."""
    value = domain.strip().rstrip(".")
    if not value or any(char in value for char in "/:@?#"):
        raise ValueError("Provide a DNS domain name, not a URL or address.")
    try:
        ascii_name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Domain is not valid IDNA.") from exc
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        pass
    else:
        raise ValueError("Provide a DNS domain name, not an IP address.")
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise ValueError("Provide a fully qualified domain name (for example, example.com).")
    labels = ascii_name.split(".")
    if any(
        not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Domain contains an invalid DNS label.")
    return ascii_name


class Auditor:
    """Read-only DNS auditor. DNSSEC results report records only, never cryptographic validity."""

    def __init__(self, timeout: float = 2.0, lifetime: float = 5.0, resolver: Any = None):
        if timeout <= 0 or lifetime <= 0:
            raise ValueError("DNS timeouts must be positive.")
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    def _query(self, name: str, kind: str) -> tuple[list[str], str | None]:
        try:
            answer = self.resolver.resolve(name, kind, search=False, raise_on_no_answer=False)
            if answer.rrset is None:
                return [], "no records"
            return [item if isinstance(item, str) else item.to_text() for item in answer], None
        except dns.resolver.NXDOMAIN:
            return [], "name does not exist"
        except dns.resolver.NoAnswer:
            return [], "no records"
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return [], "DNS query timed out"
        except dns.resolver.NoNameservers:
            return [], "all configured name servers failed"
        except (dns.resolver.NoResolverConfiguration, OSError) as exc:
            return [], f"DNS resolver unavailable: {exc}"
        except dns.exception.DNSException as exc:
            return [], f"DNS query failed: {exc.__class__.__name__}"

    def audit(self, domain: str) -> Report:
        name = normalize_domain(domain)
        findings = (
            self._check_spf(name),
            self._check_dmarc(name),
            self._check_caa(name),
            self._check_mx(name),
            self._check_ns(name),
            self._check_dnssec_presence(name),
        )
        return Report(name, findings)

    def _txt(self, name: str, check: str) -> tuple[list[str], Finding | None]:
        rows, error = self._query(name, "TXT")
        if error and error != "no records":
            return [], Finding(check, "error", "warning", f"Could not query TXT records: {error}")
        # DNS TXT character-strings concatenate without separators per RFC 1035.
        return [
            "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', row)).replace(r"\"", '"') for row in rows
        ], None

    def _check_spf(self, name: str) -> Finding:
        records, issue = self._txt(name, "spf")
        if issue:
            return issue
        spf = [r for r in records if r.lower().startswith("v=spf1")]
        if not spf:
            return Finding("spf", "fail", "warning", "No SPF policy was found.")
        if len(spf) > 1:
            return Finding(
                "spf",
                "fail",
                "error",
                "Multiple SPF policies exist; receivers cannot select one.",
                tuple(spf),
            )
        tokens = spf[0].lower().split()
        if tokens[0] != "v=spf1" or len(tokens) < 2:
            return Finding("spf", "fail", "error", "SPF policy is empty or malformed.", tuple(spf))
        mechanism_terms = [
            (t[0], t[1:]) if t[:1] in "+-~?" else ("", t) for t in tokens[1:]
        ]
        mechanisms = [mechanism for _, mechanism in mechanism_terms]
        seen_modifiers: set[str] = set()
        for qualifier, mechanism in mechanism_terms:
            if mechanism.startswith(("redirect=", "exp=")):
                key, value = mechanism.split("=", 1)
                if qualifier or key in seen_modifiers or not value or "." not in value:
                    return Finding(
                        "spf",
                        "fail",
                        "error",
                        "SPF modifier is duplicated or malformed.",
                        tuple(spf),
                    )
                seen_modifiers.add(key)
                continue
            kind, separator, argument = mechanism.partition(":")
            kind = kind.split("/", 1)[0]
            if kind == "all" and (separator or "/" in mechanism):
                return Finding(
                    "spf",
                    "fail",
                    "error",
                    "SPF 'all' mechanism cannot take an argument.",
                    tuple(spf),
                )
            if kind in {"a", "mx"}:
                match = re.fullmatch(
                    r"(?:a|mx)(?::[a-z0-9.-]+)?(?:/(?P<ipv4>[0-9]{1,2}))?"
                    r"(?://(?P<ipv6>[0-9]{1,3}))?",
                    mechanism,
                )
                valid = match is not None and (
                    match.group("ipv4") is None or int(match.group("ipv4")) <= 32
                ) and (match.group("ipv6") is None or int(match.group("ipv6")) <= 128)
            elif kind == "ptr":
                valid = re.fullmatch(r"ptr(?::[a-z0-9.-]+)?", mechanism) is not None
            elif kind == "ip4":
                try:
                    ipaddress.IPv4Network(argument, strict=False)
                    valid = (
                        bool(separator) and "/" not in mechanism.partition(":")[2].partition("/")[0]
                    )
                except ValueError:
                    valid = False
            elif kind == "ip6":
                try:
                    ipaddress.IPv6Network(argument, strict=False)
                    valid = bool(separator)
                except ValueError:
                    valid = False
            elif kind in {"include", "exists"}:
                valid = bool(
                    separator
                    and argument
                    and "." in argument
                    and re.fullmatch(r"[a-z0-9.-]+", argument)
                )
            elif kind == "all":
                valid = True
            else:
                valid = False
            if not valid:
                return Finding(
                    "spf",
                    "fail",
                    "error",
                    "SPF contains an unrecognized or malformed mechanism.",
                    tuple(spf),
                )
        if sum(m.split(":", 1)[0].split("/", 1)[0] == "all" for m in mechanisms) > 1:
            return Finding(
                "spf", "fail", "error", "SPF contains more than one 'all' mechanism.", tuple(spf)
            )
        return Finding(
            "spf",
            "pass",
            "info",
            "Exactly one SPF policy was found; this MVP checks presence and basic syntax, "
            "not evaluation.",
            tuple(spf),
        )

    def _check_dmarc(self, name: str) -> Finding:
        records, issue = self._txt(f"_dmarc.{name}", "dmarc")
        if issue:
            return issue
        policies = [r for r in records if r.lower().startswith("v=dmarc1")]
        if len(policies) != 1:
            return Finding(
                "dmarc",
                "fail",
                "warning" if not policies else "error",
                "No DMARC policy found." if not policies else "Multiple DMARC policies found.",
                tuple(policies),
            )
        tags: dict[str, str] = {}
        for token in policies[0].split(";"):
            if not token.strip():
                continue
            if "=" not in token:
                return Finding(
                    "dmarc", "fail", "error", "DMARC contains a tag without '='.", tuple(policies)
                )
            key, value = (part.strip() for part in token.split("=", 1))
            key = key.lower()
            if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or key in tags:
                return Finding(
                    "dmarc",
                    "fail",
                    "error",
                    "DMARC contains an invalid or duplicate tag.",
                    tuple(policies),
                )
            tags[key] = value
        ordered_tags = [part.strip() for part in policies[0].split(";") if part.strip()]
        if not ordered_tags[0].lower().startswith("v="):
            return Finding(
                "dmarc", "fail", "error", "DMARC version tag must appear first.", tuple(policies)
            )
        if tags.get("v", "").upper() != "DMARC1" or tags.get("p", "").lower() not in {
            "none",
            "quarantine",
            "reject",
        }:
            return Finding(
                "dmarc",
                "fail",
                "error",
                "DMARC requires v=DMARC1 and p=none, quarantine, or reject.",
                tuple(policies),
            )
        if "pct" in tags and (not tags["pct"].isdigit() or int(tags["pct"]) > 100):
            return Finding(
                "dmarc",
                "fail",
                "error",
                "DMARC pct must be an integer from 0 to 100.",
                tuple(policies),
            )
        if "rua" in tags and not all(
            re.fullmatch(r"mailto:[^,!;\s]+(?:![0-9]+[kmg]?)?", uri.strip(), re.I)
            for uri in tags["rua"].split(",")
        ):
            return Finding(
                "dmarc",
                "fail",
                "error",
                "DMARC rua must contain valid mailto URIs.",
                tuple(policies),
            )
        return Finding(
            "dmarc",
            "pass",
            "info",
            "One DMARC policy with valid version and policy tags was found.",
            tuple(policies),
        )
    def _check_caa(self, name: str) -> Finding:
        policy_owner = name

        while True:
            rows, error = self._query(policy_owner, "CAA")

            if error and error != "no records":
                return Finding(
                    "caa",
                    "error",
                    "warning",
                    f"Could not query CAA records at {policy_owner}: {error}",
                )

            if rows:
                for row in rows:
                    parts = row.split(None, 2)
                    if (
                        len(parts) != 3
                        or not parts[0].isdigit()
                        or int(parts[0]) > 255
                        or parts[1].lower()
                        not in {"issue", "issuewild", "iodef"}
                    ):
                        return Finding(
                            "caa",
                            "fail",
                            "error",
                            "Malformed CAA record (expected flags tag value).",
                            tuple(rows),
                        )

                return Finding(
                    "caa",
                    "pass",
                    "info",
                    f"CAA records are present at policy owner {policy_owner}.",
                    tuple(rows),
                )
            if "." not in policy_owner:
                break

            policy_owner = policy_owner.split(".", 1)[1]

        return Finding(
            "caa",
            "fail",
            "warning",
            "No CAA records found; any CA may be authorized by default.",
        )


    def _check_mx(self, name: str) -> Finding:
        rows, error = self._query(name, "MX")
        if error and error != "no records":
            return Finding("mx", "error", "warning", f"Could not query MX records: {error}")
        if not rows:
            return Finding(
                "mx",
                "pass",
                "info",
                "No MX records found; this domain does not advertise inbound mail.",
            )
        parsed: list[tuple[int, str]] = []
        for row in rows:
            parts = row.split()
            if len(parts) != 2 or not parts[0].isdigit():
                return Finding(
                    "mx",
                    "fail",
                    "error",
                    "Malformed MX record; expected preference and exchange.",
                    tuple(rows),
                )
            target = parts[1].rstrip(".").lower()
            if target == "" and len(rows) == 1 and int(parts[0]) == 0:
                return Finding(
                    "mx",
                    "pass",
                    "info",
                    "Null MX explicitly declares that this domain accepts no mail.",
                    tuple(rows),
                )
            if target == "" or int(parts[0]) > 65535:
                return Finding(
                    "mx", "fail", "error", "MX preference or exchange is invalid.", tuple(rows)
                )
            try:
                normalize_domain(target)
            except ValueError:
                return Finding(
                    "mx", "fail", "error", "MX exchange is not a valid DNS hostname.", tuple(rows)
                )
            parsed.append((int(parts[0]), target))
        if len({target for _, target in parsed}) != len(parsed):
            return Finding(
                "mx", "fail", "error", "Duplicate MX exchange records were found.", tuple(rows)
            )
        return Finding(
            "mx",
            "pass",
            "info",
            "MX records have valid preference and exchange fields.",
            tuple(rows),
        )

    def _check_ns(self, name: str) -> Finding:
        rows, error = self._query(name, "NS")
        if error and error != "no records":
            return Finding("ns", "error", "warning", f"Could not query NS records: {error}")
        targets = {row.rstrip(".").lower() for row in rows}
        if not targets:
            return Finding("ns", "fail", "error", "No authoritative NS records were returned.")
        if len(targets) < 2:
            return Finding(
                "ns",
                "fail",
                "warning",
                "Only one distinct NS target was found; consider provider and network diversity.",
                tuple(rows),
            )
        return Finding(
            "ns",
            "pass",
            "info",
            "At least two distinct NS targets were found; provider independence is not verified.",
            tuple(sorted(targets)),
        )

    def _check_dnssec_presence(self, name: str) -> Finding:
        found: list[str] = []
        errors: list[str] = []
        for kind in ("DNSKEY", "DS"):
            rows, error = self._query(name, kind)
            if rows:
                found.append(kind)
            elif error and error != "no records":
                errors.append(f"{kind}: {error}")
        if errors:
            return Finding(
                "dnssec_record_presence",
                "unknown",
                "warning",
                "Could not complete DNSSEC record-presence checks: " + "; ".join(errors),
                tuple(found),
            )
        if len(found) == 2:
            return Finding(
                "dnssec_record_presence",
                "pass",
                "info",
                "DNSKEY and DS records were observed. This is a presence check only; signatures "
                "and chain of trust were not cryptographically validated.",
                tuple(found),
            )
        return Finding(
            "dnssec_record_presence",
            "fail",
            "warning",
            "DNSKEY and/or DS records were not observed. This is not a cryptographic DNSSEC "
            "validation result.",
            tuple(found),
        )
