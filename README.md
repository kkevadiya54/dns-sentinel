# DNS Sentinel

DNS Sentinel is a read-only command-line tool and Python library for a first-pass review of public DNS security configuration. It checks SPF, DMARC, CAA, MX, nameserver count, and DNSSEC record presence. It is an early MVP: results are evidence-based hints, not a compliance certificate or a substitute for a mail/DNS specialist.

## Install and run

Requires Python 3.10 or newer.

```sh
python -m pip install dns-sentinel
dns-sentinel example.com
dns-sentinel example.com --json
```

To install the development version from source:

```sh
git clone https://github.com/kkevadiya54/dns-sentinel.git
cd dns-sentinel
python -m pip install .
dns-sentinel example.com
dns-sentinel example.com --json
```

Exit status is `0` when no error-severity findings exist, `1` when an error-severity finding exists, and `2` when input or runtime setup prevents an audit. Warnings can indicate missing controls or incomplete answers. Network timeouts are reported per check and do not discard other results.

Use only for domains you are authorized to assess. The tool sends ordinary DNS queries to the system-configured recursive resolver; it does not scan hosts, change DNS, or send email.

## What checks mean

| Check | MVP behavior | Not claimed |
| --- | --- | --- |
| SPF | Detects zero/multiple policies and performs basic token sanity checks | Full RFC 7208 evaluation, include/redirect expansion, DNS lookup limits, or authorization outcome |
| DMARC | Requires one `_dmarc` TXT policy and validates version, policy, duplicate tags, `pct`, and basic `rua` syntax | Full RFC 9989 semantics, organizational-domain discovery, or report processing |
| CAA | Checks returned CAA tag names and flags | Complete CAA tree-walk inheritance, issuer authorization semantics, or certificate issuance outcome |
| MX | Checks preference/exchange shape, duplicate targets, and RFC 7505 null MX | Whether each mail host is reachable or correctly configured |
| NS | Counts distinct returned NS targets | Independent operators, networks, geographic diversity, or authoritative delegation consistency |
| DNSSEC | Reports whether DNSKEY and DS records were observed at the queried name | **Cryptographic validation.** The resolver may or may not validate; this tool does not inspect signatures or establish a chain of trust. |

DNS negative answers and resolver failures are different. A timeout, SERVFAIL-like nameserver failure, or local resolver problem produces an `unknown`/warning result where relevant; it is not reported as proof that a record is absent. DNSSEC checks are strictly record-presence checks.

## Python API

```python
from dns_sentinel import Auditor

report = Auditor(timeout=2, lifetime=5).audit("example.com")
for finding in report.findings:
    print(finding.check, finding.status, finding.message)
print(report.to_dict())
```

## Development

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest --cov=dns_sentinel --cov-report=term-missing
ruff check .
mypy
python -m build
```

Integration checks can query a domain you control, for example `dns-sentinel example.com`; the unit suite uses deterministic resolver fakes and does not depend on public DNS.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md), and [COMMUNITY.md](COMMUNITY.md). Small reproducible fixes, standards-backed tests, documentation improvements, and carefully scoped record checks are welcome. Please do not claim a check validates more than it does.

Browse [beginner-friendly issues](https://github.com/kkevadiya54/dns-sentinel/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or join the [beta testing invitation](https://github.com/kkevadiya54/dns-sentinel/issues/5). Please comment before starting work on issues that ask for maintainer alignment.

## Project status

Alpha software. Version 0.1.1 is available on PyPI. Community growth and protocol coverage remain ongoing work; see [ROADMAP.md](ROADMAP.md) for the staged plan and limits.

## License

MIT; see [LICENSE](LICENSE).
