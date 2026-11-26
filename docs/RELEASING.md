# Releasing

DNS Sentinel 0.1.1 is published on PyPI. The repository's `Publish to PyPI` GitHub Actions workflow uses PyPI Trusted Publishing, so no long-lived PyPI token is stored in GitHub. The trusted publisher is already configured for this repository.

## PyPI publisher setup

The one-time publisher setup is complete. Keep the PyPI account's recovery methods current. Do not put an API token in a repository secret for this workflow.

## Release a version

1. Update the project version consistently in `pyproject.toml` and `src/dns_sentinel/__init__.py`, and prepare release notes.
2. Run unit tests, lint, type checks, and `python -m build`. Run DNS integration checks only where network access is available.
3. Merge the release change through a pull request and wait for CI.
4. Create and publish a GitHub release whose tag matches the project version (for example `v0.1.2`). Publishing the release starts the PyPI workflow.
5. Confirm the `Publish to PyPI` workflow succeeded and verify the installed distribution from a clean environment.

PyPI releases are public and cannot be silently replaced. Publish only after reviewing the built artifacts and release notes. Never create a release tag for a version that has already been published.
