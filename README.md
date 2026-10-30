# APIGuard

**A lightweight static security auditor for OpenAPI / Swagger specifications.**

APIGuard reviews an API's JSON specification and reports security-relevant configuration gaps before an API is released. It is designed as a small, reproducible security engineering project with a CLI, JSON reports, and automated tests.

> **Scope:** APIGuard analyzes specification files only. It does not send traffic, authenticate to services, exploit vulnerabilities, or prove that a deployed API is vulnerable. Findings are indicators for manual review.

## Features

- Detects server URLs documented with plain HTTP.
- Flags operations without a declared authentication requirement.
- Highlights potentially sensitive paths that appear unauthenticated.
- Notes missing rate-limiting guidance in operation documentation.
- Checks for absent reusable security scheme declarations.
- Produces readable terminal output or machine-readable JSON.
- Uses Python's standard library; no third-party dependencies.

## Requirements

- Python 3.10+
- OpenAPI / Swagger specification in JSON format

## Quick start

Clone the repository, then run:

```bash
python apiguard.py samples/openapi.json
```

Generate a JSON report:

```bash
python apiguard.py samples/openapi.json --format json --output report.json
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Example output

The included sample intentionally contains issues so you can see how the checks work. Findings include a rule ID, severity, affected operation or field, explanation, and a suggested next step.

Exit codes:
- `0`: no findings from the configured checks
- `1`: one or more findings were reported
- `2`: input or file error

## Rule catalogue

| Rule | Severity | What it checks |
|---|---|---|
| TLS001 | HIGH | Plain HTTP server URL or Swagger HTTP scheme |
| AUTH001 | HIGH | Operation has no declared security requirement |
| AUTH002 | HIGH | Sensitive-looking path has no declared security requirement |
| RATE001 | INFO | Rate-limiting guidance is not documented for the operation |
| AUTH003 | MEDIUM | No reusable security scheme or global security declaration |
| SPEC001 | HIGH | OpenAPI/Swagger version field is missing |
| SPEC002 | MEDIUM | No supported operations found under paths |

Severity is a triage aid, not a CVSS score. A public health endpoint may be intentional; an operation-level empty `security` array explicitly marks an operation as public in OpenAPI. APIGuard reports the configuration for human review rather than deciding business policy.

## Project structure

```text
APIGuard/
├── apiguard.py
├── samples/
│   └── openapi.json
├── tests/
│   └── test_apiguard.py
└── .github/
    └── workflows/
        └── tests.yml
```

## Limitations

- Current input support is JSON; YAML specifications are not parsed.
- Checks are static and heuristic. Sensitive paths are identified by path-name patterns.
- Rate-limit detection looks for documentation hints; it cannot verify enforcement.
- The tool does not resolve every OpenAPI reference or validate full schema conformance.
- A missing security declaration may be intentional for a public endpoint.

## Roadmap

- YAML input support.
- More checks for CORS, deprecated operations, and insecure authentication schemes.
- SARIF output for code-scanning integrations.
- Configurable rules and severity overrides.

## Responsible use

Use APIGuard on specifications you own or are authorized to assess. Review every finding in context before treating it as a security defect.

## License

MIT
