# APIGuard

<p align="center">
  <strong>Find API security configuration gaps before they reach production.</strong>
</p>

<p align="center">
  A lightweight, dependency-free CLI that audits OpenAPI and Swagger JSON specifications for security-relevant configuration issues.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Dependencies" src="https://img.shields.io/badge/Dependencies-None-2ea44f">
  <img alt="Analysis" src="https://img.shields.io/badge/Analysis-Static-orange">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-blue">
</p>

---

## Why APIGuard?

API specifications are more than documentation: they describe how an API is exposed and what security controls are expected around its operations. Missing authentication declarations, insecure server URLs, or undocumented rate-limiting expectations can be easy to overlook during review.

**APIGuard** helps developers and security learners spot these configuration gaps early. Point it at an OpenAPI/Swagger JSON file and get actionable findings in your terminal or a JSON report.

> **Important:** APIGuard performs static analysis of specification files. It does not contact live APIs, test runtime controls, exploit endpoints, or establish that a service is vulnerable. Treat findings as review signals—not proof of exploitability.

## What it checks

| Rule | Severity | Detection |
|---|---|---|
| `TLS001` | HIGH | Server URLs or Swagger schemes using plain HTTP |
| `AUTH001` | HIGH | Operations without a declared security requirement |
| `AUTH002` | HIGH | Sensitive-looking paths without a declared security requirement |
| `AUTH003` | MEDIUM | Missing reusable security scheme / global security declaration |
| `SPEC001` | HIGH | Missing OpenAPI or Swagger version field |
| `SPEC002` | MEDIUM | No supported operations found under `paths` |
| `RATE001` | INFO | No rate-limiting guidance detected in operation documentation |

Severity is a triage aid, not a CVSS score. Public endpoints may be intentional. In OpenAPI, an operation-level empty `security: []` explicitly makes that operation public; review it against the API's intended design.

## Quick start

### 1. Requirements

- Python 3.10 or newer
- An OpenAPI / Swagger specification in JSON format
- No third-party Python packages required

### 2. Clone the project

```bash
git clone https://github.com/devanshshukla-3004/APIGuard.git
cd APIGuard
```

### 3. Run an audit

Use the included sample specification:

```bash
python apiguard.py samples/openapi.json
```

### 4. Export a JSON report

```bash
python apiguard.py samples/openapi.json --format json --output report.json
```

### 5. Run the test suite

```bash
python -m unittest discover -s tests -v
```

## How it works

1. **Load** — reads a local OpenAPI/Swagger JSON document.
2. **Inspect** — evaluates supported specification fields and operations against APIGuard's security rules.
3. **Report** — prints findings or writes a machine-readable JSON report.
4. **Review** — use each rule ID and recommendation to investigate the API's intended security design.

Each finding identifies the rule, severity, affected location, explanation, and a suggested next step.

## Example workflow

```bash
# Audit the bundled example
python apiguard.py samples/openapi.json

# Save findings for another tool or review
python apiguard.py samples/openapi.json --format json --output report.json

# Run automated tests
python -m unittest discover -s tests -v
```

The bundled sample is intentionally configured to exercise detection rules. It is a test fixture—not a real production API.

## Project structure

```text
APIGuard/
├── apiguard.py                 # CLI and static analysis rules
├── samples/
│   └── openapi.json            # Example specification for testing
├── tests/
│   └── test_apiguard.py        # Automated unit tests
├── .github/
│   └── workflows/
│       └── tests.yml           # GitHub Actions test workflow
├── .gitignore
└── README.md
```

## Current scope and limitations

- **Input:** JSON specifications only; YAML parsing is not currently implemented.
- **Analysis:** static and heuristic; it does not send network requests.
- **Sensitive paths:** identified through path-name patterns, so false positives and false negatives are possible.
- **Rate limiting:** checks for documentation hints only; it cannot verify actual throttling or enforcement.
- **Authentication:** checks declared security configuration; it does not validate identity-provider behavior, token correctness, or authorization logic.
- **Specification validation:** does not replace a complete OpenAPI schema validator and does not resolve every possible reference.

Always inspect findings in the context of the API's intended behavior.

## Roadmap

- [ ] Add YAML specification support
- [ ] Expand checks for CORS and insecure authentication patterns
- [ ] Add SARIF output for code-scanning workflows
- [ ] Support configurable rules and severity overrides
- [ ] Improve reference resolution and specification validation

## Responsible use

Use APIGuard with API specifications you own or are explicitly authorized to assess. Do not interpret a static finding as confirmation of a live vulnerability without appropriate validation.

## License

This project is released under the [MIT License](LICENSE).

---

<p align="center">
  Built as a practical API security engineering project.
</p>
