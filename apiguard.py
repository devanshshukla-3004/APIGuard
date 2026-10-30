#!/usr/bin/env python3
"""APIGuard: static security checks for OpenAPI JSON documents.

This tool audits a specification; it does not send requests to the target API.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
SENSITIVE_PATH = re.compile(r"(admin|auth|login|token|password|payment|billing|user|account|upload)", re.I)


def _has_security(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def audit_spec(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Return deterministic findings from an OpenAPI 3.x/Swagger 2.0 document."""
    findings: list[dict[str, str]] = []

    def add(severity: str, rule_id: str, location: str, message: str, recommendation: str) -> None:
        findings.append({
            "severity": severity,
            "rule_id": rule_id,
            "location": location,
            "message": message,
            "recommendation": recommendation,
        })

    if not isinstance(spec, dict):
        raise ValueError("The OpenAPI document root must be a JSON object.")

    version = str(spec.get("openapi") or spec.get("swagger") or "")
    if not version:
        add("HIGH", "SPEC001", "/", "OpenAPI/Swagger version is missing.",
            "Provide a valid OpenAPI 3.x or Swagger 2.0 version field.")

    servers: list[Any] = spec.get("servers", []) if isinstance(spec.get("servers", []), list) else []
    if str(spec.get("swagger", "")).startswith("2"):
        host = spec.get("host")
        scheme = spec.get("schemes", [])
        if host and "http" in scheme:
            add("HIGH", "TLS001", "host", "Swagger server permits plain HTTP.",
                "Use HTTPS for API transport and avoid documenting plaintext endpoints.")
    else:
        for index, server in enumerate(servers):
            url = server.get("url", "") if isinstance(server, dict) else ""
            if isinstance(url, str) and url.lower().startswith("http://"):
                add("HIGH", "TLS001", f"servers[{index}].url",
                    "Server URL uses unencrypted HTTP.",
                    "Use HTTPS so credentials and API data are protected in transit.")

    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    if str(spec.get("swagger", "")).startswith("2"):
        schemes = spec.get("securityDefinitions", {}) or {}

    global_security = _has_security(spec.get("security"))
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        paths = {}

    operations_seen = 0
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_lower = str(method).lower()
            if method_lower not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            operations_seen += 1
            location = f"{method_lower.upper()} {path}"
            operation_security = operation.get("security")
            explicitly_public = operation_security == []
            protected = _has_security(operation_security) or (global_security and not explicitly_public)

            if not protected:
                add("HIGH", "AUTH001", location,
                    "Operation has no declared authentication requirement.",
                    "Define an appropriate security requirement, or explicitly document why this endpoint is public.")

            if SENSITIVE_PATH.search(str(path)) and not protected:
                add("HIGH", "AUTH002", location,
                    "Potentially sensitive endpoint appears to have no authentication requirement.",
                    "Review endpoint exposure and require authentication/authorization where appropriate.")

            description = " ".join(str(operation.get(k, "")) for k in ("description", "summary")).lower()
            extensions = " ".join(str(k).lower() for k in operation.keys() if str(k).startswith("x-"))
            if not any(term in description for term in ("rate limit", "rate-limit", "throttl")) and "rate" not in extensions:
                add("INFO", "RATE001", location,
                    "No rate-limiting guidance is documented for this operation.",
                    "Document expected throttling behavior and relevant response headers or vendor extensions.")

    if operations_seen == 0:
        add("MEDIUM", "SPEC002", "paths",
            "No API operations were found in the paths object.",
            "Check that the specification contains path items and supported HTTP operations.")

    if not schemes and not global_security:
        add("MEDIUM", "AUTH003", "components.securitySchemes",
            "No reusable security scheme is declared.",
            "If the API uses authentication, define reusable schemes such as HTTP bearer or OAuth2.")

    return findings


def load_spec(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError("The document root must be a JSON object.")
    return data


def render_text(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "APIGuard: no findings from the configured static checks.\n"
    lines = [f"APIGuard findings: {len(findings)}", ""]
    for item in findings:
        lines.extend([
            f"[{item['severity']}] {item['rule_id']} — {item['location']}",
            f"  {item['message']}",
            f"  Recommendation: {item['recommendation']}",
            "",
        ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Statically audit an OpenAPI/Swagger JSON specification.")
    parser.add_argument("spec", type=Path, help="Path to an OpenAPI/Swagger JSON file")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format")
    parser.add_argument("--output", type=Path, help="Write the report to a file instead of stdout")
    args = parser.parse_args(argv)

    try:
        findings = audit_spec(load_spec(args.spec))
    except (OSError, ValueError) as exc:
        print(f"APIGuard error: {exc}", file=sys.stderr)
        return 2

    report = json.dumps({"tool": "APIGuard", "finding_count": len(findings), "findings": findings},
                        indent=2) if args.format == "json" else render_text(findings)
    if args.output:
        args.output.write_text(report + ("" if report.endswith("\n") else "\n"), encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
