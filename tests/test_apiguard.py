import unittest

from apiguard import audit_spec


class APIGuardTests(unittest.TestCase):
    def test_detects_http_server(self):
        findings = audit_spec({
            "openapi": "3.0.3",
            "servers": [{"url": "http://api.example.test"}],
            "paths": {"/health": {"get": {"security": []}}},
        })
        self.assertIn("TLS001", {item["rule_id"] for item in findings})

    def test_detects_unprotected_sensitive_operation(self):
        findings = audit_spec({
            "openapi": "3.0.3",
            "paths": {"/admin/users": {"get": {"summary": "List users"}}},
        })
        rules = {item["rule_id"] for item in findings}
        self.assertIn("AUTH001", rules)
        self.assertIn("AUTH002", rules)

    def test_global_security_protects_operation(self):
        findings = audit_spec({
            "openapi": "3.0.3",
            "security": [{"BearerAuth": []}],
            "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}},
            "paths": {"/reports": {"get": {"summary": "Get reports"}}},
        })
        self.assertNotIn("AUTH001", {item["rule_id"] for item in findings})

    def test_explicit_empty_security_overrides_global(self):
        findings = audit_spec({
            "openapi": "3.0.3",
            "security": [{"BearerAuth": []}],
            "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}}},
            "paths": {"/admin": {"get": {"security": []}}},
        })
        self.assertIn("AUTH001", {item["rule_id"] for item in findings})

    def test_rejects_non_object_root(self):
        with self.assertRaises(ValueError):
            audit_spec([])


if __name__ == "__main__":
    unittest.main()
