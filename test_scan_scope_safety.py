import unittest
from unittest.mock import MagicMock, patch

import sql_injection_tester as scanner


class ScanScopeSafetyTests(unittest.TestCase):
    def test_blocks_loopback_by_default(self):
        with self.assertRaises(ValueError):
            scanner.validate_target_url("http://127.0.0.1/login")

    def test_private_target_requires_explicit_opt_in(self):
        parsed = scanner.validate_target_url("http://127.0.0.1/login", allow_private=True)
        self.assertEqual(parsed.hostname, "127.0.0.1")

    def test_rejects_embedded_url_credentials(self):
        with self.assertRaises(ValueError):
            scanner.validate_target_url("https://user:pass@example.com/")

    def test_same_origin_compares_effective_ports(self):
        self.assertTrue(scanner.same_origin("https://example.com/a", "https://example.com/b"))
        self.assertFalse(scanner.same_origin("https://example.com/", "http://example.com/"))
        self.assertFalse(scanner.same_origin("https://example.com/", "https://other.example/"))
        self.assertFalse(scanner.same_origin("https://example.com/", "https://example.com:8443/"))

    def test_cross_origin_form_action_is_never_submitted(self):
        session = MagicMock()
        form = {"action": "http://127.0.0.1/admin", "method": "post", "inputs": []}
        result = scanner.submit_form(form, "https://public.example/login", "payload", session)
        self.assertIsNone(result)
        session.post.assert_not_called()
        session.get.assert_not_called()

    def test_scan_delay_is_bounded_before_network_requests(self):
        with self.assertRaises(ValueError):
            scanner.scan("http://127.0.0.1/", delay=0, allow_private_targets=True)


if __name__ == "__main__":
    unittest.main()
