"""Tests for the web GUI."""

import unittest
import json


class TestWebApp(unittest.TestCase):

    def setUp(self):
        from keyshield.web.app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_index_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"KeyShield", resp.data)

    def test_scan_page(self):
        resp = self.client.get("/scan")
        self.assertEqual(resp.status_code, 200)

    def test_history_page(self):
        resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)

    def test_settings_page(self):
        resp = self.client.get("/settings")
        self.assertEqual(resp.status_code, 200)

    def test_api_system(self):
        resp = self.client.get("/api/system")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("system_info", data)
        self.assertIn("is_admin", data)

    def test_api_scan_status(self):
        resp = self.client.get("/api/scan/status")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("running", data)

    def test_api_scan_result_no_result(self):
        resp = self.client.get("/api/scan/result")
        self.assertEqual(resp.status_code, 404)

    def test_api_history_empty(self):
        resp = self.client.get("/api/history")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("history", data)

    def test_api_reports(self):
        resp = self.client.get("/api/reports")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("reports", data)

    def test_report_not_found(self):
        resp = self.client.get("/report/nonexistent-id")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Report Not Found", resp.data)

    def test_path_traversal_protection(self):
        resp = self.client.get("/api/reports/download/../../etc/passwd")
        self.assertIn(resp.status_code, [404, 400, 500])

    def test_scan_start_returns_json(self):
        resp = self.client.post(
            "/api/scan/start",
            data=json.dumps({"quick": True}),
            content_type="application/json",
        )
        self.assertIn(resp.status_code, [200, 409])


if __name__ == "__main__":
    unittest.main()
