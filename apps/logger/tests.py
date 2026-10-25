from django.test import Client, TestCase
from apps.logger.models import ScanLog


class ScanLogModelAndLoggerViewTests(TestCase):
    """Skenario pengujian model ScanLog, pencarian, pemfilteran, dan paginasi."""

    def setUp(self):
        self.client = Client()
        # Seed test logs
        self.log_safe = ScanLog.objects.create(
            url="https://google.com",
            classification=ScanLog.Classification.SAFE,
            confidence_score=0.0,
            hermes_verification_detail={"threat_level": "LOW", "ai_notes": "Aman"},
        )
        self.log_suspicious = ScanLog.objects.create(
            url="https://bit.ly/claim-bonus-2026",
            classification=ScanLog.Classification.SUSPICIOUS,
            confidence_score=0.55,
            hermes_verification_detail={"threat_level": "HIGH", "ai_notes": "Mencurigakan"},
        )
        self.log_phishing = ScanLog.objects.create(
            url="https://fake-bank-login.xyz",
            classification=ScanLog.Classification.PHISHING,
            confidence_score=0.95,
            hermes_verification_detail={"threat_level": "CRITICAL", "ai_notes": "Phishing"},
        )

    def test_scanlog_str_representation(self):
        self.assertIn("https://google.com", str(self.log_safe))
        self.assertIn("SAFE", str(self.log_safe))

    def test_logger_view_default(self):
        response = self.client.get("/logger/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "google.com")
        self.assertContains(response, "fake-bank-login.xyz")

    def test_logger_filter_safe(self):
        response = self.client.get("/logger/?status=safe")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "google.com")
        self.assertNotContains(response, "fake-bank-login.xyz")

    def test_logger_filter_phishing(self):
        response = self.client.get("/logger/?status=phishing")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "fake-bank-login.xyz")
        self.assertNotContains(response, "google.com")

    def test_logger_filter_suspicious(self):
        response = self.client.get("/logger/?status=suspicious")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "bit.ly/claim-bonus-2026")
        self.assertNotContains(response, "google.com")

    def test_logger_search_query(self):
        response = self.client.get("/logger/?q=fake-bank")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "fake-bank-login.xyz")
        self.assertNotContains(response, "google.com")

    def test_logger_pagination_invalid_page_handles_gracefully(self):
        # Invalid page non-numeric should default to page 1
        resp_invalid = self.client.get("/logger/?page=notanumber")
        self.assertEqual(resp_invalid.status_code, 200)

        # Out-of-range page should default to last page
        resp_out_of_range = self.client.get("/logger/?page=99999")
        self.assertEqual(resp_out_of_range.status_code, 200)
