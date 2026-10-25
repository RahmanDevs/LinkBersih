from unittest.mock import patch
from django.core.cache import cache
from django.test import Client, TestCase
from apps.core.services import PhishingDetectorService
from apps.logger.models import ScanLog


class SSRFDefenseTests(TestCase):
    """Skenario pengujian ketahanan keamanan terhadap Server-Side Request Forgery (SSRF)."""

    def test_blocks_loopback_and_localhost(self):
        is_safe, reason = PhishingDetectorService.validate_safe_url("http://127.0.0.1:8000/admin")
        self.assertFalse(is_safe)
        self.assertIn("blocked", reason.lower())

        is_safe, reason = PhishingDetectorService.validate_safe_url("http://localhost:8000")
        self.assertFalse(is_safe)
        self.assertIn("blocked", reason.lower())

    def test_blocks_private_ip_ranges(self):
        private_ips = [
            "http://10.0.0.1/internal-status",
            "http://192.168.1.1/router-login",
            "http://172.16.0.5/api/metrics",
        ]
        for url in private_ips:
            is_safe, reason = PhishingDetectorService.validate_safe_url(url)
            self.assertFalse(is_safe, f"URL {url} seharusnya diblokir oleh filter SSRF.")
            self.assertIn("blocked", reason.lower())

    def test_blocks_cloud_metadata_service(self):
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        for url in metadata_urls:
            is_safe, reason = PhishingDetectorService.validate_safe_url(url)
            self.assertFalse(is_safe, f"Metadata service {url} seharusnya diblokir.")

    def test_blocks_disallowed_schemes(self):
        disallowed = [
            "file:///etc/passwd",
            "ftp://files.internal.org/",
            "gopher://internal.lan/",
        ]
        for url in disallowed:
            is_safe, reason = PhishingDetectorService.validate_safe_url(url)
            self.assertFalse(is_safe, f"Skema {url} seharusnya ditolak.")

    def test_inspect_transit_triggers_ssrf_indicator(self):
        result = PhishingDetectorService.inspect_transit_and_page("http://127.0.0.1:9999/status")
        self.assertTrue(result["indicators"]["ssrf_blocked"])
        self.assertTrue(result["indicators"]["connection_failed"])
        self.assertTrue(any("Security Policy" in r for r in result["reasons"]))


class PhishingClassificationLogicTests(TestCase):
    """Skenario pengujian akurasi logika skor risiko dan klasifikasi ancaman."""

    def test_high_risk_score_is_classified_as_phishing(self):
        classification = PhishingDetectorService.classify_score(0.95)
        self.assertEqual(classification["verdict"], ScanLog.Classification.PHISHING)
        self.assertEqual(classification["threat_level"], "CRITICAL")
        self.assertIn("BERBAHAYA/PHISHING", classification["message"])

    def test_medium_risk_score_is_classified_as_suspicious(self):
        classification = PhishingDetectorService.classify_score(0.55)
        self.assertEqual(classification["verdict"], ScanLog.Classification.SUSPICIOUS)
        self.assertEqual(classification["threat_level"], "HIGH")
        self.assertIn("MENCURIGAKAN", classification["message"])

    def test_low_risk_score_is_classified_as_safe(self):
        classification = PhishingDetectorService.classify_score(0.10)
        self.assertEqual(classification["verdict"], ScanLog.Classification.SAFE)
        self.assertEqual(classification["threat_level"], "LOW")
        self.assertIn("AMAN", classification["message"])

    def test_whitelisted_domain_always_safe(self):
        classification = PhishingDetectorService.classify_score(0.99, is_whitelisted=True)
        self.assertEqual(classification["verdict"], ScanLog.Classification.SAFE)
        self.assertEqual(classification["threat_level"], "LOW")
        self.assertIn("whitelist", classification["message"].lower())


class DomainParsingAndBrandDetectionTests(TestCase):
    """Skenario pengujian parsing domain ccTLD bertingkat dan deteksi peniruan brand."""

    def test_cctld_multi_part_parsing(self):
        # Indonesian second-level domain
        reg_domain, label, subs = PhishingDetectorService.extract_domain_parts("klikbca.co.id")
        self.assertEqual(reg_domain, "klikbca.co.id")
        self.assertEqual(label, "klikbca")
        self.assertEqual(subs, [])

        # Subdomain on ccTLD
        reg_domain, label, subs = PhishingDetectorService.extract_domain_parts("m.ib.bri.co.id")
        self.assertEqual(reg_domain, "bri.co.id")
        self.assertEqual(label, "bri")
        self.assertEqual(subs, ["m", "ib"])

        # UK ccTLD
        reg_domain, label, subs = PhishingDetectorService.extract_domain_parts("portal.co.uk")
        self.assertEqual(reg_domain, "portal.co.uk")
        self.assertEqual(label, "portal")

        # Standard gTLD
        reg_domain, label, subs = PhishingDetectorService.extract_domain_parts("accounts.google.com")
        self.assertEqual(reg_domain, "google.com")
        self.assertEqual(label, "google")
        self.assertEqual(subs, ["accounts"])

    def test_whitelist_matches_cctld_and_subdomain(self):
        self.assertTrue(PhishingDetectorService.is_whitelisted("https://bca.co.id"))
        self.assertTrue(PhishingDetectorService.is_whitelisted("https://www.bca.co.id"))
        self.assertTrue(PhishingDetectorService.is_whitelisted("https://klikbca.com"))
        self.assertTrue(PhishingDetectorService.is_whitelisted("https://google.com/search"))
        self.assertFalse(PhishingDetectorService.is_whitelisted("https://attacker-bca-login.xyz"))

    def test_brand_impersonation_detection(self):
        # 3-letter Indonesian brand prefix token
        analysis = PhishingDetectorService.analyze_domain("https://bca-secure-login.com")
        self.assertTrue(analysis["indicators"]["brand_impersonation"])
        self.assertIn("bca", " ".join(analysis["reasons"]).lower())

        # Typosquatting on 4+ letter brand
        analysis2 = PhishingDetectorService.analyze_domain("https://goog1e.xyz")
        self.assertTrue(analysis2["indicators"]["brand_impersonation"])

    def test_entropy_calculation(self):
        low_entropy = PhishingDetectorService.calculate_entropy("aaaaaaa")
        high_entropy = PhishingDetectorService.calculate_entropy("x8z9q1w4m2k7")
        self.assertEqual(low_entropy, 0.0)
        self.assertGreater(high_entropy, 3.0)


class InputValidationAndHomeViewTests(TestCase):
    """Skenario pengujian ketahanan input dan fungsionalitas Home View."""

    def setUp(self):
        self.client = Client()
        cache.clear()

    def test_normalize_url(self):
        self.assertEqual(
            PhishingDetectorService.normalize_url("google.com"),
            "https://google.com",
        )
        self.assertEqual(
            PhishingDetectorService.normalize_url("http://example.com/test"),
            "http://example.com/test",
        )
        with self.assertRaises(ValueError):
            PhishingDetectorService.normalize_url("")

        with self.assertRaises(ValueError):
            PhishingDetectorService.normalize_url("javascript:alert(1)")

        with self.assertRaises(ValueError):
            PhishingDetectorService.normalize_url("file:///etc/hosts")

    def test_home_view_get(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Save")
        self.assertContains(response, "Check Safety")

    def test_home_view_post_invalid_url_handles_gracefully(self):
        response = self.client.post("/", {"url": "javascript:void(0)"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Validasi URL Gagal")

    def test_home_view_post_whitelisted_url(self):
        response = self.client.post("/", {"url": "https://google.com"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Scan Result")
        self.assertContains(response, "Safe")

    @patch.object(PhishingDetectorService, 'analyze_with_llm')
    @patch.object(PhishingDetectorService, 'inspect_transit_and_page')
    def test_end_to_end_phishing_scan_classified_as_phishing(self, mock_transit, mock_llm):
        mock_transit.return_value = {
            "transit_confidence": 0.80,
            "reasons": ["Password harvesting form detected"],
            "indicators": {"password_form": True},
            "redirect_chain": [],
            "external_links_count": 0,
        }
        mock_llm.return_value = {
            "llm_confidence": 0.90,
            "llm_reasons": ["Impersonates banking credentials"],
            "llm_prediction": "PHISHING",
            "llm_score": 0.90,
        }

        scan_log = PhishingDetectorService.scan_and_save("https://bca-login-verification.xyz")
        self.assertEqual(scan_log.classification, ScanLog.Classification.PHISHING)
        self.assertGreaterEqual(scan_log.confidence_score, 0.70)
        self.assertEqual(scan_log.hermes_verification_detail["threat_level"], "CRITICAL")
        self.assertIn("BERBAHAYA/PHISHING", scan_log.hermes_verification_detail["message"])

    def test_home_view_rate_limiting(self):
        cache.clear()
        # Lakukan 20 request
        for _ in range(20):
            resp = self.client.post("/", {"url": "https://google.com"})
            self.assertEqual(resp.status_code, 200)

        # Request ke-21 harus terkena rate limit
        resp_blocked = self.client.post("/", {"url": "https://google.com"})
        self.assertEqual(resp_blocked.status_code, 200)
        self.assertContains(resp_blocked, "Terlalu banyak permintaan pemindaian")
