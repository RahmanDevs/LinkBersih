from django.db import models

# Scan Log Model
class ScanLog(models.Model):
    class Classification(models.TextChoices):
        SAFE = 'SAFE', 'Safe'
        SUSPICIOUS = 'SUSPICIOUS', 'Suspicious'
        PHISHING = 'PHISHING', 'Phishing'

    url = models.URLField(max_length=2000)
    classification = models.CharField(
        max_length=20,
        choices=Classification.choices,
        default=Classification.SAFE,
    )
    confidence_score = models.FloatField(default=0.0)  # Rentang 0.0 - 1.0 atau 0-100%
    string_analysis_detail = models.JSONField(
        default=dict, blank=True
    )  # Hasil analisa algoritma string
    hermes_verification_detail = models.JSONField(
        default=dict, blank=True
    )  # Response JSON dari Hermes AI
    html_analysis_detail = models.JSONField(
        default=dict, blank=True
    )  # Hasil analisa HTML content
    llm_analysis_detail = models.JSONField(
        default=dict, blank=True
    )  # Hasil analisa LLM
    virustotal_analysis_detail = models.JSONField(
        default=dict, blank=True
    )  # Hasil analisa VirusTotal
    mistral_analysis_detail = models.JSONField(
        default=dict, blank=True
    )  # Hasil analisa Mistral LLM
    date_scanned = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date_scanned']

    def __str__(self):
        return f'{self.url} - {self.classification} ({self.confidence_score})'