from django.db import models
from django.contrib.auth.models import User

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    url = models.URLField(max_length=2000)
    is_phishing = models.BooleanField(default=False)
    risk_score = models.IntegerField(default=0)
    reasons = models.TextField(blank=True)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url