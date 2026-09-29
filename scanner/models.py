from django.db import models
from django.contrib.auth.models import User


class Scan(models.Model):

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="scans"
    )

    target = models.CharField(
        max_length=255
    )

    target_type = models.CharField(
        max_length=50
    )

    status = models.CharField(
        max_length=50,
        default="Completed"
    )

    score = models.IntegerField(
        default=0
    )

    risk_level = models.CharField(
        max_length=20,
        default="Low"
    )

    total_risk = models.IntegerField(
        default=0
    )
    
    web_scan_data = models.JSONField(
    default=dict,
    blank=True
    )
    
    tls_scan_data = models.JSONField(
    default=dict,
    blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return f"{self.target} - {self.score}/100"


class Finding(models.Model):

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name="findings"
    )

    title = models.CharField(
        max_length=255
    )

    port = models.CharField(
        max_length=50
    )

    service = models.CharField(
        max_length=100
    )

    product = models.CharField(
        max_length=255,
        blank=True
    )

    version = models.CharField(
        max_length=100,
        blank=True
    )

    extra_info = models.TextField(
        blank=True
    )

    severity = models.CharField(
        max_length=20
    )

    risk_points = models.IntegerField(
        default=0
    )

    description = models.TextField()

    recommendation = models.TextField(
        blank=True
    )

    security_intelligence = models.JSONField(
    default=dict,
    blank=True
    )

    cve_intelligence = models.JSONField(
    default=dict,
    blank=True
    )

    def __str__(self):
        return self.title