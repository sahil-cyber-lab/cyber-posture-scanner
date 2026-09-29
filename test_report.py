import os
import django

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "cyber_posture.settings"
)

django.setup()


from scanner.models import Scan
from scanner.services.report_generator import generate_security_report


# Latest scan
scan = Scan.objects.order_by(
    "-created_at"
).first()


if scan is None:

    print("No scan found in database.")

else:

    findings = scan.findings.all()

    output_path = "security_report.pdf"

    generate_security_report(
        scan,
        findings,
        output_path
    )

    print("PDF report generated successfully.")
    print("File:", output_path)