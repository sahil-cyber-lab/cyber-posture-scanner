from scanner.services.tls_scanner import check_tls_certificate
from scanner.services.risk_engine import analyze_tls_risks


tls_result = check_tls_certificate(
    "https://example.com"
)

risk_result = analyze_tls_risks(
    tls_result
)

print("TLS Result:")
print(tls_result)

print("\nTLS Risk Result:")
print(risk_result)