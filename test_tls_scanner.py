from scanner.services.tls_scanner import check_tls_certificate


result = check_tls_certificate(
    "https://example.com"
)

print(result)