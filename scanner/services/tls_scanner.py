import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_tls_certificate(url):

    parsed = urlparse(url)

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                # Certificate expiry
                expiry_date = datetime.strptime(
                    certificate["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)

                days_remaining = (
                    expiry_date - now
                ).days

                if days_remaining < 0:
                    certificate_status = "Expired"
                else:
                    certificate_status = "Valid"

                # Certificate issuer
                issuer = "Unknown"

                for item in certificate.get("issuer", []):
                    for key, value in item:
                        if key == "commonName":
                            issuer = value

                return {
                    "success": True,
                    "hostname": hostname,
                    "hostname_valid": True,
                    "tls_version": secure_socket.version(),
                    "cipher": secure_socket.cipher()[0],
                    "certificate_status": certificate_status,
                    "issuer": issuer,
                    "expiry_date": expiry_date.strftime(
                        "%Y-%m-%d"
                    ),
                    "days_remaining": days_remaining
                }

    except ssl.CertificateError as error:

        return {
            "success": False,
            "hostname": hostname,
            "hostname_valid": False,
            "error": f"Certificate hostname validation failed: {error}"
        }

    except Exception as error:

        return {
            "success": False,
            "hostname": hostname,
            "hostname_valid": False,
            "error": str(error)
        }