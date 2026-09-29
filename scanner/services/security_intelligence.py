# ==========================================================
# SECURITY INTELLIGENCE
# ==========================================================
#
# This module analyzes product/version information detected
# by Nmap and provides additional security intelligence.
#
# IMPORTANT:
# This module does NOT claim that a specific CVE exists.
# Exact vulnerability verification requires checking the
# vendor advisory / CVE database against the exact product,
# version, OS and patch level.
# ==========================================================


# ==========================================================
# PRODUCT SECURITY RULES
# ==========================================================

PRODUCT_RULES = {

    "openssh": {
        "name": "OpenSSH",
        "description": (
            "SSH service detected with a specific OpenSSH "
            "version. Older or unsupported versions may contain "
            "known security issues depending on the exact "
            "vendor build and patch level."
        ),
        "recommendation": (
            "Verify the installed OpenSSH version against the "
            "vendor's security advisories and apply available "
            "security updates."
        )
    },

    "apache": {
        "name": "Apache HTTP Server",
        "description": (
            "Apache HTTP Server version information was detected. "
            "Security exposure depends on the exact version, "
            "configuration and installed vendor patches."
        ),
        "recommendation": (
            "Verify the Apache version against current vendor "
            "security advisories and keep the server updated."
        )
    },

    "nginx": {
        "name": "Nginx",
        "description": (
            "Nginx version information was detected. The security "
            "posture depends on the exact version and configuration."
        ),
        "recommendation": (
            "Verify the installed Nginx version against vendor "
            "security advisories and apply security updates."
        )
    },

    "microsoft iis": {
        "name": "Microsoft IIS",
        "description": (
            "Microsoft IIS service information was detected. "
            "Security exposure depends on the installed IIS "
            "version, Windows build and applied security updates."
        ),
        "recommendation": (
            "Keep Windows and IIS fully patched and verify the "
            "detected version against Microsoft's security advisories."
        )
    },

    "mysql": {
        "name": "MySQL",
        "description": (
            "MySQL database service information was detected. "
            "Database exposure should be restricted to trusted "
            "applications and networks."
        ),
        "recommendation": (
            "Restrict MySQL network access and keep the database "
            "server updated according to vendor security advisories."
        )
    },

    "postgresql": {
        "name": "PostgreSQL",
        "description": (
            "PostgreSQL database service information was detected. "
            "Direct network exposure can increase the attack surface."
        ),
        "recommendation": (
            "Restrict PostgreSQL access to trusted systems and "
            "apply available security updates."
        )
    },

    "microsoft sql server": {
        "name": "Microsoft SQL Server",
        "description": (
            "Microsoft SQL Server information was detected. "
            "Database exposure and outdated builds may increase "
            "security risk."
        ),
        "recommendation": (
            "Restrict database access and apply current Microsoft "
            "SQL Server security updates."
        )
    },

    "ftp": {
        "name": "FTP",
        "description": (
            "FTP service information was detected. Traditional "
            "FTP does not provide encrypted communication."
        ),
        "recommendation": (
            "Disable FTP when unnecessary or migrate to a secure "
            "alternative such as SFTP."
        )
    },

    "telnet": {
        "name": "Telnet",
        "description": (
            "Telnet service information was detected. Telnet does "
            "not provide modern encrypted communication."
        ),
        "recommendation": (
            "Disable Telnet and use SSH or another secure "
            "remote administration protocol."
        )
    }
}


# ==========================================================
# FIND PRODUCT RULE
# ==========================================================

def find_product_rule(product, service):
    """
    Try to identify a known product from Nmap's product
    and service fields.
    """

    product_text = (
        product or ""
    ).lower().strip()

    service_text = (
        service or ""
    ).lower().strip()

    # ------------------------------------------------------
    # PRODUCT MATCH
    # ------------------------------------------------------

    for keyword, rule in PRODUCT_RULES.items():

        if keyword in product_text:

            return rule

    # ------------------------------------------------------
    # SERVICE MATCH
    # ------------------------------------------------------

    for keyword, rule in PRODUCT_RULES.items():

        if keyword == service_text:

            return rule

    return None


# ==========================================================
# ANALYZE PRODUCT / VERSION
# ==========================================================

def analyze_product_version(
    product="",
    version="",
    service=""
):
    """
    Analyze product and version information detected by Nmap.

    Returns structured security intelligence.
    """

    product = (
        product or ""
    ).strip()

    version = (
        version or ""
    ).strip()

    service = (
        service or ""
    ).strip()

    # ======================================================
    # NO PRODUCT / VERSION INFORMATION
    # ======================================================

    if not product and not version:

        return {
            "detected": False,
            "product": "",
            "version": "",
            "status": "No version information detected",
            "severity": "Informational",
            "risk_points": 0,
            "description": (
                "Nmap did not provide product or version "
                "information for this service."
            ),
            "recommendation": (
                "Verify the service and version manually or "
                "perform additional authorized service detection."
            )
        }

    # ======================================================
    # PRODUCT RULE
    # ======================================================

    rule = find_product_rule(
        product,
        service
    )

    # ======================================================
    # KNOWN PRODUCT
    # ======================================================

    if rule:

        if version:

            status = (
                f"{rule['name']} {version} detected"
            )

        else:

            status = (
                f"{rule['name']} detected; "
                "version not identified"
            )

        return {
            "detected": True,
            "product": product,
            "version": version,
            "status": status,
            "severity": "Informational",
            "risk_points": 0,
            "description": rule["description"],
            "recommendation": rule["recommendation"]
        }

    # ======================================================
    # UNKNOWN PRODUCT
    # ======================================================

    product_name = product or service or "Unknown service"

    if version:

        status = (
            f"{product_name} {version} detected"
        )

        description = (
            f"Product/version information was detected: "
            f"{product_name} {version}. "
            "The exact security posture should be verified "
            "against the vendor's security advisories."
        )

    else:

        status = (
            f"{product_name} detected; "
            "version not identified"
        )

        description = (
            f"The service '{product_name}' was detected, "
            "but a version was not identified."
        )

    return {
        "detected": True,
        "product": product,
        "version": version,
        "status": status,
        "severity": "Informational",
        "risk_points": 0,
        "description": description,
        "recommendation": (
            "Verify the product, exact version and patch level "
            "against the vendor's security advisories."
        )
    }


# ==========================================================
# ANALYZE NMAP PORTS
# ==========================================================

def analyze_nmap_intelligence(ports):
    """
    Analyze all Nmap-detected ports and return security
    intelligence for each detected service.
    """

    intelligence = []

    for port in ports:

        product = port.get(
            "product",
            ""
        )

        version = port.get(
            "version",
            ""
        )

        service = port.get(
            "service",
            "unknown"
        )

        result = analyze_product_version(
            product=product,
            version=version,
            service=service
        )

        result["port"] = port.get(
            "port",
            ""
        )

        result["service"] = service

        result["extrainfo"] = port.get(
            "extrainfo",
            ""
        )

        intelligence.append(
            result
        )

    return intelligence