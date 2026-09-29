from .security_intelligence import analyze_product_version
from .cve_intelligence import search_product_version


# ==========================================================
# RISK ENGINE V2
# ==========================================================
#
# Risk model:
#
#   Exposure Risk
#   + Configuration Risk
#   + CVE Risk
#   + TLS Risk
#   ----------------
#   = Total Risk
#
# The final score is:
#
#   100 - Total Risk
#
# Risk is capped at a minimum score of 0.
#
# CVEs are NOT summed together.
# Only the highest applicable CVSS contributes CVE risk.
#
# ==========================================================


# ==========================================================
# CVSS RISK CALCULATION
# ==========================================================

def cvss_to_risk_points(cvss_score):
    """
    Convert CVSS score into controlled risk points.

    CVSS:
        0.0        -> 0
        0.1 - 3.9  -> 3
        4.0 - 6.9  -> 7
        7.0 - 8.9  -> 12
        9.0 - 10.0 -> 18
    """

    if cvss_score is None:
        return 0

    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return 0

    if score <= 0:
        return 0

    if score <= 3.9:
        return 3

    if score <= 6.9:
        return 7

    if score <= 8.9:
        return 12

    return 18


def calculate_cve_risk(cve_intelligence):
    """
    Calculate CVE risk using the highest applicable CVSS.

    Multiple CVEs are NOT added together.
    """

    if not cve_intelligence:

        return {
            "cve_risk_points": 0,
            "highest_cvss": None,
            "highest_severity": "Unknown",
            "cve_count": 0
        }

    if not cve_intelligence.get(
        "success",
        False
    ):

        return {
            "cve_risk_points": 0,
            "highest_cvss": None,
            "highest_severity": "Unknown",
            "cve_count": 0
        }

    vulnerabilities = cve_intelligence.get(
        "vulnerabilities",
        []
    )

    valid_vulnerabilities = []

    for vulnerability in vulnerabilities:

        cvss_score = vulnerability.get(
            "cvss_score"
        )

        if cvss_score is None:
            continue

        try:
            score = float(cvss_score)
        except (TypeError, ValueError):
            continue

        valid_vulnerabilities.append({
            "score": score,
            "severity": vulnerability.get(
                "severity",
                "Unknown"
            )
        })

    if not valid_vulnerabilities:

        return {
            "cve_risk_points": 0,
            "highest_cvss": None,
            "highest_severity": "Unknown",
            "cve_count": 0
        }

    highest = max(
        valid_vulnerabilities,
        key=lambda item: item["score"]
    )

    return {
        "cve_risk_points": cvss_to_risk_points(
            highest["score"]
        ),
        "highest_cvss": highest["score"],
        "highest_severity": highest["severity"],
        "cve_count": len(valid_vulnerabilities)
    }


# ==========================================================
# FINDING HELPER
# ==========================================================

def create_finding(
    title,
    port="-",
    service="",
    product="",
    version="",
    extrainfo="",
    severity="Informational",
    risk_points=0,
    description="",
    recommendation="",
    category="",
    risk_source=""
):
    """
    Create a consistent finding structure.

    Existing fields are preserved for compatibility
    with templates, PDF reports and database saving.
    """

    return {
        "title": title,
        "port": port,
        "service": service,
        "product": product,
        "version": version,
        "extrainfo": extrainfo,
        "severity": severity,
        "risk_points": risk_points,
        "description": description,
        "recommendation": recommendation,
        "category": category,
        "risk_source": risk_source
    }


# ==========================================================
# NMAP RISK ANALYSIS
# ==========================================================

def analyze_risks(ports):

    findings = []

    total_risk = 0

    exposure_risk = 0

    cve_risk_total = 0

    configuration_risk = 0

    for port in ports:

        port_number = str(
            port.get(
                "port_number",
                port["port"].split("/")[0]
            )
        )

        service = port.get(
            "service",
            "unknown"
        )

        product = port.get(
            "product",
            ""
        )

        version = port.get(
            "version",
            ""
        )

        extrainfo = port.get(
            "extrainfo",
            ""
        )

        # ======================================================
        # SECURITY INTELLIGENCE
        # ======================================================

        security_intelligence = (
            analyze_product_version(
                product=product,
                version=version,
                service=service
            )
        )

        # ======================================================
        # CVE INTELLIGENCE
        # ======================================================

        cve_intelligence = {
            "success": False,
            "total_results": 0,
            "vulnerabilities": [],
            "error": ""
        }

        if product and version:

            try:

                cve_intelligence = (
                    search_product_version(
                        product=product,
                        version=version
                    )
                )

            except Exception as error:

                cve_intelligence = {
                    "success": False,
                    "total_results": 0,
                    "vulnerabilities": [],
                    "error": str(error)
                }

        # ======================================================
        # CVE RISK
        # ======================================================

        cve_risk = calculate_cve_risk(
            cve_intelligence
        )

        cve_risk_points = cve_risk[
            "cve_risk_points"
        ]

        # ======================================================
        # BASE EXPOSURE RISK
        # ======================================================

        base_finding = None

        base_risk = 0

        # ------------------------------------------------------
        # SMB
        # ------------------------------------------------------

        if port_number == "445":

            base_risk = 10

            base_finding = create_finding(
                title="SMB service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Medium",
                risk_points=base_risk,
                description=(
                    "SMB is exposed on the target. "
                    "SMB exposure can increase the attack "
                    "surface when access is not properly "
                    "restricted."
                ),
                recommendation=(
                    "Restrict SMB access to trusted networks "
                    "and disable unnecessary SMB services."
                ),
                category="Exposure",
                risk_source="Network service exposure"
            )

        # ------------------------------------------------------
        # HTTP
        # ------------------------------------------------------

        elif service in [
            "http",
            "http-alt"
        ]:

            base_risk = 5

            base_finding = create_finding(
                title="HTTP service detected",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Low",
                risk_points=base_risk,
                description=(
                    "An HTTP service is exposed on the target."
                ),
                recommendation=(
                    "Use HTTPS where appropriate and redirect "
                    "unencrypted HTTP traffic to HTTPS."
                ),
                category="Exposure",
                risk_source="Network service exposure"
            )

        # ------------------------------------------------------
        # RDP
        # ------------------------------------------------------

        elif port_number == "3389":

            base_risk = 10

            base_finding = create_finding(
                title="RDP service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Medium",
                risk_points=base_risk,
                description=(
                    "Remote Desktop Protocol is exposed "
                    "on the target."
                ),
                recommendation=(
                    "Restrict RDP access to trusted networks "
                    "or use a VPN and strong authentication."
                ),
                category="Exposure",
                risk_source="Remote administration exposure"
            )

        # ------------------------------------------------------
        # FTP
        # ------------------------------------------------------

        elif port_number == "21":

            base_risk = 10

            base_finding = create_finding(
                title="FTP service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Medium",
                risk_points=base_risk,
                description=(
                    "FTP is exposed on the target. "
                    "Traditional FTP does not provide "
                    "encrypted communication."
                ),
                recommendation=(
                    "Disable FTP when unnecessary or use "
                    "a secure alternative such as SFTP."
                ),
                category="Exposure",
                risk_source="Insecure service exposure"
            )

        # ------------------------------------------------------
        # TELNET
        # ------------------------------------------------------

        elif port_number == "23":

            base_risk = 20

            base_finding = create_finding(
                title="Telnet service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="High",
                risk_points=base_risk,
                description=(
                    "Telnet is exposed on the target. "
                    "Telnet transmits communication "
                    "without modern transport encryption."
                ),
                recommendation=(
                    "Disable Telnet and use SSH or another "
                    "secure remote administration protocol."
                ),
                category="Exposure",
                risk_source="Insecure service exposure"
            )

        # ------------------------------------------------------
        # SSH
        # ------------------------------------------------------

        elif port_number == "22":

            base_risk = 3

            base_finding = create_finding(
                title="SSH service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Low",
                risk_points=base_risk,
                description=(
                    "SSH is exposed on the target."
                ),
                recommendation=(
                    "Restrict SSH access to trusted networks "
                    "and use strong authentication."
                ),
                category="Exposure",
                risk_source="Remote administration exposure"
            )

        # ------------------------------------------------------
        # DATABASE
        # ------------------------------------------------------

        elif port_number in [
            "3306",
            "5432",
            "1433",
            "1521",
            "27017"
        ]:

            base_risk = 10

            base_finding = create_finding(
                title="Database service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Medium",
                risk_points=base_risk,
                description=(
                    "A database service is exposed on the "
                    "network. Direct external exposure can "
                    "increase the attack surface."
                ),
                recommendation=(
                    "Restrict database access to trusted "
                    "applications and networks. Do not expose "
                    "database services publicly unless required."
                ),
                category="Exposure",
                risk_source="Database exposure"
            )

        # ------------------------------------------------------
        # UNKNOWN
        # ------------------------------------------------------

        elif service == "unknown" or not service:

            base_finding = create_finding(
                title="Unknown service detected",
                port=port["port"],
                service="unknown",
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Informational",
                risk_points=0,
                description=(
                    "Nmap detected an open port but could not "
                    "identify the associated service."
                ),
                recommendation=(
                    "Identify the service running on this port "
                    "and verify whether it is required."
                ),
                category="Discovery",
                risk_source="Service identification"
            )

        # ------------------------------------------------------
        # OTHER
        # ------------------------------------------------------

        else:

            product_information = ""

            if product:
                product_information = (
                    f" Product: {product}."
                )

            version_information = ""

            if version:
                version_information = (
                    f" Version: {version}."
                )

            extra_information = ""

            if extrainfo:
                extra_information = (
                    f" Additional information: {extrainfo}."
                )

            base_finding = create_finding(
                title="Network service exposed",
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity="Informational",
                risk_points=0,
                description=(
                    f"The service '{service}' is exposed "
                    f"on the target."
                    f"{product_information}"
                    f"{version_information}"
                    f"{extra_information}"
                ),
                recommendation=(
                    "Verify that this service is required "
                    "and restrict access where appropriate."
                ),
                category="Exposure",
                risk_source="Network service exposure"
            )

        # ======================================================
        # ADD BASE EXPOSURE RISK
        # ======================================================

        findings.append(base_finding)

        exposure_risk += base_risk

        # ======================================================
        # ADD CVE INFORMATION
        # ======================================================

        base_finding["security_intelligence"] = (
            security_intelligence
        )

        base_finding["cve_intelligence"] = (
            cve_intelligence
        )

        base_finding["cve_risk_points"] = (
            cve_risk_points
        )

        base_finding["highest_cvss"] = (
            cve_risk["highest_cvss"]
        )

        base_finding["highest_cve_severity"] = (
            cve_risk["highest_severity"]
        )

        base_finding["cve_count"] = (
            cve_risk["cve_count"]
        )

        # ------------------------------------------------------
        # CVE becomes a separate risk contribution.
        # ------------------------------------------------------

        if cve_risk_points > 0:

            cve_finding = create_finding(
                title=(
                    f"Known vulnerability exposure in "
                    f"{product or service}"
                ),
                port=port["port"],
                service=service,
                product=product,
                version=version,
                extrainfo=extrainfo,
                severity=cve_risk[
                    "highest_severity"
                ],
                risk_points=cve_risk_points,
                description=(
                    f"One or more applicable CVEs were "
                    f"identified for {product or service} "
                    f"{version}. The highest applicable "
                    f"CVSS score is "
                    f"{cve_risk['highest_cvss']}."
                ),
                recommendation=(
                    "Review the applicable CVEs and vendor "
                    "security advisories, then apply available "
                    "security updates or mitigations."
                ),
                category="Vulnerability",
                risk_source="CVE / CVSS"
            )

            cve_finding["security_intelligence"] = (
                security_intelligence
            )

            cve_finding["cve_intelligence"] = (
                cve_intelligence
            )

            cve_finding["cve_risk_points"] = (
                cve_risk_points
            )

            cve_finding["highest_cvss"] = (
                cve_risk["highest_cvss"]
            )

            cve_finding["highest_cve_severity"] = (
                cve_risk["highest_severity"]
            )

            cve_finding["cve_count"] = (
                cve_risk["cve_count"]
            )

            findings.append(cve_finding)

            cve_risk_total += cve_risk_points

    total_risk = (
        exposure_risk
        + cve_risk_total
        + configuration_risk
    )

    result = calculate_score(
        findings,
        total_risk
    )

    result["risk_breakdown"] = {
        "exposure_risk": exposure_risk,
        "configuration_risk": configuration_risk,
        "cve_risk": cve_risk_total,
        "tls_risk": 0,
        "total_risk": total_risk
    }

    return result


# ==========================================================
# WEB SECURITY RISK ANALYSIS
# ==========================================================

def analyze_web_risks(web_findings):

    findings = []

    total_risk = 0

    configuration_risk = 0

    header_rules = {

        "Content-Security-Policy": {
            "severity": "Medium",
            "risk_points": 5,
            "description": (
                "Content-Security-Policy (CSP) controls which "
                "scripts, styles, images and other resources "
                "a browser is allowed to load. A suitable CSP "
                "can reduce the impact of certain client-side "
                "injection attacks."
            ),
            "recommendation": (
                "Implement a Content-Security-Policy header "
                "with a policy appropriate for the application. "
                "Avoid unnecessarily broad source directives."
            )
        },

        "Strict-Transport-Security": {
            "severity": "Medium",
            "risk_points": 5,
            "description": (
                "Strict-Transport-Security (HSTS) instructs "
                "browsers to use HTTPS when connecting to the "
                "website. It helps reduce the risk of users "
                "being directed to an insecure HTTP connection."
            ),
            "recommendation": (
                "Enable HSTS with an appropriate max-age value "
                "after confirming the site is fully available "
                "over HTTPS."
            )
        },

        "X-Content-Type-Options": {
            "severity": "Low",
            "risk_points": 2,
            "description": (
                "X-Content-Type-Options helps prevent browsers "
                "from interpreting a response as a different "
                "MIME type than the one declared by the server."
            ),
            "recommendation": (
                "Set X-Content-Type-Options to 'nosniff' "
                "for applicable HTTP responses."
            )
        },

        "X-Frame-Options": {
            "severity": "Low",
            "risk_points": 2,
            "description": (
                "X-Frame-Options controls whether the website "
                "can be embedded inside frames by another "
                "website. Missing framing protection can "
                "increase exposure to clickjacking attacks."
            ),
            "recommendation": (
                "Set X-Frame-Options to an appropriate value "
                "or use a suitable frame-ancestors directive "
                "in Content-Security-Policy."
            )
        },

        "Referrer-Policy": {
            "severity": "Low",
            "risk_points": 1,
            "description": (
                "Referrer-Policy controls how much referrer "
                "information the browser sends when navigating "
                "from one resource to another."
            ),
            "recommendation": (
                "Configure an appropriate Referrer-Policy "
                "according to the application's requirements."
            )
        },

        "Permissions-Policy": {
            "severity": "Low",
            "risk_points": 1,
            "description": (
                "Permissions-Policy controls access to selected "
                "browser features and APIs."
            ),
            "recommendation": (
                "Configure Permissions-Policy to restrict "
                "browser features that the application does "
                "not require."
            )
        }
    }

    for finding in web_findings:

        finding_type = finding.get(
            "type"
        )

        # ======================================================
        # SECURITY HEADERS
        # ======================================================

        if finding_type == "security_header":

            if finding.get("status") != "Missing":
                continue

            header = finding.get(
                "header"
            )

            if header not in header_rules:
                continue

            rule = header_rules[header]

            risk_points = rule[
                "risk_points"
            ]

            findings.append(
                create_finding(
                    title=f"{header} header is missing",
                    severity=rule["severity"],
                    risk_points=risk_points,
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    category="Configuration",
                    risk_source="Security header"
                )
            )

            total_risk += risk_points

            configuration_risk += risk_points

        # ======================================================
        # SERVER INFORMATION
        # ======================================================

        elif finding_type == "server_information":

            if finding.get("status") != "Present":
                continue

            server_value = finding.get(
                "value",
                "Unknown"
            )

            risk_points = 1

            findings.append(
                create_finding(
                    title="Server information disclosed",
                    extrainfo=server_value,
                    severity="Low",
                    risk_points=risk_points,
                    description=(
                        "The HTTP response discloses "
                        f"server information: {server_value}."
                    ),
                    recommendation=(
                        "Consider minimizing server information "
                        "exposed through HTTP response headers."
                    ),
                    category="Configuration",
                    risk_source="Information disclosure"
                )
            )

            total_risk += risk_points

            configuration_risk += risk_points

        # ======================================================
        # X-POWERED-BY
        # ======================================================

        elif finding_type == "technology_disclosure":

            if finding.get("status") != "Present":
                continue

            value = finding.get(
                "value",
                "Unknown"
            )

            risk_points = 1

            findings.append(
                create_finding(
                    title="Technology information disclosed",
                    extrainfo=value,
                    severity="Low",
                    risk_points=risk_points,
                    description=(
                        "The HTTP response discloses "
                        "technology information through "
                        f"X-Powered-By: {value}."
                    ),
                    recommendation=(
                        "Remove or minimize unnecessary "
                        "technology information from HTTP "
                        "response headers."
                    ),
                    category="Configuration",
                    risk_source="Information disclosure"
                )
            )

            total_risk += risk_points

            configuration_risk += risk_points

        # ======================================================
        # HTTPS REDIRECT
        # ======================================================

        elif finding_type == "https_redirect":

            status = finding.get(
                "status"
            )

            # -----------------------------------------------
            # Confirmed missing redirect
            # -----------------------------------------------

            if status == "Not detected":

                risk_points = 8

                findings.append(
                    create_finding(
                        title="HTTPS redirect not detected",
                        severity="Medium",
                        risk_points=risk_points,
                        description=(
                            "The HTTP endpoint did not return "
                            "a redirect to HTTPS during the "
                            "authorized assessment."
                        ),
                        recommendation=(
                            "Configure the web server to redirect "
                            "HTTP requests to HTTPS where "
                            "appropriate."
                        ),
                        category="Configuration",
                        risk_source="HTTPS enforcement"
                    )
                )

                total_risk += risk_points

                configuration_risk += risk_points

            # -----------------------------------------------
            # Could not verify
            # -----------------------------------------------

            elif status == "Could not verify":

                findings.append(
                    create_finding(
                        title="HTTPS redirect could not be verified",
                        severity="Informational",
                        risk_points=0,
                        description=(
                            "The scanner could not reliably "
                            "verify HTTP-to-HTTPS redirect "
                            "behavior."
                        ),
                        recommendation=(
                            "Manually verify that HTTP requests "
                            "are redirected to HTTPS."
                        ),
                        category="Configuration",
                        risk_source="HTTPS enforcement"
                    )
                )

        # ======================================================
        # COOKIE SECURITY
        # ======================================================

        elif finding_type == "cookie_security":

            if finding.get("status") != "Present":
                continue

            cookie = finding.get(
                "cookie",
                {}
            )

            cookie_name = cookie.get(
                "name",
                "Unknown"
            )

            secure = cookie.get(
                "secure",
                False
            )

            httponly = cookie.get(
                "httponly",
                False
            )

            samesite = cookie.get(
                "samesite"
            )

            if not secure:

                risk_points = 5

                findings.append(
                    create_finding(
                        title=(
                            f"Cookie '{cookie_name}' "
                            "missing Secure flag"
                        ),
                        severity="Medium",
                        risk_points=risk_points,
                        description=(
                            f"The cookie '{cookie_name}' "
                            "does not have the Secure flag."
                        ),
                        recommendation=(
                            "Set the Secure flag on sensitive "
                            "cookies so they are transmitted "
                            "only over HTTPS."
                        ),
                        category="Configuration",
                        risk_source="Cookie security"
                    )
                )

                total_risk += risk_points

                configuration_risk += risk_points

            if not httponly:

                risk_points = 5

                findings.append(
                    create_finding(
                        title=(
                            f"Cookie '{cookie_name}' "
                            "missing HttpOnly flag"
                        ),
                        severity="Medium",
                        risk_points=risk_points,
                        description=(
                            f"The cookie '{cookie_name}' "
                            "does not have the HttpOnly flag."
                        ),
                        recommendation=(
                            "Set the HttpOnly flag on sensitive "
                            "cookies to reduce client-side "
                            "script access."
                        ),
                        category="Configuration",
                        risk_source="Cookie security"
                    )
                )

                total_risk += risk_points

                configuration_risk += risk_points

            if not samesite:

                risk_points = 3

                findings.append(
                    create_finding(
                        title=(
                            f"Cookie '{cookie_name}' "
                            "missing SameSite attribute"
                        ),
                        severity="Low",
                        risk_points=risk_points,
                        description=(
                            f"The cookie '{cookie_name}' "
                            "does not specify a SameSite "
                            "attribute."
                        ),
                        recommendation=(
                            "Configure an appropriate SameSite "
                            "attribute such as Lax or Strict "
                            "for applicable cookies."
                        ),
                        category="Configuration",
                        risk_source="Cookie security"
                    )
                )

                total_risk += risk_points

                configuration_risk += risk_points

        # ======================================================
        # CORS
        # ======================================================

        elif finding_type == "cors":

            if finding.get("status") != "Present":
                continue

            origin = finding.get(
                "value",
                ""
            )

            credentials = finding.get(
                "credentials"
            )

            if origin == "*":

                if str(
                    credentials
                ).lower() == "true":

                    risk_points = 10
                    severity = "Medium"

                    description = (
                        "The target allows cross-origin "
                        "requests from any origin while "
                        "also indicating credential support."
                    )

                else:

                    risk_points = 5
                    severity = "Low"

                    description = (
                        "The target allows cross-origin "
                        "requests from any origin using "
                        "Access-Control-Allow-Origin: *."
                    )

                findings.append(
                    create_finding(
                        title="Permissive CORS configuration",
                        extrainfo=(
                            f"Origin: {origin}"
                        ),
                        severity=severity,
                        risk_points=risk_points,
                        description=description,
                        recommendation=(
                            "Restrict CORS to trusted origins "
                            "when cross-origin access is required."
                        ),
                        category="Configuration",
                        risk_source="CORS configuration"
                    )
                )

                total_risk += risk_points

                configuration_risk += risk_points

        # ======================================================
        # HTTP METHODS
        # ======================================================

        elif finding_type == "http_methods":

            if finding.get("status") != "Present":
                continue

            methods = finding.get(
                "methods",
                []
            )

            dangerous_methods = []

            for method in methods:

                method_upper = method.upper()

                if method_upper in [
                    "TRACE",
                    "PUT",
                    "DELETE"
                ]:

                    dangerous_methods.append(
                        method_upper
                    )

            if dangerous_methods:

                method_string = ", ".join(
                    dangerous_methods
                )

                risk_points = 5

                findings.append(
                    create_finding(
                        title=(
                            "Potentially risky HTTP "
                            "methods exposed"
                        ),
                        extrainfo=method_string,
                        severity="Medium",
                        risk_points=risk_points,
                        description=(
                            "The web server advertises "
                            "potentially risky HTTP methods: "
                            f"{method_string}."
                        ),
                        recommendation=(
                            "Disable HTTP methods that are not "
                            "required by the application and "
                            "restrict access to administrative "
                            "or write operations."
                        ),
                        category="Configuration",
                        risk_source="HTTP method configuration"
                    )
                )

                total_risk += risk_points

                configuration_risk += risk_points

        # ======================================================
        # INFORMATIONAL WEB DATA
        # ======================================================

        elif finding_type in [
            "security_txt",
            "robots_txt",
            "response_information",
            "technology_detection"
        ]:

            # These are useful assessment information,
            # but are not automatically treated as vulnerabilities.
            continue

    return {
        "findings": findings,
        "total_risk": total_risk,
        "risk_breakdown": {
            "exposure_risk": 0,
            "configuration_risk": configuration_risk,
            "cve_risk": 0,
            "tls_risk": 0,
            "total_risk": total_risk
        }
    }


# ==========================================================
# TLS RISK ANALYSIS
# ==========================================================

def analyze_tls_risks(tls_result):

    findings = []

    total_risk = 0

    if not tls_result:

        return {
            "findings": [],
            "total_risk": 0,
            "risk_breakdown": {
                "exposure_risk": 0,
                "configuration_risk": 0,
                "cve_risk": 0,
                "tls_risk": 0,
                "total_risk": 0
            }
        }

    # ======================================================
    # HOSTNAME VALIDATION
    # ======================================================

    if not tls_result.get(
        "hostname_valid",
        True
    ):

        risk_points = 20

        findings.append(
            create_finding(
                title="TLS certificate hostname mismatch",
                port="443",
                service="HTTPS",
                version=tls_result.get(
                    "tls_version",
                    ""
                ),
                severity="High",
                risk_points=risk_points,
                description=(
                    "The TLS certificate does not match "
                    "the target hostname."
                ),
                recommendation=(
                    "Install a certificate whose hostname "
                    "matches the target domain."
                ),
                category="TLS",
                risk_source="Certificate validation"
            )
        )

        total_risk += risk_points

    # ======================================================
    # TLS SCAN FAILURE
    # ======================================================

    if not tls_result.get(
        "success",
        False
    ):

        return {
            "findings": findings,
            "total_risk": total_risk,
            "risk_breakdown": {
                "exposure_risk": 0,
                "configuration_risk": 0,
                "cve_risk": 0,
                "tls_risk": total_risk,
                "total_risk": total_risk
            }
        }

    # ======================================================
    # EXPIRED CERTIFICATE
    # ======================================================

    if tls_result.get(
        "certificate_status"
    ) == "Expired":

        risk_points = 20

        findings.append(
            create_finding(
                title="TLS certificate has expired",
                port="443",
                service="HTTPS",
                version=tls_result.get(
                    "tls_version",
                    ""
                ),
                severity="High",
                risk_points=risk_points,
                description=(
                    "The TLS certificate of the target "
                    "has expired."
                ),
                recommendation=(
                    "Renew and correctly install a valid "
                    "TLS certificate for the target."
                ),
                category="TLS",
                risk_source="Certificate validity"
            )
        )

        total_risk += risk_points

    # ======================================================
    # CERTIFICATE EXPIRING SOON
    # ======================================================

    elif tls_result.get(
        "days_remaining",
        999
    ) <= 30:

        risk_points = 10

        findings.append(
            create_finding(
                title="TLS certificate is expiring soon",
                port="443",
                service="HTTPS",
                version=tls_result.get(
                    "tls_version",
                    ""
                ),
                severity="Medium",
                risk_points=risk_points,
                description=(
                    "The TLS certificate will expire "
                    "within 30 days."
                ),
                recommendation=(
                    "Renew the TLS certificate before "
                    "its expiration date."
                ),
                category="TLS",
                risk_source="Certificate lifecycle"
            )
        )

        total_risk += risk_points

    # ======================================================
    # OLD TLS VERSION
    # ======================================================

    if tls_result.get(
        "tls_version"
    ) in [
        "TLSv1",
        "TLSv1.1"
    ]:

        risk_points = 20

        findings.append(
            create_finding(
                title="Old TLS version detected",
                port="443",
                service="HTTPS",
                version=tls_result[
                    "tls_version"
                ],
                severity="High",
                risk_points=risk_points,
                description=(
                    "The target is using an outdated "
                    "TLS version."
                ),
                recommendation=(
                    "Disable outdated TLS protocols and "
                    "use modern TLS versions such as "
                    "TLS 1.2 or TLS 1.3."
                ),
                category="TLS",
                risk_source="Protocol configuration"
            )
        )

        total_risk += risk_points

    return {
        "findings": findings,
        "total_risk": total_risk,
        "risk_breakdown": {
            "exposure_risk": 0,
            "configuration_risk": 0,
            "cve_risk": 0,
            "tls_risk": total_risk,
            "total_risk": total_risk
        }
    }


# ==========================================================
# SCORE CALCULATION
# ==========================================================

def calculate_score(
    findings,
    total_risk
):

    total_risk = max(
        0,
        int(total_risk)
    )

    score = max(
        0,
        100 - total_risk
    )

    if score >= 80:

        risk_level = "Low"

    elif score >= 60:

        risk_level = "Medium"

    else:

        risk_level = "High"

    return {
        "findings": findings,
        "total_risk": total_risk,
        "score": score,
        "risk_level": risk_level
    }


# ==========================================================
# COMBINE ALL RISKS
# ==========================================================

def combine_risks(
    nmap_result=None,
    web_result=None,
    tls_result=None
):

    all_findings = []

    nmap_risk = 0
    web_risk = 0
    tls_risk = 0

    exposure_risk = 0
    configuration_risk = 0
    cve_risk = 0

    # ======================================================
    # NMAP
    # ======================================================

    if nmap_result:

        all_findings.extend(
            nmap_result.get(
                "findings",
                []
            )
        )

        nmap_risk = nmap_result.get(
            "total_risk",
            0
        )

        nmap_breakdown = nmap_result.get(
            "risk_breakdown",
            {}
        )

        exposure_risk += nmap_breakdown.get(
            "exposure_risk",
            0
        )

        configuration_risk += (
            nmap_breakdown.get(
                "configuration_risk",
                0
            )
        )

        cve_risk += nmap_breakdown.get(
            "cve_risk",
            0
        )

    # ======================================================
    # WEB
    # ======================================================

    if web_result:

        all_findings.extend(
            web_result.get(
                "findings",
                []
            )
        )

        web_risk = web_result.get(
            "total_risk",
            0
        )

        web_breakdown = web_result.get(
            "risk_breakdown",
            {}
        )

        exposure_risk += web_breakdown.get(
            "exposure_risk",
            0
        )

        configuration_risk += (
            web_breakdown.get(
                "configuration_risk",
                0
            )
        )

        cve_risk += web_breakdown.get(
            "cve_risk",
            0
        )

    # ======================================================
    # TLS
    # ======================================================

    if tls_result:

        all_findings.extend(
            tls_result.get(
                "findings",
                []
            )
        )

        tls_risk = tls_result.get(
            "total_risk",
            0
        )

    # ======================================================
    # TOTAL
    # ======================================================

    total_risk = (
        nmap_risk
        + web_risk
        + tls_risk
    )

    result = calculate_score(
        all_findings,
        total_risk
    )

    result["risk_breakdown"] = {
        "exposure_risk": exposure_risk,
        "configuration_risk": configuration_risk,
        "cve_risk": cve_risk,
        "tls_risk": tls_risk,
        "total_risk": total_risk
    }

    return result