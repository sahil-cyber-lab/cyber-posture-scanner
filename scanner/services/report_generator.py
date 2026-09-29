from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from xml.sax.saxutils import escape


# ==============================================================
# HELPER FUNCTIONS
# ==============================================================

def safe_text(value, default="-"):
    """
    Convert values into safe text for ReportLab Paragraphs.

    This prevents characters such as &, < and > inside scanned
    values from being interpreted as ReportLab markup.
    """
    if value is None:
        value = default

    text = str(value)

    if not text:
        text = default

    return escape(text)


def paragraph(text, style):
    """
    Small helper for creating ReportLab paragraphs safely.
    """
    return Paragraph(
        safe_text(text),
        style
    )


def bold_label(text, style):
    """
    Create a bold label.
    """
    return Paragraph(
        f"<b>{safe_text(text)}</b>",
        style
    )


def get_risk_breakdown(
    scan,
    findings,
    web_scan=None,
    tls_scan=None
):
    """
    Retrieve Risk Breakdown information.

    The project may store the breakdown in different places
    depending on which version of the persistence layer created
    the scan.

    Priority:
        1. scan.risk_breakdown
        2. scan.risk_breakdown_data
        3. web_scan['risk_breakdown']
        4. tls_scan['risk_breakdown']
        5. calculated fallback

    Expected structure:

    {
        "exposure_risk": 0,
        "configuration_risk": 25,
        "cve_risk": 0,
        "tls_risk": 0,
        "total_risk": 25
    }
    """

    web_scan = web_scan or {}
    tls_scan = tls_scan or {}

    # ----------------------------------------------------------
    # 1. Dynamic/model attribute
    # ----------------------------------------------------------

    risk_breakdown = getattr(
        scan,
        "risk_breakdown",
        None
    )

    if isinstance(risk_breakdown, dict):
        return _normalize_risk_breakdown(
            risk_breakdown,
            scan
        )

    # ----------------------------------------------------------
    # 2. Alternative model attribute
    # ----------------------------------------------------------

    risk_breakdown = getattr(
        scan,
        "risk_breakdown_data",
        None
    )

    if isinstance(risk_breakdown, dict):
        return _normalize_risk_breakdown(
            risk_breakdown,
            scan
        )

    # ----------------------------------------------------------
    # 3. Web scan JSON
    # ----------------------------------------------------------

    risk_breakdown = web_scan.get(
        "risk_breakdown"
    )

    if isinstance(risk_breakdown, dict):
        return _normalize_risk_breakdown(
            risk_breakdown,
            scan
        )

    # ----------------------------------------------------------
    # 4. TLS JSON
    # ----------------------------------------------------------

    risk_breakdown = tls_scan.get(
        "risk_breakdown"
    )

    if isinstance(risk_breakdown, dict):
        return _normalize_risk_breakdown(
            risk_breakdown,
            scan
        )

    # ----------------------------------------------------------
    # 5. Fallback calculation
    # ----------------------------------------------------------

    return _calculate_fallback_risk_breakdown(
        scan,
        findings,
        web_scan,
        tls_scan
    )


def _normalize_risk_breakdown(data, scan):
    """
    Normalize different possible key names into one structure.
    """

    exposure = data.get(
        "exposure_risk",
        data.get("exposure", 0)
    )

    configuration = data.get(
        "configuration_risk",
        data.get("configuration", 0)
    )

    cve = data.get(
        "cve_risk",
        data.get("cve", 0)
    )

    tls = data.get(
        "tls_risk",
        data.get("tls", 0)
    )

    total = data.get(
        "total_risk",
        getattr(scan, "total_risk", 0)
    )

    try:
        exposure = int(exposure or 0)
    except (TypeError, ValueError):
        exposure = 0

    try:
        configuration = int(configuration or 0)
    except (TypeError, ValueError):
        configuration = 0

    try:
        cve = int(cve or 0)
    except (TypeError, ValueError):
        cve = 0

    try:
        tls = int(tls or 0)
    except (TypeError, ValueError):
        tls = 0

    try:
        total = int(total or 0)
    except (TypeError, ValueError):
        total = (
            exposure
            + configuration
            + cve
            + tls
        )

    return {
        "exposure_risk": exposure,
        "configuration_risk": configuration,
        "cve_risk": cve,
        "tls_risk": tls,
        "total_risk": total
    }


def _calculate_fallback_risk_breakdown(
    scan,
    findings,
    web_scan,
    tls_scan
):
    """
    Fallback risk breakdown for older Scan records.

    This is intentionally conservative.

    Web findings are treated as configuration risk.
    CVE contributions are separated from configuration risk.
    TLS findings are identified from TLS-related titles.

    Nmap service findings that do not contain explicit CVE
    contribution are treated as exposure risk.
    """

    exposure_risk = 0
    configuration_risk = 0
    cve_risk = 0
    tls_risk = 0

    tls_keywords = (
        "certificate",
        "tls",
        "ssl",
        "hostname",
        "expired",
        "cipher",
        "protocol"
    )

    web_keywords = (
        "header",
        "cors",
        "cookie",
        "https redirect",
        "server information",
        "technology",
        "security.txt",
        "robots.txt",
        "referrer",
        "permissions-policy",
        "content-type",
        "content security",
        "hsts",
        "frame-options"
    )

    for finding in findings:

        risk_points = getattr(
            finding,
            "risk_points",
            0
        ) or 0

        try:
            risk_points = int(risk_points)
        except (TypeError, ValueError):
            risk_points = 0

        title = (
            getattr(finding, "title", "")
            or ""
        ).lower()

        intelligence = getattr(
            finding,
            "cve_intelligence",
            None
        ) or {}

        # ------------------------------------------------------
        # CVE contribution
        # ------------------------------------------------------

        cve_points = getattr(
            finding,
            "cve_risk_points",
            None
        )

        if cve_points is None:
            cve_points = intelligence.get(
                "cve_risk_points",
                0
            )

        try:
            cve_points = int(cve_points or 0)
        except (TypeError, ValueError):
            cve_points = 0

        if cve_points:
            cve_risk += cve_points

        remaining_risk = max(
            0,
            risk_points - cve_points
        )

        # ------------------------------------------------------
        # TLS
        # ------------------------------------------------------

        if any(
            keyword in title
            for keyword in tls_keywords
        ):
            tls_risk += remaining_risk
            continue

        # ------------------------------------------------------
        # Web configuration
        # ------------------------------------------------------

        if any(
            keyword in title
            for keyword in web_keywords
        ):
            configuration_risk += remaining_risk
            continue

        # ------------------------------------------------------
        # Nmap/service exposure
        # ------------------------------------------------------

        if (
            getattr(finding, "port", "")
            or getattr(finding, "service", "")
        ):
            exposure_risk += remaining_risk
            continue

        configuration_risk += remaining_risk

    total_risk = getattr(
        scan,
        "total_risk",
        0
    ) or 0

    try:
        total_risk = int(total_risk)
    except (TypeError, ValueError):
        total_risk = (
            exposure_risk
            + configuration_risk
            + cve_risk
            + tls_risk
        )

    return {
        "exposure_risk": exposure_risk,
        "configuration_risk": configuration_risk,
        "cve_risk": cve_risk,
        "tls_risk": tls_risk,
        "total_risk": total_risk
    }


def get_cve_summary(finding):
    """
    Read CVE summary values from either model attributes
    or cve_intelligence JSON.

    Current Finding model stores CVE information inside
    cve_intelligence JSON, so JSON values are supported first-class.
    """

    cve_intelligence = getattr(
        finding,
        "cve_intelligence",
        None
    ) or {}

    vulnerabilities = cve_intelligence.get(
        "vulnerabilities",
        []
    )

    # ----------------------------------------------------------
    # CVE count
    # ----------------------------------------------------------

    cve_count = getattr(
        finding,
        "cve_count",
        None
    )

    if cve_count is None:
        cve_count = cve_intelligence.get(
            "cve_count",
            len(vulnerabilities)
        )

    # ----------------------------------------------------------
    # Highest CVSS
    # ----------------------------------------------------------

    highest_cvss = getattr(
        finding,
        "highest_cvss",
        None
    )

    if highest_cvss is None:
        highest_cvss = cve_intelligence.get(
            "highest_cvss",
            None
        )

    # ----------------------------------------------------------
    # Highest severity
    # ----------------------------------------------------------

    highest_severity = getattr(
        finding,
        "highest_cve_severity",
        None
    )

    if highest_severity is None:
        highest_severity = cve_intelligence.get(
            "highest_severity",
            cve_intelligence.get(
                "highest_cve_severity",
                "-"
            )
        )

    # ----------------------------------------------------------
    # CVE risk contribution
    # ----------------------------------------------------------

    cve_risk_points = getattr(
        finding,
        "cve_risk_points",
        None
    )

    if cve_risk_points is None:
        cve_risk_points = cve_intelligence.get(
            "cve_risk_points",
            0
        )

    return {
        "cve_count": cve_count,
        "highest_cvss": highest_cvss,
        "highest_severity": highest_severity,
        "cve_risk_points": cve_risk_points,
        "vulnerabilities": vulnerabilities
    }


def get_https_redirect_display(web_scan):
    """
    Produce a useful human-readable HTTPS redirect result.
    """

    redirect_data = web_scan.get(
        "http_redirect"
    )

    if isinstance(redirect_data, dict):

        status = redirect_data.get(
            "status"
        )

        if status:
            return status

        if redirect_data.get("location"):
            return (
                f"Redirect detected: "
                f"{redirect_data.get('location')}"
            )

        if redirect_data.get("checked"):
            return "No HTTP redirect detected"

    https_redirect = web_scan.get(
        "https_redirect"
    )

    if https_redirect is True:
        return "Enabled"

    if https_redirect is False:
        return "Not detected"

    return "Could not verify"


# ==============================================================
# MAIN REPORT GENERATOR
# ==============================================================

def generate_security_report(
    scan,
    findings,
    buffer,
    web_scan=None,
    tls_scan=None
):

    web_scan = web_scan or {}
    tls_scan = tls_scan or {}

    findings = list(findings)

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=15,
        spaceBefore=15,
        spaceAfter=10,
    )

    normal_style = ParagraphStyle(
        "NormalCustom",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
    )

    story = []

    # ==========================================================
    # TITLE
    # ==========================================================

    story.append(
        Paragraph(
            "Cybersecurity Posture Scanner",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 15))

    # ==========================================================
    # 1. SCAN INFORMATION
    # ==========================================================

    story.append(
        Paragraph(
            "1. Scan Information",
            heading_style
        )
    )

    scan_date = scan.created_at.strftime(
        "%d %B %Y, %I:%M %p"
    )

    scan_data = [
        [
            bold_label("Target", normal_style),
            paragraph(scan.target, normal_style)
        ],
        [
            bold_label("Target Type", normal_style),
            paragraph(scan.target_type, normal_style)
        ],
        [
            bold_label("Scan Status", normal_style),
            paragraph(scan.status, normal_style)
        ],
        [
            bold_label("Scan Date", normal_style),
            paragraph(scan_date, normal_style)
        ],
    ]

    scan_table = Table(
        scan_data,
        colWidths=[1.5 * inch, 4.8 * inch]
    )

    scan_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            ),
        ])
    )

    story.append(scan_table)
    story.append(Spacer(1, 20))

    # ==========================================================
    # 2. SECURITY ASSESSMENT
    # ==========================================================

    story.append(
        Paragraph(
            "2. Security Assessment",
            heading_style
        )
    )

    score = scan.score
    risk_level = scan.risk_level
    total_risk = scan.total_risk

    summary_data = [
        [
            bold_label(
                "Security Score",
                normal_style
            ),
            Paragraph(
                f"<b>{safe_text(score)}/100</b>",
                normal_style
            )
        ],
        [
            bold_label(
                "Risk Level",
                normal_style
            ),
            paragraph(
                risk_level,
                normal_style
            )
        ],
        [
            bold_label(
                "Total Risk Points",
                normal_style
            ),
            paragraph(
                total_risk,
                normal_style
            )
        ],
        [
            bold_label(
                "Total Findings",
                normal_style
            ),
            paragraph(
                len(findings),
                normal_style
            )
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[2.5 * inch, 3.8 * inch]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            ),
        ])
    )

    story.append(summary_table)
    story.append(Spacer(1, 15))

    # ==========================================================
    # RISK BREAKDOWN
    # ==========================================================

    risk_breakdown = get_risk_breakdown(
        scan,
        findings,
        web_scan,
        tls_scan
    )

    story.append(
        Paragraph(
            "Risk Breakdown",
            heading_style
        )
    )

    risk_data = [
        [
            bold_label(
                "Risk Category",
                small_style
            ),
            bold_label(
                "Risk Points",
                small_style
            )
        ],
        [
            paragraph(
                "Exposure Risk",
                small_style
            ),
            paragraph(
                risk_breakdown["exposure_risk"],
                small_style
            )
        ],
        [
            paragraph(
                "Configuration Risk",
                small_style
            ),
            paragraph(
                risk_breakdown["configuration_risk"],
                small_style
            )
        ],
        [
            paragraph(
                "CVE Risk",
                small_style
            ),
            paragraph(
                risk_breakdown["cve_risk"],
                small_style
            )
        ],
        [
            paragraph(
                "TLS Risk",
                small_style
            ),
            paragraph(
                risk_breakdown["tls_risk"],
                small_style
            )
        ],
        [
            bold_label(
                "Total Risk",
                small_style
            ),
            Paragraph(
                (
                    f"<b>"
                    f"{safe_text(risk_breakdown['total_risk'])}"
                    f"</b>"
                ),
                small_style
            )
        ],
    ]

    risk_table = Table(
        risk_data,
        colWidths=[4.5 * inch, 1.8 * inch]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "BACKGROUND",
                (0, -1),
                (-1, -1),
                colors.whitesmoke
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            ),
        ])
    )

    story.append(risk_table)
    story.append(Spacer(1, 20))

    # ==========================================================
    # 3. WEB SCAN DETAILS
    # ==========================================================

    if web_scan:

        story.append(
            Paragraph(
                "3. Web Scan Details",
                heading_style
            )
        )

        https_redirect_display = (
            get_https_redirect_display(web_scan)
        )

        web_data = [
            [
                bold_label(
                    "HTTP Status",
                    normal_style
                ),
                paragraph(
                    web_scan.get(
                        "status_code",
                        "-"
                    ),
                    normal_style
                )
            ],
            [
                bold_label(
                    "Final URL",
                    normal_style
                ),
                paragraph(
                    web_scan.get(
                        "final_url",
                        "-"
                    ),
                    normal_style
                )
            ],
            [
                bold_label(
                    "Redirected",
                    normal_style
                ),
                paragraph(
                    "Yes"
                    if web_scan.get("redirected")
                    else "No",
                    normal_style
                )
            ],
            [
                bold_label(
                    "Server",
                    normal_style
                ),
                paragraph(
                    web_scan.get("server")
                    or "Not disclosed",
                    normal_style
                )
            ],
            [
                bold_label(
                    "X-Powered-By",
                    normal_style
                ),
                paragraph(
                    web_scan.get("powered_by")
                    or "Not disclosed",
                    normal_style
                )
            ],
            [
                bold_label(
                    "HTTPS Redirect",
                    normal_style
                ),
                paragraph(
                    https_redirect_display,
                    normal_style
                )
            ],
        ]

        web_table = Table(
            web_data,
            colWidths=[2.0 * inch, 4.3 * inch]
        )

        web_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.whitesmoke
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),
            ])
        )

        story.append(web_table)
        story.append(Spacer(1, 15))

        # ------------------------------------------------------
        # HTTP Redirect Details
        # ------------------------------------------------------

        http_redirect = web_scan.get(
            "http_redirect"
        )

        if isinstance(http_redirect, dict):

            story.append(
                Paragraph(
                    "<b>HTTP → HTTPS Redirect Details</b>",
                    normal_style
                )
            )

            redirect_data = [
                [
                    bold_label(
                        "Source URL",
                        small_style
                    ),
                    paragraph(
                        http_redirect.get(
                            "source_url",
                            "-"
                        ),
                        small_style
                    )
                ],
                [
                    bold_label(
                        "HTTP Status Code",
                        small_style
                    ),
                    paragraph(
                        http_redirect.get(
                            "status_code",
                            "-"
                        ),
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Location",
                        small_style
                    ),
                    paragraph(
                        http_redirect.get(
                            "location"
                        )
                        or "-",
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Final URL",
                        small_style
                    ),
                    paragraph(
                        http_redirect.get(
                            "final_url",
                            "-"
                        ),
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Status",
                        small_style
                    ),
                    paragraph(
                        http_redirect.get(
                            "status",
                            "-"
                        ),
                        small_style
                    )
                ],
            ]

            redirect_table = Table(
                redirect_data,
                colWidths=[
                    2.0 * inch,
                    4.3 * inch
                ]
            )

            redirect_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.whitesmoke
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),
                ])
            )

            story.append(redirect_table)
            story.append(Spacer(1, 15))

        # ------------------------------------------------------
        # Security Headers
        # ------------------------------------------------------

        story.append(
            Paragraph(
                "<b>Security Headers</b>",
                normal_style
            )
        )

        headers = web_scan.get(
            "headers",
            {}
        )

        if headers:

            header_data = [
                [
                    bold_label(
                        "Header",
                        small_style
                    ),
                    bold_label(
                        "Status",
                        small_style
                    )
                ]
            ]

            for header_name, header_value in headers.items():

                status = (
                    str(header_value)
                    if header_value
                    else "Missing"
                )

                header_data.append([
                    paragraph(
                        header_name,
                        small_style
                    ),
                    paragraph(
                        status,
                        small_style
                    )
                ])

            header_table = Table(
                header_data,
                colWidths=[
                    3.5 * inch,
                    2.8 * inch
                ]
            )

            header_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),
                ])
            )

            story.append(header_table)

        else:

            story.append(
                Paragraph(
                    "No security header information was detected.",
                    small_style
                )
            )

        story.append(Spacer(1, 15))

        # ------------------------------------------------------
        # CORS
        # ------------------------------------------------------

        cors = web_scan.get(
            "cors",
            {}
        )

        story.append(
            Paragraph(
                "<b>CORS Configuration</b>",
                normal_style
            )
        )

        cors_data = [
            [
                bold_label(
                    "Allow Origin",
                    small_style
                ),
                paragraph(
                    cors.get(
                        "allow_origin",
                        "Not configured"
                    ),
                    small_style
                )
            ],
            [
                bold_label(
                    "Allow Credentials",
                    small_style
                ),
                paragraph(
                    cors.get(
                        "allow_credentials",
                        "Not configured"
                    ),
                    small_style
                )
            ],
            [
                bold_label(
                    "Allow Methods",
                    small_style
                ),
                paragraph(
                    cors.get(
                        "allow_methods",
                        "Not configured"
                    ),
                    small_style
                )
            ],
        ]

        cors_table = Table(
            cors_data,
            colWidths=[
                2.5 * inch,
                3.8 * inch
            ]
        )

        cors_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.whitesmoke
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),
            ])
        )

        story.append(cors_table)
        story.append(Spacer(1, 15))

        # ------------------------------------------------------
        # Cookies
        # ------------------------------------------------------

        cookies = web_scan.get(
            "cookies",
            []
        )

        story.append(
            Paragraph(
                "<b>Cookie Security</b>",
                normal_style
            )
        )

        if cookies:

            cookie_data = [
                [
                    bold_label(
                        "Name",
                        small_style
                    ),
                    bold_label(
                        "Secure",
                        small_style
                    ),
                    bold_label(
                        "HttpOnly",
                        small_style
                    ),
                    bold_label(
                        "SameSite",
                        small_style
                    ),
                ]
            ]

            for cookie in cookies:

                cookie_data.append([
                    paragraph(
                        cookie.get(
                            "name",
                            "-"
                        ),
                        small_style
                    ),
                    paragraph(
                        cookie.get(
                            "secure",
                            "-"
                        ),
                        small_style
                    ),
                    paragraph(
                        cookie.get(
                            "httponly",
                            "-"
                        ),
                        small_style
                    ),
                    paragraph(
                        cookie.get(
                            "samesite",
                            "-"
                        ),
                        small_style
                    ),
                ])

            cookie_table = Table(
                cookie_data,
                colWidths=[
                    2.2 * inch,
                    1.3 * inch,
                    1.3 * inch,
                    1.5 * inch
                ]
            )

            cookie_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    ),
                ])
            )

            story.append(cookie_table)

        else:

            story.append(
                Paragraph(
                    "No cookies detected.",
                    small_style
                )
            )

        story.append(Spacer(1, 15))

        # ------------------------------------------------------
        # HTTP Methods
        # ------------------------------------------------------

        story.append(
            Paragraph(
                "<b>HTTP Methods</b>",
                normal_style
            )
        )

        methods = web_scan.get(
            "http_methods",
            []
        )

        story.append(
            Paragraph(
                safe_text(
                    ", ".join(map(str, methods))
                    if methods
                    else "No methods detected."
                ),
                small_style
            )
        )

        story.append(Spacer(1, 10))

        # ------------------------------------------------------
        # OPTIONS Methods
        # ------------------------------------------------------

        story.append(
            Paragraph(
                "<b>OPTIONS Methods</b>",
                normal_style
            )
        )

        options_methods = web_scan.get(
            "options_methods",
            []
        )

        story.append(
            Paragraph(
                safe_text(
                    ", ".join(
                        map(
                            str,
                            options_methods
                        )
                    )
                    if options_methods
                    else (
                        "No methods disclosed "
                        "through OPTIONS."
                    )
                ),
                small_style
            )
        )

        story.append(Spacer(1, 10))

        # ------------------------------------------------------
        # Security.txt
        # ------------------------------------------------------

        story.append(
            Paragraph(
                "<b>security.txt</b>",
                normal_style
            )
        )

        story.append(
            Paragraph(
                "Detected"
                if web_scan.get("security_txt")
                else "Not detected.",
                small_style
            )
        )

        story.append(Spacer(1, 8))

        # ------------------------------------------------------
        # robots.txt
        # ------------------------------------------------------

        story.append(
            Paragraph(
                "<b>robots.txt</b>",
                normal_style
            )
        )

        story.append(
            Paragraph(
                "Detected"
                if web_scan.get("robots_txt")
                else "Not detected.",
                small_style
            )
        )

        story.append(Spacer(1, 10))

        # ------------------------------------------------------
        # Technology Detection
        # ------------------------------------------------------

        technology = web_scan.get(
            "technology",
            []
        )

        story.append(
            Paragraph(
                "<b>Technology Detection</b>",
                normal_style
            )
        )

        if isinstance(
            technology,
            list
        ):

            technology_text = ", ".join(
                map(
                    str,
                    technology
                )
            )

        else:

            technology_text = str(
                technology
                or "No technology detected."
            )

        story.append(
            Paragraph(
                safe_text(technology_text),
                small_style
            )
        )

    # ==========================================================
    # 4. TLS / SSL DETAILS
    # ==========================================================

    if tls_scan:

        story.append(
            Paragraph(
                "4. TLS / SSL Certificate Details",
                heading_style
            )
        )

        if tls_scan.get("success"):

            days_remaining = tls_scan.get(
                "days_remaining"
            )

            if days_remaining is None:
                days_remaining_display = "-"
            else:
                days_remaining_display = (
                    str(days_remaining)
                )

            tls_data = [
                [
                    bold_label(
                        "Hostname",
                        normal_style
                    ),
                    paragraph(
                        tls_scan.get(
                            "hostname",
                            "-"
                        ),
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "Hostname Validation",
                        normal_style
                    ),
                    paragraph(
                        "Valid"
                        if tls_scan.get(
                            "hostname_valid"
                        )
                        else "Invalid",
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "TLS Version",
                        normal_style
                    ),
                    paragraph(
                        tls_scan.get(
                            "tls_version",
                            "-"
                        ),
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "Cipher",
                        normal_style
                    ),
                    paragraph(
                        tls_scan.get(
                            "cipher",
                            "-"
                        ),
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "Certificate Status",
                        normal_style
                    ),
                    paragraph(
                        tls_scan.get(
                            "certificate_status",
                            "-"
                        ),
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "Certificate Issuer",
                        normal_style
                    ),
                    paragraph(
                        tls_scan.get(
                            "issuer",
                            "-"
                        ),
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "Expiry Date",
                        normal_style
                    ),
                    paragraph(
                        tls_scan.get(
                            "expiry_date",
                            "-"
                        ),
                        normal_style
                    )
                ],
                [
                    bold_label(
                        "Days Remaining",
                        normal_style
                    ),
                    paragraph(
                        days_remaining_display,
                        normal_style
                    )
                ],
            ]

            tls_table = Table(
                tls_data,
                colWidths=[
                    2.2 * inch,
                    4.1 * inch
                ]
            )

            tls_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.whitesmoke
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        7
                    ),
                ])
            )

            story.append(tls_table)

        else:

            story.append(
                Paragraph(
                    (
                        "TLS scan failed: "
                        f"{safe_text(tls_scan.get('error', 'Unknown error'))}"
                    ),
                    normal_style
                )
            )

    # ==========================================================
    # 5. SECURITY FINDINGS
    # ==========================================================

    story.append(
        Paragraph(
            "5. Security Findings",
            heading_style
        )
    )

    if findings:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            story.append(
                Paragraph(
                    (
                        f"{index}. "
                        f"{safe_text(finding.title)}"
                    ),
                    styles["Heading3"]
                )
            )

            finding_data = [
                [
                    bold_label(
                        "Port",
                        small_style
                    ),
                    paragraph(
                        finding.port,
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Service",
                        small_style
                    ),
                    paragraph(
                        finding.service,
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Product",
                        small_style
                    ),
                    paragraph(
                        finding.product or "-",
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Version",
                        small_style
                    ),
                    paragraph(
                        finding.version or "-",
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Extra Information",
                        small_style
                    ),
                    paragraph(
                        finding.extra_info or "-",
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Severity",
                        small_style
                    ),
                    paragraph(
                        finding.severity,
                        small_style
                    )
                ],
                [
                    bold_label(
                        "Risk Points",
                        small_style
                    ),
                    paragraph(
                        finding.risk_points,
                        small_style
                    ),
                ],
            ]

            finding_table = Table(
                finding_data,
                colWidths=[
                    1.7 * inch,
                    4.6 * inch
                ]
            )

            finding_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        colors.whitesmoke
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.grey
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),
                ])
            )

            story.append(finding_table)
            story.append(Spacer(1, 8))

            # --------------------------------------------------
            # Description
            # --------------------------------------------------

            story.append(
                Paragraph(
                    "<b>Description</b>",
                    small_style
                )
            )

            story.append(
                Paragraph(
                    safe_text(
                        finding.description
                    ),
                    small_style
                )
            )

            story.append(Spacer(1, 8))

            # --------------------------------------------------
            # Recommendation
            # --------------------------------------------------

            if finding.recommendation:

                story.append(
                    Paragraph(
                        "<b>Recommendation</b>",
                        small_style
                    )
                )

                story.append(
                    Paragraph(
                        safe_text(
                            finding.recommendation
                        ),
                        small_style
                    )
                )

                story.append(
                    Spacer(1, 8)
                )

            # ==================================================
            # SECURITY INTELLIGENCE
            # ==================================================

            intelligence = getattr(
                finding,
                "security_intelligence",
                None
            ) or {}

            if intelligence:

                # Only show meaningful intelligence.
                detected = intelligence.get(
                    "detected"
                )

                if (
                    detected
                    or intelligence.get("product")
                    or intelligence.get("version")
                    or intelligence.get("status")
                ):

                    story.append(
                        Paragraph(
                            "<b>Security Intelligence</b>",
                            small_style
                        )
                    )

                    intelligence_data = [
                        [
                            bold_label(
                                "Detection Status",
                                small_style
                            ),
                            paragraph(
                                (
                                    "Detected"
                                    if intelligence.get(
                                        "detected"
                                    )
                                    else "Not Detected"
                                ),
                                small_style
                            )
                        ],
                        [
                            bold_label(
                                "Product",
                                small_style
                            ),
                            paragraph(
                                intelligence.get(
                                    "product"
                                ) or "-",
                                small_style
                            )
                        ],
                        [
                            bold_label(
                                "Version",
                                small_style
                            ),
                            paragraph(
                                intelligence.get(
                                    "version"
                                ) or "-",
                                small_style
                            )
                        ],
                        [
                            bold_label(
                                "Severity",
                                small_style
                            ),
                            paragraph(
                                intelligence.get(
                                    "severity",
                                    "Informational"
                                ),
                                small_style
                            )
                        ],
                        [
                            bold_label(
                                "Status",
                                small_style
                            ),
                            paragraph(
                                intelligence.get(
                                    "status",
                                    "-"
                                ),
                                small_style
                            )
                        ],
                    ]

                    intelligence_table = Table(
                        intelligence_data,
                        colWidths=[
                            1.7 * inch,
                            4.6 * inch
                        ]
                    )

                    intelligence_table.setStyle(
                        TableStyle([
                            (
                                "BACKGROUND",
                                (0, 0),
                                (0, -1),
                                colors.lightblue
                            ),
                            (
                                "GRID",
                                (0, 0),
                                (-1, -1),
                                0.4,
                                colors.grey
                            ),
                            (
                                "VALIGN",
                                (0, 0),
                                (-1, -1),
                                "TOP"
                            ),
                            (
                                "PADDING",
                                (0, 0),
                                (-1, -1),
                                6
                            ),
                        ])
                    )

                    story.append(
                        intelligence_table
                    )

                    story.append(
                        Spacer(1, 6)
                    )

                    if intelligence.get(
                        "description"
                    ):

                        story.append(
                            Paragraph(
                                "<b>Intelligence Analysis</b>",
                                small_style
                            )
                        )

                        story.append(
                            Paragraph(
                                safe_text(
                                    intelligence.get(
                                        "description"
                                    )
                                ),
                                small_style
                            )
                        )

                        story.append(
                            Spacer(1, 6)
                        )

                    if intelligence.get(
                        "recommendation"
                    ):

                        story.append(
                            Paragraph(
                                "<b>Intelligence Recommendation</b>",
                                small_style
                            )
                        )

                        story.append(
                            Paragraph(
                                safe_text(
                                    intelligence.get(
                                        "recommendation"
                                    )
                                ),
                                small_style
                            )
                        )

                        story.append(
                            Spacer(1, 8)
                        )

            # ==================================================
            # CVE INTELLIGENCE
            # ==================================================

            cve_intelligence = getattr(
                finding,
                "cve_intelligence",
                None
            ) or {}

            # --------------------------------------------------
            # Only display CVE section when:
            # product + version + CVE data exist.
            # --------------------------------------------------

            product = (
                getattr(
                    finding,
                    "product",
                    ""
                )
                or ""
            ).strip()

            version = (
                getattr(
                    finding,
                    "version",
                    ""
                )
                or ""
            ).strip()

            if (
                product
                and version
                and cve_intelligence
            ):

                story.append(
                    Paragraph(
                        "<b>CVE Intelligence</b>",
                        small_style
                    )
                )

                cve_summary = get_cve_summary(
                    finding
                )

                vulnerabilities = cve_summary[
                    "vulnerabilities"
                ]

                # ------------------------------------------------
                # CVE Summary
                # ------------------------------------------------

                cve_summary_data = [
                    [
                        bold_label(
                            "Applicable CVEs",
                            small_style
                        ),
                        paragraph(
                            cve_summary[
                                "cve_count"
                            ],
                            small_style
                        )
                    ],
                    [
                        bold_label(
                            "Highest CVSS",
                            small_style
                        ),
                        paragraph(
                            (
                                cve_summary[
                                    "highest_cvss"
                                ]
                                if cve_summary[
                                    "highest_cvss"
                                ] is not None
                                else "-"
                            ),
                            small_style
                        )
                    ],
                    [
                        bold_label(
                            "Highest Severity",
                            small_style
                        ),
                        paragraph(
                            cve_summary[
                                "highest_severity"
                            ]
                            or "-",
                            small_style
                        )
                    ],
                    [
                        bold_label(
                            "CVE Risk Contribution",
                            small_style
                        ),
                        paragraph(
                            cve_summary[
                                "cve_risk_points"
                            ],
                            small_style
                        )
                    ],
                ]

                cve_summary_table = Table(
                    cve_summary_data,
                    colWidths=[
                        2.2 * inch,
                        4.1 * inch
                    ]
                )

                cve_summary_table.setStyle(
                    TableStyle([
                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, -1),
                            colors.whitesmoke
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            colors.grey
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP"
                        ),
                        (
                            "PADDING",
                            (0, 0),
                            (-1, -1),
                            6
                        ),
                    ])
                )

                story.append(
                    cve_summary_table
                )

                story.append(
                    Spacer(1, 8)
                )

                # ------------------------------------------------
                # Individual CVEs
                # ------------------------------------------------

                if vulnerabilities:

                    story.append(
                        Paragraph(
                            "<b>Applicable Vulnerabilities</b>",
                            small_style
                        )
                    )

                    for cve in vulnerabilities:

                        cve_id = cve.get(
                            "cve_id",
                            cve.get(
                                "id",
                                "-"
                            )
                        )

                        severity = cve.get(
                            "severity",
                            "Unknown"
                        )

                        cvss_score = cve.get(
                            "cvss_score",
                            cve.get(
                                "score",
                                None
                            )
                        )

                        cvss_version = cve.get(
                            "cvss_version",
                            "-"
                        )

                        description = cve.get(
                            "description",
                            "No CVE description available."
                        )

                        matched_cpes = cve.get(
                            "matched_cpes",
                            []
                        )

                        cve_data = [
                            [
                                bold_label(
                                    "CVE ID",
                                    small_style
                                ),
                                paragraph(
                                    cve_id,
                                    small_style
                                )
                            ],
                            [
                                bold_label(
                                    "Severity",
                                    small_style
                                ),
                                paragraph(
                                    severity,
                                    small_style
                                )
                            ],
                            [
                                bold_label(
                                    "CVSS Score",
                                    small_style
                                ),
                                paragraph(
                                    (
                                        cvss_score
                                        if cvss_score is not None
                                        else "-"
                                    ),
                                    small_style
                                )
                            ],
                            [
                                bold_label(
                                    "CVSS Version",
                                    small_style
                                ),
                                paragraph(
                                    cvss_version,
                                    small_style
                                )
                            ],
                        ]

                        cve_table = Table(
                            cve_data,
                            colWidths=[
                                1.7 * inch,
                                4.6 * inch
                            ]
                        )

                        cve_table.setStyle(
                            TableStyle([
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (0, -1),
                                    colors.whitesmoke
                                ),
                                (
                                    "GRID",
                                    (0, 0),
                                    (-1, -1),
                                    0.4,
                                    colors.grey
                                ),
                                (
                                    "VALIGN",
                                    (0, 0),
                                    (-1, -1),
                                    "TOP"
                                ),
                                (
                                    "PADDING",
                                    (0, 0),
                                    (-1, -1),
                                    6
                                ),
                            ])
                        )

                        story.append(
                            cve_table
                        )

                        story.append(
                            Spacer(1, 5)
                        )

                        story.append(
                            Paragraph(
                                "<b>CVE Description</b>",
                                small_style
                            )
                        )

                        story.append(
                            Paragraph(
                                safe_text(
                                    description
                                ),
                                small_style
                            )
                        )

                        story.append(
                            Spacer(1, 5)
                        )

                        # ----------------------------------------
                        # Matched CPEs
                        # ----------------------------------------

                        if matched_cpes:

                            story.append(
                                Paragraph(
                                    "<b>Matched CPE</b>",
                                    small_style
                                )
                            )

                            for matched_cpe in matched_cpes:

                                if isinstance(
                                    matched_cpe,
                                    dict
                                ):

                                    criteria = (
                                        matched_cpe.get(
                                            "criteria",
                                            "-"
                                        )
                                    )

                                    start_including = (
                                        matched_cpe.get(
                                            "versionStartIncluding"
                                        )
                                    )

                                    start_excluding = (
                                        matched_cpe.get(
                                            "versionStartExcluding"
                                        )
                                    )

                                    end_including = (
                                        matched_cpe.get(
                                            "versionEndIncluding"
                                        )
                                    )

                                    end_excluding = (
                                        matched_cpe.get(
                                            "versionEndExcluding"
                                        )
                                    )

                                    cpe_text = str(
                                        criteria
                                    )

                                    version_range = []

                                    if start_including:
                                        version_range.append(
                                            f">= {start_including}"
                                        )

                                    if start_excluding:
                                        version_range.append(
                                            f"> {start_excluding}"
                                        )

                                    if end_including:
                                        version_range.append(
                                            f"<= {end_including}"
                                        )

                                    if end_excluding:
                                        version_range.append(
                                            f"< {end_excluding}"
                                        )

                                    if version_range:

                                        cpe_text += (
                                            " | Version range: "
                                            + ", ".join(
                                                version_range
                                            )
                                        )

                                else:

                                    cpe_text = str(
                                        matched_cpe
                                    )

                                story.append(
                                    Paragraph(
                                        safe_text(
                                            cpe_text
                                        ),
                                        small_style
                                    )
                                )

                        story.append(
                            Spacer(1, 8)
                        )

                else:

                    story.append(
                        Paragraph(
                            (
                                "No applicable CVEs were "
                                "identified for the detected "
                                "product/version."
                            ),
                            small_style
                        )
                    )

                # ------------------------------------------------
                # CVE Disclaimer
                # ------------------------------------------------

                story.append(
                    Paragraph(
                        (
                            "<b>CVE Assessment Note:</b> "
                            "CVE results are based on available "
                            "vulnerability intelligence and "
                            "product/version applicability data. "
                            "A CVE match does not by itself "
                            "confirm exploitation or active "
                            "compromise."
                        ),
                        small_style
                    )
                )

            story.append(
                Spacer(1, 15)
            )

    else:

        story.append(
            Paragraph(
                "No security findings were detected.",
                normal_style
            )
        )

    # ==========================================================
    # 6. REPORT SUMMARY
    # ==========================================================

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "6. Report Summary",
            heading_style
        )
    )

    story.append(
        Paragraph(
            (
                "This report was generated by the "
                "Cybersecurity Posture Scanner. "
                "The assessment combines network/service "
                "enumeration, web security checks, TLS "
                "certificate analysis, security intelligence "
                "and applicable vulnerability intelligence."
            ),
            normal_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ----------------------------------------------------------
    # Final assessment summary
    # ----------------------------------------------------------

    final_summary_data = [
        [
            bold_label(
                "Security Score",
                small_style
            ),
            paragraph(
                f"{score}/100",
                small_style
            )
        ],
        [
            bold_label(
                "Risk Level",
                small_style
            ),
            paragraph(
                risk_level,
                small_style
            )
        ],
        [
            bold_label(
                "Total Risk Points",
                small_style
            ),
            paragraph(
                total_risk,
                small_style
            )
        ],
        [
            bold_label(
                "Total Findings",
                small_style
            ),
            paragraph(
                len(findings),
                small_style
            )
        ],
    ]

    final_summary_table = Table(
        final_summary_data,
        colWidths=[
            2.5 * inch,
            3.8 * inch
        ]
    )

    final_summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.whitesmoke
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            ),
        ])
    )

    story.append(
        final_summary_table
    )

    story.append(
        Spacer(1, 20)
    )

    # ----------------------------------------------------------
    # Risk methodology
    # ----------------------------------------------------------

    story.append(
        Paragraph(
            "<b>Risk Methodology</b>",
            normal_style
        )
    )

    story.append(
        Paragraph(
            (
                "Risk points are derived from the scanner's "
                "risk engine. The assessment separates "
                "service/exposure risk, configuration-related "
                "risk, applicable CVE risk and TLS/certificate "
                "risk where the available scan data supports "
                "that classification."
            ),
            small_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    # ----------------------------------------------------------
    # CVE methodology
    # ----------------------------------------------------------

    story.append(
        Paragraph(
            "<b>Vulnerability Intelligence</b>",
            normal_style
        )
    )

    story.append(
        Paragraph(
            (
                "CVE results are informational vulnerability "
                "intelligence derived from detected product and "
                "version information. Applicability is evaluated "
                "using available product/version and CPE "
                "information. A reported CVE should be validated "
                "against the vendor's advisory, patch level and "
                "deployment context before remediation decisions "
                "are made."
            ),
            small_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    # ----------------------------------------------------------
    # Authorization notice
    # ----------------------------------------------------------

    story.append(
        Paragraph(
            (
                "<b>Important:</b> Only scan systems and "
                "websites that you own or have explicit "
                "authorization to assess."
            ),
            normal_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    story.append(
        Paragraph(
            (
                "This automated assessment does not guarantee "
                "that all vulnerabilities or security weaknesses "
                "have been identified."
            ),
            small_style
        )
    )

    # ==========================================================
    # BUILD PDF
    # ==========================================================

    document.build(
        story
    )