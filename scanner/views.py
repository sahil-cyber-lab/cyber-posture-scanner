from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Avg
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from io import BytesIO

from .models import Scan, Finding
from .validators import detect_target_type

from .services.nmap_scanner import run_nmap_scan
from .services.web_scanner import check_security_headers
from .services.tls_scanner import check_tls_certificate
from .services.report_generator import generate_security_report

from .services.posture_manager import (
    compare_scans,
    get_posture_trends,
    get_posture_summary
)

from .services.risk_engine import (
    analyze_risks,
    analyze_web_risks,
    analyze_tls_risks,
    combine_risks
)


# ==========================================================
# HOME
# ==========================================================

def home(request):
    return render(
        request,
        "scanner/home.html"
    )


# ==========================================================
# SCAN
# ==========================================================

@login_required
def scan(request):

    target = None
    target_type = None

    scan_result = None
    web_result = None
    tls_result = None
    risk_result = None

    if request.method == "POST":

        target = request.POST.get(
            "target",
            ""
        ).strip()

        authorized = request.POST.get(
            "authorized"
        )

        # --------------------------------------------------
        # AUTHORIZATION CHECK
        # --------------------------------------------------

        if not authorized:

            return render(
                request,
                "scanner/scan.html",
                {
                    "target": target,
                    "error": (
                        "Authorization confirmation "
                        "is required before scanning."
                    )
                }
            )

        # --------------------------------------------------
        # TARGET TYPE DETECTION
        # --------------------------------------------------

        target_type = detect_target_type(
            target
        )

        print(
            "Target:",
            target
        )

        print(
            "Target type:",
            target_type
        )

        # --------------------------------------------------
        # INVALID TARGET
        # --------------------------------------------------

        if target_type == "Invalid":

            scan_result = {
                "success": False,
                "error": "Invalid target."
            }

        # ==================================================
        # IP ADDRESS
        # ==================================================

        elif target_type == "IP address":

            print(
                "Starting Nmap scan..."
            )

            scan_result = run_nmap_scan(
                target
            )

            print(
                "Nmap Result:"
            )

            print(
                scan_result
            )

            if scan_result["success"]:

                nmap_risk = analyze_risks(
                    scan_result["ports"]
                )

                risk_result = combine_risks(
                    nmap_result=nmap_risk
                )

        # ==================================================
        # URL
        # ==================================================

        elif target_type == "URL":

            print(
                "Starting Web scan..."
            )

            web_result = check_security_headers(
                target
            )

            print(
                "Web Result:"
            )

            print(
                web_result
            )

            print(
                "Starting TLS scan..."
            )

            tls_result = check_tls_certificate(
                target
            )

            print(
                "TLS Result:"
            )

            print(
                tls_result
            )

            if web_result["success"]:

                web_risk = analyze_web_risks(
                    web_result["findings"]
                )

                tls_risk = analyze_tls_risks(
                    tls_result
                )

                risk_result = combine_risks(
                    web_result=web_risk,
                    tls_result=tls_risk
                )

                scan_result = {
                    "success": True,
                    "ports": []
                }

            else:

                scan_result = {
                    "success": False,
                    "error": web_result["error"]
                }

        # ==================================================
        # DOMAIN
        # ==================================================

        elif target_type == "Domain":

            web_url = (
                f"https://{target}"
            )

            print(
                "Web URL:",
                web_url
            )

            print(
                "Starting Web scan..."
            )

            web_result = check_security_headers(
                web_url
            )

            print(
                "Web Result:"
            )

            print(
                web_result
            )

            print(
                "Starting TLS scan..."
            )

            tls_result = check_tls_certificate(
                web_url
            )

            print(
                "TLS Result:"
            )

            print(
                tls_result
            )

            if web_result["success"]:

                web_risk = analyze_web_risks(
                    web_result["findings"]
                )

                tls_risk = analyze_tls_risks(
                    tls_result
                )

                risk_result = combine_risks(
                    web_result=web_risk,
                    tls_result=tls_risk
                )

                scan_result = {
                    "success": True,
                    "ports": []
                }

            else:

                scan_result = {
                    "success": False,
                    "error": web_result["error"]
                }

        # ==================================================
        # SAVE RESULT
        # ==================================================

        if risk_result:

            # --------------------------------------------------
            # WEB DATA
            # --------------------------------------------------

            saved_web_data = {}

            if (
                web_result
                and web_result.get("success")
            ):

                saved_web_data = (
                    web_result.copy()
                )

            # --------------------------------------------------
            # TLS DATA
            # --------------------------------------------------

            saved_tls_data = {}

            if (
                tls_result
                and tls_result.get("success")
            ):

                saved_tls_data = (
                    tls_result.copy()
                )

            # --------------------------------------------------
            # RISK BREAKDOWN
            # --------------------------------------------------

            risk_breakdown = risk_result.get(
                "risk_breakdown",
                {}
            )

            if saved_web_data:

                saved_web_data[
                    "risk_breakdown"
                ] = risk_breakdown

            if saved_tls_data:

                saved_tls_data[
                    "risk_breakdown"
                ] = risk_breakdown

            # --------------------------------------------------
            # CREATE SCAN
            # --------------------------------------------------

            scan_record = Scan.objects.create(

                user=request.user,

                target=target,

                target_type=target_type,

                score=risk_result[
                    "score"
                ],

                risk_level=risk_result[
                    "risk_level"
                ],

                total_risk=risk_result[
                    "total_risk"
                ],

                web_scan_data=saved_web_data,

                tls_scan_data=saved_tls_data
            )

            print(
                "Scan saved to database:",
                scan_record.id
            )

            # --------------------------------------------------
            # SAVE FINDINGS
            # --------------------------------------------------

            for finding in risk_result[
                "findings"
            ]:

                cve_data = finding.get(
                    "cve_intelligence",
                    {}
                ).copy()

                cve_data.update({

                    "cve_risk_points": finding.get(
                        "cve_risk_points",
                        0
                    ),

                    "highest_cvss": finding.get(
                        "highest_cvss"
                    ),

                    "highest_severity": finding.get(
                        "highest_cve_severity",
                        "Unknown"
                    ),

                    "cve_count": finding.get(
                        "cve_count",
                        0
                    )
                })

                Finding.objects.create(

                    scan=scan_record,

                    title=finding[
                        "title"
                    ],

                    port=finding[
                        "port"
                    ],

                    service=finding[
                        "service"
                    ],

                    product=finding.get(
                        "product",
                        ""
                    ),

                    version=finding.get(
                        "version",
                        ""
                    ),

                    extra_info=finding.get(
                        "extrainfo",
                        ""
                    ),

                    severity=finding[
                        "severity"
                    ],

                    risk_points=finding[
                        "risk_points"
                    ],

                    description=finding[
                        "description"
                    ],

                    recommendation=finding.get(
                        "recommendation",
                        ""
                    ),

                    security_intelligence=finding.get(
                        "security_intelligence",
                        {}
                    ),

                    cve_intelligence=cve_data
                )

            print(
                "Findings saved to database"
            )

    # ======================================================
    # RENDER
    # ======================================================

    return render(
        request,
        "scanner/scan.html",
        {
            "target": target,
            "target_type": target_type,
            "scan_result": scan_result,
            "web_result": web_result,
            "tls_result": tls_result,
            "risk_result": risk_result
        }
    )


# ==========================================================
# HISTORY
# ==========================================================

@login_required
def history(request):

    scans = (
        Scan.objects
        .filter(
            user=request.user
        )
        .order_by("-created_at")
    )

    return render(
        request,
        "scanner/history.html",
        {
            "scans": scans
        }
    )


# ==========================================================
# SCAN DETAIL
# ==========================================================

@login_required
def scan_detail(
    request,
    scan_id
):

    scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user
    )

    findings = (
        scan.findings.all()
    )

    web_scan = (
        scan.web_scan_data
        or {}
    )

    tls_scan = (
        scan.tls_scan_data
        or {}
    )

    # ------------------------------------------------------
    # RISK BREAKDOWN
    # ------------------------------------------------------

    risk_breakdown = (
        web_scan.get(
            "risk_breakdown"
        )
        or tls_scan.get(
            "risk_breakdown"
        )
        or {}
    )

    # ------------------------------------------------------
    # FALLBACK FOR OLDER SCANS
    # ------------------------------------------------------

    if not risk_breakdown:

        exposure_risk = 0
        configuration_risk = 0
        cve_risk = 0
        tls_risk = 0

        for finding in findings:

            title = (
                finding.title
                or ""
            ).lower()

            risk_points = (
                finding.risk_points
                or 0
            )

            # Current Finding model does not
            # contain a category database field.
            #
            # Therefore classify older findings
            # using their title / stored data.

            if (
                "tls" in title
                or "certificate" in title
            ):

                tls_risk += risk_points

            elif (
                "cve" in title
                or "vulnerability" in title
                or "known vulnerability" in title
            ):

                cve_risk += risk_points

            elif (
                "header" in title
                or "cookie" in title
                or "cors" in title
                or "https redirect" in title
                or "http methods" in title
                or "server information" in title
                or "technology information" in title
            ):

                configuration_risk += risk_points

            else:

                exposure_risk += risk_points

        risk_breakdown = {

            "exposure_risk":
                exposure_risk,

            "configuration_risk":
                configuration_risk,

            "cve_risk":
                cve_risk,

            "tls_risk":
                tls_risk,

            "total_risk":
                scan.total_risk
        }

    # ======================================================
    # RENDER
    # ======================================================

    return render(
        request,
        "scanner/scan_detail.html",
        {
            "scan": scan,
            "findings": findings,
            "web_scan": web_scan,
            "tls_scan": tls_scan,
            "risk_breakdown": risk_breakdown
        }
    )


# ==========================================================
# PDF REPORT
# ==========================================================

@login_required
def generate_report(
    request,
    scan_id
):

    scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user
    )

    findings = (
        scan.findings.all()
    )

    web_scan = (
        scan.web_scan_data
        or {}
    )

    tls_scan = (
        scan.tls_scan_data
        or {}
    )

    buffer = BytesIO()

    generate_security_report(
        scan,
        findings,
        buffer,
        web_scan=web_scan,
        tls_scan=tls_scan
    )

    buffer.seek(0)

    response = HttpResponse(
        buffer.getvalue(),
        content_type="application/pdf"
    )

    response[
        "Content-Disposition"
    ] = (
        f'attachment; '
        f'filename="security_report_{scan.id}.pdf"'
    )

    return response


# ==========================================================
# SCAN COMPARISON
# ==========================================================

@login_required
def scan_comparison(
    request,
    scan_id
):

    current_scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user
    )

    previous_scan = (
        Scan.objects
        .filter(
            user=request.user,
            target=current_scan.target,
            created_at__lt=current_scan.created_at
        )
        .order_by("-created_at")
        .first()
    )

    comparison = None

    if previous_scan:

        comparison = compare_scans(
            previous_scan,
            current_scan
        )

    return render(
        request,
        "scanner/scan_comparison.html",
        {
            "current_scan":
                current_scan,

            "previous_scan":
                previous_scan,

            "comparison":
                comparison
        }
    )


# ==========================================================
# DASHBOARD
# ==========================================================

@login_required
def dashboard(request):

    # ======================================================
    # BASIC SCAN STATISTICS
    # ======================================================

    user_scans = Scan.objects.filter(
        user=request.user
    )

    total_scans = user_scans.count()

    average_score = (
        user_scans.aggregate(
            Avg("score")
        )["score__avg"]
    )

    high_risk = user_scans.filter(
        risk_level="High"
    ).count()

    medium_risk = user_scans.filter(
        risk_level="Medium"
    ).count()

    low_risk = user_scans.filter(
        risk_level="Low"
    ).count()

    # ======================================================
    # FINDING STATISTICS
    # ======================================================

    user_findings = Finding.objects.filter(
        scan__user=request.user
    )

    high_findings = user_findings.filter(
        severity="High"
    ).count()

    medium_findings = user_findings.filter(
        severity="Medium"
    ).count()

    low_findings = user_findings.filter(
        severity="Low"
    ).count()

    # ======================================================
    # RECENT SCANS
    # ======================================================

    recent_scans = (
        user_scans
        .order_by("-created_at")[:5]
    )

    # ======================================================
    # LATEST SCAN
    # ======================================================

    latest_scan = (
        user_scans
        .order_by("-created_at")
        .first()
    )

    # ======================================================
    # POSTURE TRENDS
    # ======================================================
    #
    # IMPORTANT:
    # The dashboard template already expects:
    #
    # posture_trends
    # posture_summary
    #
    # These were missing from the previous dashboard
    # context. They are now supplied here.
    #
    # ======================================================

    posture_scans = (
        user_scans
        .order_by("created_at")
    )

    posture_trends = get_posture_trends(
        posture_scans
    )

    posture_summary = get_posture_summary(
        posture_scans
    )

    # ======================================================
    # DASHBOARD CONTEXT
    # ======================================================

    context = {

        "total_scans":
            total_scans,

        "average_score":
            average_score,

        "high_risk":
            high_risk,

        "medium_risk":
            medium_risk,

        "low_risk":
            low_risk,

        "high_findings":
            high_findings,

        "medium_findings":
            medium_findings,

        "low_findings":
            low_findings,

        "recent_scans":
            recent_scans,

        "latest_scan":
            latest_scan,

        "posture_trends":
            posture_trends,

        "posture_summary":
            posture_summary
    }

    return render(
        request,
        "scanner/dashboard.html",
        context
    )


# ==========================================================
# SIGNUP
# ==========================================================

def signup_view(request):

    if request.method == "POST":

        username = request.POST.get(
            "username",
            ""
        ).strip()

        email = request.POST.get(
            "email",
            ""
        ).strip()

        password = request.POST.get(
            "password",
            ""
        )

        confirm_password = request.POST.get(
            "confirm_password",
            ""
        )

        # --------------------------------------------------
        # PASSWORD MATCH CHECK
        # --------------------------------------------------

        if password != confirm_password:

            return render(
                request,
                "scanner/signup.html",
                {
                    "error":
                        "Passwords do not match.",
                    "username":
                        username,
                    "email":
                        email
                }
            )

        # --------------------------------------------------
        # USERNAME CHECK
        # --------------------------------------------------

        from django.contrib.auth.models import User

        if User.objects.filter(
            username=username
        ).exists():

            return render(
                request,
                "scanner/signup.html",
                {
                    "error":
                        "Username already exists.",
                    "username":
                        username,
                    "email":
                        email
                }
            )

        # --------------------------------------------------
        # PASSWORD VALIDATION
        # --------------------------------------------------

        try:

             validate_password(
             password,
             user=None
            )

        except ValidationError as error:

             return render(
            request,
            "scanner/signup.html",
            {
            "error":
                " ".join(error.messages),
            "username":
                username,
            "email":
                email
            }
        )

        # --------------------------------------------------
        # CREATE USER
        # --------------------------------------------------

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        print(
            "New user created:",
            user.username
        )

        return redirect(
            "/login/"
        )

    return render(
        request,
        "scanner/signup.html"
    )

# ==========================================================
# LOGIN
# ==========================================================

def login_view(request):

    if request.method == "POST":

        username = request.POST.get(
            "username"
        )

        password = request.POST.get(
            "password"
        )

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:

            login(
                request,
                user
            )

            return redirect(
                "/dashboard/"
            )

        return render(
            request,
            "scanner/login.html",
            {
                "error":
                    "Invalid username or password."
            }
        )

    return render(
        request,
        "scanner/login.html"
    )


# ==========================================================
# LOGOUT
# ==========================================================

@login_required
def logout_view(request):

    if request.method == "POST":
        logout(request)

    return redirect("/login/")