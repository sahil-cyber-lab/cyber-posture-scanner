"""
URL configuration for cyber_posture project.
"""

from django.contrib import admin
from django.urls import path

from scanner import views


urlpatterns = [

    # =========================
    # ADMIN
    # =========================

    path(
        "admin/",
        admin.site.urls,
    ),

    # =========================
    # HOME
    # =========================

    path(
        "",
        views.home,
        name="home",
    ),

    # =========================
    # AUTHENTICATION
    # =========================
    
    path("signup/", views.signup_view, name="signup"),
    
    path(
        "login/",
        views.login_view,
        name="login",
    ),

    path(
        "logout/",
        views.logout_view,
        name="logout",
    ),

    # =========================
    # DASHBOARD
    # =========================

    path(
        "dashboard/",
        views.dashboard,
        name="dashboard",
    ),

    # =========================
    # SECURITY SCANNER
    # =========================

    path(
        "scan/",
        views.scan,
        name="scan",
    ),

    # =========================
    # SCAN HISTORY
    # =========================

    path(
        "history/",
        views.history,
        name="history",
    ),

    # =========================
    # SCAN DETAILS
    # =========================

    path(
        "history/<int:scan_id>/",
        views.scan_detail,
        name="scan_detail",
    ),

    # =========================
    # SCAN COMPARISON
    # =========================

    path(
        "compare/<int:scan_id>/",
        views.scan_comparison,
        name="scan_comparison",
    ),

    # =========================
    # PDF SECURITY REPORT
    # =========================

    path(
        "history/<int:scan_id>/report/",
        views.generate_report,
        name="generate_report",
    ),
]