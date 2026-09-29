from scanner.services.risk_engine import combine_risks


nmap_result = {
    "findings": [
        {
            "title": "SMB service exposed",
            "port": "445/tcp",
            "service": "microsoft-ds",
            "severity": "Medium",
            "risk_points": 10,
            "description": "SMB is exposed on the target."
        }
    ],
    "total_risk": 10
}


web_result = {
    "findings": [
        {
            "title": "Content-Security-Policy header is missing",
            "port": "-",
            "service": "Web",
            "severity": "Medium",
            "risk_points": 10,
            "description": "CSP header was not detected."
        },
        {
            "title": "X-Frame-Options header is missing",
            "port": "-",
            "service": "Web",
            "severity": "Low",
            "risk_points": 5,
            "description": "X-Frame-Options header was not detected."
        }
    ],
    "total_risk": 15
}


result = combine_risks(
    nmap_result,
    web_result
)

print(result)