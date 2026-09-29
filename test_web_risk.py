from scanner.services.web_scanner import check_security_headers
from scanner.services.risk_engine import analyze_web_risks


web_result = check_security_headers("https://example.com")

if web_result["success"]:

    risk_result = analyze_web_risks(
        web_result["findings"]
    )

    print(risk_result)

else:

    print(web_result["error"])