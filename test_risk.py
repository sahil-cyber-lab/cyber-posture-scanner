from scanner.services.risk_engine import analyze_risks


ports = [
    {
        "port": "445/tcp",
        "state": "open",
        "service": "microsoft-ds",
        "product": "",
        "version": ""
    },
    {
        "port": "8000/tcp",
        "state": "open",
        "service": "http-alt",
        "product": "",
        "version": ""
    }
]


result = analyze_risks(ports)

print(result)