import subprocess
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_output):

    ports = []

    root = ET.fromstring(xml_output)

    for port in root.findall(".//port"):

        port_id = port.get("portid")
        protocol = port.get("protocol")

        state_element = port.find("state")
        service_element = port.find("service")

        # -------------------------
        # PORT STATE
        # -------------------------

        state = (
            state_element.get("state")
            if state_element is not None
            else "unknown"
        )

        # -------------------------
        # SERVICE INFORMATION
        # -------------------------

        service = "unknown"
        product = ""
        version = ""
        extrainfo = ""

        if service_element is not None:

            service = service_element.get(
                "name",
                "unknown"
            )

            product = service_element.get(
                "product",
                ""
            )

            version = service_element.get(
                "version",
                ""
            )

            extrainfo = service_element.get(
                "extrainfo",
                ""
            )

        # -------------------------
        # CREATE PORT RESULT
        # -------------------------

        ports.append({

            "port": f"{port_id}/{protocol}",

            "port_number": int(port_id)
            if port_id and port_id.isdigit()
            else None,

            "protocol": protocol,

            "state": state,

            "service": service,

            "product": product,

            "version": version,

            "extrainfo": extrainfo

        })

    return ports


def run_nmap_scan(target):

    try:

        result = subprocess.run(
            [
                "nmap",
                "-sV",
                "-oX",
                "-",
                target
            ],

            capture_output=True,

            text=True,

            timeout=600
        )

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "error": (
                "Nmap scan timed out "
                "after 10 minutes."
            )
        }

    except FileNotFoundError:

        return {
            "success": False,
            "error": (
                "Nmap was not found. "
                "Please make sure Nmap is installed "
                "and available in PATH."
            )
        }

    except Exception as error:

        return {
            "success": False,
            "error": str(error)
        }

    # -------------------------
    # NMAP ERROR
    # -------------------------

    if result.returncode != 0:

        return {
            "success": False,
            "error": result.stderr
        }

    # -------------------------
    # PARSE XML
    # -------------------------

    try:

        parsed_results = parse_nmap_xml(
            result.stdout
        )

        return {

            "success": True,

            "ports": parsed_results,

            "total_ports": len(
                parsed_results
            ),

            "open_ports": [
                port
                for port in parsed_results
                if port["state"] == "open"
            ]

        }

    except ET.ParseError as error:

        return {
            "success": False,
            "error": (
                f"XML parsing failed: {error}"
            )
        }