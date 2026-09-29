import requests
from urllib.parse import urljoin, urlparse


REQUEST_TIMEOUT = 10


def urlunparse_http(url):
    """
    Convert an HTTPS URL into its HTTP equivalent.

    Example:
        https://example.com/path
        ->
        http://example.com/path
    """

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid target hostname.")

    # Preserve explicit non-standard ports.
    if parsed.port:
        if parsed.port == 443:
            netloc = hostname
        else:
            netloc = f"{hostname}:{parsed.port}"
    else:
        netloc = hostname

    path = parsed.path or "/"

    if parsed.query:
        path += f"?{parsed.query}"

    return f"http://{netloc}{path}"


def check_security_headers(url):
    try:

        # =========================================================
        # 1. MAIN REQUEST
        # =========================================================

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )

        headers = response.headers

        findings = []

        # =========================================================
        # 2. SECURITY HEADERS
        # =========================================================

        security_headers = {
            "Content-Security-Policy":
                headers.get("Content-Security-Policy"),

            "Strict-Transport-Security":
                headers.get("Strict-Transport-Security"),

            "X-Content-Type-Options":
                headers.get("X-Content-Type-Options"),

            "X-Frame-Options":
                headers.get("X-Frame-Options"),

            "Referrer-Policy":
                headers.get("Referrer-Policy"),

            "Permissions-Policy":
                headers.get("Permissions-Policy"),
        }

        for header, value in security_headers.items():

            if value is None:

                findings.append({
                    "type": "security_header",
                    "header": header,
                    "status": "Missing"
                })

            else:

                findings.append({
                    "type": "security_header",
                    "header": header,
                    "status": "Present",
                    "value": value
                })

        # =========================================================
        # 3. SERVER INFORMATION DISCLOSURE
        # =========================================================

        server_header = headers.get("Server")

        if server_header:

            findings.append({
                "type": "server_information",
                "header": "Server",
                "status": "Present",
                "value": server_header
            })

        else:

            findings.append({
                "type": "server_information",
                "header": "Server",
                "status": "Not disclosed"
            })

        # =========================================================
        # 4. X-POWERED-BY INFORMATION DISCLOSURE
        # =========================================================

        powered_by = headers.get("X-Powered-By")

        if powered_by:

            findings.append({
                "type": "technology_disclosure",
                "header": "X-Powered-By",
                "status": "Present",
                "value": powered_by
            })

        else:

            findings.append({
                "type": "technology_disclosure",
                "header": "X-Powered-By",
                "status": "Not disclosed"
            })

        # =========================================================
        # 5. HTTP -> HTTPS REDIRECT VERIFICATION
        # =========================================================

        https_redirect = None

        http_redirect_data = {
            "checked": False,
            "source_url": None,
            "status_code": None,
            "location": None,
            "final_url": None,
            "redirect_chain": [],
            "status": "Could not verify"
        }

        parsed_url = urlparse(url)

        if parsed_url.scheme.lower() in ("http", "https"):

            try:

                # Always test the HTTP version of the target.
                http_url = urlunparse_http(url)

                # -------------------------------------------------
                # First request:
                # Do NOT follow redirects.
                # This allows us to inspect the real HTTP response.
                # -------------------------------------------------

                http_response = requests.get(
                    http_url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False
                )

                http_status = http_response.status_code
                location = http_response.headers.get("Location")

                http_redirect_data.update({
                    "checked": True,
                    "source_url": http_url,
                    "status_code": http_status,
                    "location": location
                })

                # -------------------------------------------------
                # HTTP -> HTTPS redirect detected
                # -------------------------------------------------

                if (
                    http_status in (301, 302, 303, 307, 308)
                    and location
                ):

                    redirect_url = urljoin(
                        http_url,
                        location
                    )

                    redirect_parsed = urlparse(
                        redirect_url
                    )

                    # ---------------------------------------------
                    # Redirect leads directly to HTTPS
                    # ---------------------------------------------

                    if redirect_parsed.scheme.lower() == "https":

                        https_redirect = True

                        try:

                            chain_response = requests.get(
                                http_url,
                                timeout=REQUEST_TIMEOUT,
                                allow_redirects=True
                            )

                            final_url = chain_response.url

                            redirect_chain = [
                                str(item.url)
                                for item in chain_response.history
                            ]

                            redirect_chain.append(
                                str(chain_response.url)
                            )

                            http_redirect_data.update({
                                "final_url": final_url,
                                "redirect_chain": redirect_chain,
                                "status": "Enabled"
                            })

                        except requests.RequestException:

                            http_redirect_data.update({
                                "final_url": redirect_url,
                                "redirect_chain": [
                                    http_url,
                                    redirect_url
                                ],
                                "status": "Enabled"
                            })

                        findings.append({
                            "type": "https_redirect",
                            "header": "HTTPS Redirect",
                            "status": "Enabled",
                            "source_url": http_url,
                            "status_code": http_status,
                            "location": location,
                            "final_url":
                                http_redirect_data["final_url"],
                            "redirect_chain":
                                http_redirect_data[
                                    "redirect_chain"
                                ]
                        })

                    # ---------------------------------------------
                    # Redirect exists but does NOT lead to HTTPS
                    # ---------------------------------------------

                    else:

                        https_redirect = False

                        http_redirect_data.update({
                            "final_url": redirect_url,
                            "redirect_chain": [
                                http_url,
                                redirect_url
                            ],
                            "status":
                                "Redirect does not lead to HTTPS"
                        })

                        findings.append({
                            "type": "https_redirect",
                            "header": "HTTPS Redirect",
                            "status": "Not detected",
                            "source_url": http_url,
                            "status_code": http_status,
                            "location": location,
                            "final_url": redirect_url,
                            "redirect_chain":
                                http_redirect_data[
                                    "redirect_chain"
                                ]
                        })

                # -------------------------------------------------
                # No redirect
                # -------------------------------------------------

                else:

                    https_redirect = False

                    http_redirect_data.update({
                        "final_url": http_url,
                        "redirect_chain": [
                            http_url
                        ],
                        "status":
                            "No HTTP redirect detected"
                    })

                    findings.append({
                        "type": "https_redirect",
                        "header": "HTTPS Redirect",
                        "status": "Not detected",
                        "source_url": http_url,
                        "status_code": http_status,
                        "location": location,
                        "final_url": http_url,
                        "redirect_chain":
                            http_redirect_data[
                                "redirect_chain"
                            ]
                    })

            # -----------------------------------------------------
            # Redirect verification errors
            # -----------------------------------------------------

            except requests.exceptions.Timeout:

                https_redirect = None

                http_redirect_data.update({
                    "status": "Could not verify",
                    "error":
                        "HTTP redirect check timed out."
                })

                findings.append({
                    "type": "https_redirect",
                    "header": "HTTPS Redirect",
                    "status": "Could not verify",
                    "error":
                        "HTTP redirect check timed out."
                })

            except requests.exceptions.SSLError as error:

                https_redirect = None

                http_redirect_data.update({
                    "status": "Could not verify",
                    "error": str(error)
                })

                findings.append({
                    "type": "https_redirect",
                    "header": "HTTPS Redirect",
                    "status": "Could not verify",
                    "error": str(error)
                })

            except requests.RequestException as error:

                https_redirect = None

                http_redirect_data.update({
                    "status": "Could not verify",
                    "error": str(error)
                })

                findings.append({
                    "type": "https_redirect",
                    "header": "HTTPS Redirect",
                    "status": "Could not verify",
                    "error": str(error)
                })

            except ValueError as error:

                https_redirect = None

                http_redirect_data.update({
                    "status": "Could not verify",
                    "error": str(error)
                })

                findings.append({
                    "type": "https_redirect",
                    "header": "HTTPS Redirect",
                    "status": "Could not verify",
                    "error": str(error)
                })

        # =========================================================
        # 6. COOKIE SECURITY
        # =========================================================

        cookies = []

        for cookie in response.cookies:

            rest = getattr(cookie, "_rest", {})

            samesite = rest.get("SameSite")

            httponly = (
                "HttpOnly" in rest
                or "httponly" in rest
            )

            cookie_data = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": httponly,
                "samesite": samesite
            }

            cookies.append(cookie_data)

        if cookies:

            for cookie in cookies:

                findings.append({
                    "type": "cookie_security",
                    "header": "Cookie",
                    "status": "Present",
                    "cookie": cookie
                })

        else:

            findings.append({
                "type": "cookie_security",
                "header": "Cookie",
                "status": "No cookies detected"
            })

        # =========================================================
        # 7. CORS CONFIGURATION
        # =========================================================

        cors_origin = headers.get(
            "Access-Control-Allow-Origin"
        )

        cors_credentials = headers.get(
            "Access-Control-Allow-Credentials"
        )

        cors_methods = headers.get(
            "Access-Control-Allow-Methods"
        )

        cors_info = {
            "allow_origin": cors_origin,
            "allow_credentials": cors_credentials,
            "allow_methods": cors_methods
        }

        if cors_origin:

            findings.append({
                "type": "cors",
                "header": "Access-Control-Allow-Origin",
                "status": "Present",
                "value": cors_origin,
                "credentials": cors_credentials,
                "methods": cors_methods
            })

        else:

            findings.append({
                "type": "cors",
                "header": "Access-Control-Allow-Origin",
                "status": "Not configured"
            })

        # =========================================================
        # 8. HTTP METHODS
        # =========================================================

        allow_header = headers.get("Allow")

        methods = []

        if allow_header:

            methods = [
                method.strip().upper()
                for method in allow_header.split(",")
                if method.strip()
            ]

            findings.append({
                "type": "http_methods",
                "header": "Allow",
                "status": "Present",
                "methods": methods
            })

        else:

            findings.append({
                "type": "http_methods",
                "header": "Allow",
                "status": "Not disclosed"
            })

        # =========================================================
        # 9. OPTIONS REQUEST
        # =========================================================

        options_methods = []

        try:

            options_response = requests.options(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            options_allow = options_response.headers.get(
                "Allow"
            )

            if options_allow:

                options_methods = [
                    method.strip().upper()
                    for method in options_allow.split(",")
                    if method.strip()
                ]

        except requests.RequestException:

            options_methods = []

        # =========================================================
        # 10. SECURITY.TXT
        # =========================================================

        security_txt_url = urljoin(
            response.url,
            "/.well-known/security.txt"
        )

        security_txt_found = False

        try:

            security_txt_response = requests.get(
                security_txt_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            if (
                security_txt_response.status_code == 200
                and security_txt_response.text.strip()
            ):

                security_txt_found = True

                findings.append({
                    "type": "security_txt",
                    "header": "security.txt",
                    "status": "Present",
                    "url":
                        security_txt_response.url
                })

            else:

                findings.append({
                    "type": "security_txt",
                    "header": "security.txt",
                    "status": "Not found"
                })

        except requests.RequestException:

            findings.append({
                "type": "security_txt",
                "header": "security.txt",
                "status": "Could not check"
            })

        # =========================================================
        # 11. ROBOTS.TXT
        # =========================================================

        robots_url = urljoin(
            response.url,
            "/robots.txt"
        )

        robots_found = False

        try:

            robots_response = requests.get(
                robots_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            if (
                robots_response.status_code == 200
                and robots_response.text.strip()
            ):

                robots_found = True

                findings.append({
                    "type": "robots_txt",
                    "header": "robots.txt",
                    "status": "Present",
                    "url":
                        robots_response.url
                })

            else:

                findings.append({
                    "type": "robots_txt",
                    "header": "robots.txt",
                    "status": "Not found"
                })

        except requests.RequestException:

            findings.append({
                "type": "robots_txt",
                "header": "robots.txt",
                "status": "Could not check"
            })

        # =========================================================
        # 12. RESPONSE INFORMATION
        # =========================================================

        findings.append({
            "type": "response_information",
            "header": "HTTP Status",
            "status": str(response.status_code),
            "final_url": response.url
        })

        # =========================================================
        # 13. TECHNOLOGY INFORMATION
        # =========================================================

        technology = []

        if server_header:
            technology.append(server_header)

        if powered_by:
            technology.append(powered_by)

        if technology:

            findings.append({
                "type": "technology_detection",
                "header": "Detected Technology",
                "status": "Detected",
                "technologies": technology
            })

        else:

            findings.append({
                "type": "technology_detection",
                "header": "Detected Technology",
                "status":
                    "No obvious technology disclosed"
            })

        # =========================================================
        # 14. FINAL RESULT
        # =========================================================

        return {

            "success": True,

            "status_code":
                response.status_code,

            "final_url":
                response.url,

            "redirected":
                response.url != url,

            "headers":
                security_headers,

            "server":
                server_header,

            "powered_by":
                powered_by,

            "https_redirect":
                https_redirect,

            "http_redirect":
                http_redirect_data,

            "cookies":
                cookies,

            "cors":
                cors_info,

            "http_methods":
                methods,

            "options_methods":
                options_methods,

            "security_txt":
                security_txt_found,

            "robots_txt":
                robots_found,

            "technology":
                technology,

            "findings":
                findings
        }

    # =============================================================
    # 15. MAIN REQUEST ERROR HANDLING
    # =============================================================

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "error":
                "Web request timed out after 10 seconds."
        }

    except requests.exceptions.SSLError:

        return {
            "success": False,
            "error":
                "SSL/TLS connection failed."
        }

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "error":
                "Could not connect to the target."
        }

    except requests.RequestException as error:

        return {
            "success": False,
            "error":
                f"Web request failed: {error}"
        }

    except Exception as error:

        return {
            "success": False,
            "error":
                f"Unexpected error: {error}"
        }