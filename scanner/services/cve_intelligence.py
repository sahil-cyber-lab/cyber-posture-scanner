import re
import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def normalize_version(version):
    """
    Convert a product version into a comparable tuple.

    Example:
        8.2       -> (8, 2)
        2.4.49    -> (2, 4, 49)
        8.2p1     -> (8, 2, 1)
    """

    if not version:
        return ()

    numbers = re.findall(r"\d+", str(version))

    return tuple(int(number) for number in numbers)


def compare_versions(version_a, version_b):
    """
    Compare two versions.

    Returns:
        -1 if version_a < version_b
         0 if version_a == version_b
         1 if version_a > version_b
    """

    a = normalize_version(version_a)
    b = normalize_version(version_b)

    max_length = max(len(a), len(b))

    a = a + (0,) * (max_length - len(a))
    b = b + (0,) * (max_length - len(b))

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


def version_matches_range(
    version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None,
):
    """
    Check whether a detected version falls inside
    an NVD CPE version range.
    """

    if not version:
        return False

    if start_including:
        if compare_versions(version, start_including) < 0:
            return False

    if start_excluding:
        if compare_versions(version, start_excluding) <= 0:
            return False

    if end_including:
        if compare_versions(version, end_including) > 0:
            return False

    if end_excluding:
        if compare_versions(version, end_excluding) >= 0:
            return False

    return True


def cpe_matches_product_version(
    cpe_match,
    product,
    version,
):
    """
    Determine whether an NVD CPE match applies to the
    detected product/version.

    This checks the CPE product/version and any NVD
    version-range boundaries.
    """

    if not cpe_match.get("vulnerable", False):
        return False

    criteria = cpe_match.get("criteria", "")

    if not criteria:
        return False

    parts = criteria.split(":")

    # A normal CPE 2.3 string looks like:
    #
    # cpe:2.3:a:vendor:product:version:...

    if len(parts) < 6:
        return False

    cpe_product = parts[4]
    cpe_version = parts[5]

    product_normalized = (product or "").lower().replace(" ", "_")
    cpe_product_normalized = cpe_product.lower()

    # Product must appear compatible.
    if (
        product_normalized not in cpe_product_normalized
        and cpe_product_normalized not in product_normalized
    ):
        return False

    # If the CPE specifies an exact version,
    # compare it directly.
    if cpe_version not in ("*", "-"):

        if compare_versions(version, cpe_version) != 0:
            return False

        return True

    # Otherwise use NVD's version range.
    return version_matches_range(
        version=version,
        start_including=cpe_match.get(
            "versionStartIncluding"
        ),
        start_excluding=cpe_match.get(
            "versionStartExcluding"
        ),
        end_including=cpe_match.get(
            "versionEndIncluding"
        ),
        end_excluding=cpe_match.get(
            "versionEndExcluding"
        ),
    )


def extract_cve_configuration_matches(
    cve,
    product,
    version,
):
    """
    Recursively inspect NVD CVE configuration nodes
    and return only applicable CPE matches.
    """

    matched_cpes = []

    def process_node(node):

        for cpe_match in node.get("cpeMatch", []):

            if cpe_matches_product_version(
                cpe_match,
                product,
                version,
            ):
                matched_cpes.append(
                    {
                        "criteria": cpe_match.get(
                            "criteria",
                            ""
                        ),
                        "matchCriteriaId": cpe_match.get(
                            "matchCriteriaId",
                            ""
                        ),
                        "versionStartIncluding": cpe_match.get(
                            "versionStartIncluding"
                        ),
                        "versionStartExcluding": cpe_match.get(
                            "versionStartExcluding"
                        ),
                        "versionEndIncluding": cpe_match.get(
                            "versionEndIncluding"
                        ),
                        "versionEndExcluding": cpe_match.get(
                            "versionEndExcluding"
                        ),
                    }
                )

        for child in node.get("children", []):
            process_node(child)

    configurations = cve.get("configurations", [])

    for configuration in configurations:

        for node in configuration.get("nodes", []):
            process_node(node)

    return matched_cpes


def extract_cvss(cve):
    """
    Extract the highest-priority CVSS information
    available in the NVD record.
    """

    metrics = cve.get("metrics", {})

    if metrics.get("cvssMetricV40"):
        metric = metrics["cvssMetricV40"][0]
        data = metric.get("cvssData", {})

        return {
            "version": "4.0",
            "severity": data.get(
                "baseSeverity",
                "Unknown"
            ),
            "score": data.get("baseScore"),
        }

    if metrics.get("cvssMetricV31"):
        metric = metrics["cvssMetricV31"][0]
        data = metric.get("cvssData", {})

        return {
            "version": "3.1",
            "severity": data.get(
                "baseSeverity",
                "Unknown"
            ),
            "score": data.get("baseScore"),
        }

    if metrics.get("cvssMetricV30"):
        metric = metrics["cvssMetricV30"][0]
        data = metric.get("cvssData", {})

        return {
            "version": "3.0",
            "severity": data.get(
                "baseSeverity",
                "Unknown"
            ),
            "score": data.get("baseScore"),
        }

    if metrics.get("cvssMetricV2"):
        metric = metrics["cvssMetricV2"][0]
        data = metric.get("cvssData", {})

        return {
            "version": "2.0",
            "severity": metric.get(
                "baseSeverity",
                "Unknown"
            ),
            "score": data.get("baseScore"),
        }

    return {
        "version": None,
        "severity": "Unknown",
        "score": None,
    }


def search_cves(
    keyword,
    product=None,
    version=None,
    timeout=15,
):
    """
    Search NVD and keep only CVEs whose CPE applicability
    matches the detected product/version.
    """

    if not keyword:
        return {
            "success": False,
            "total_results": 0,
            "vulnerabilities": [],
            "error": "No search keyword provided.",
        }

    try:

        response = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": 20,
            },
            timeout=timeout,
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as error:

        return {
            "success": False,
            "total_results": 0,
            "vulnerabilities": [],
            "error": str(error),
        }

    vulnerabilities = []

    for item in data.get("vulnerabilities", []):

        cve = item.get("cve", {})

        cve_id = cve.get("id", "")

        if product and version:

            matched_cpes = (
                extract_cve_configuration_matches(
                    cve,
                    product,
                    version,
                )
            )

            if not matched_cpes:
                continue

        else:
            matched_cpes = []

        description = ""

        for desc in cve.get(
            "descriptions",
            []
        ):

            if desc.get("lang") == "en":

                description = desc.get(
                    "value",
                    ""
                )

                break

        cvss = extract_cvss(cve)

        vulnerabilities.append(
            {
                "cve_id": cve_id,
                "severity": cvss["severity"],
                "cvss_score": cvss["score"],
                "cvss_version": cvss["version"],
                "description": description,
                "matched_cpes": matched_cpes,
            }
        )

    return {
        "success": True,
        "total_results": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def search_product_version(
    product,
    version,
):
    """
    Search NVD using detected product/version
    and perform CPE applicability matching.
    """

    product = (product or "").strip()
    version = (version or "").strip()

    if not product:

        return {
            "success": False,
            "total_results": 0,
            "vulnerabilities": [],
            "error": "Product information is missing.",
        }

    if not version:

        return {
            "success": False,
            "total_results": 0,
            "vulnerabilities": [],
            "error": (
                "Exact product version is required "
                "for vulnerability matching."
            ),
        }

    keyword = f"{product} {version}"

    return search_cves(
        keyword=keyword,
        product=product,
        version=version,
    )