import ipaddress
import re
from urllib.parse import urlparse


def is_valid_domain(domain):
    """
    Check whether the given string looks like a valid domain name.
    """

    if len(domain) > 253:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    labels = domain.split(".")

    # Domain should contain at least one dot
    if len(labels) < 2:
        return False

    for label in labels:

        if not label:
            return False

        if len(label) > 63:
            return False

        # Label cannot start or end with hyphen
        if label.startswith("-") or label.endswith("-"):
            return False

        # Only letters, numbers and hyphen allowed
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False

    return True


def detect_target_type(target):

    target = target.strip()

    # Empty target
    if not target:
        return "Invalid"

    # IP address
    try:
        ipaddress.ip_address(target)
        return "IP address"

    except ValueError:
        pass

    # URL
    if target.startswith(("http://", "https://")):

        try:
            parsed = urlparse(target)

            if (
                parsed.netloc
                and " " not in target
                and parsed.hostname
            ):
                return "URL"

        except ValueError:
            pass

        return "Invalid"

    # Domain
    if is_valid_domain(target):
        return "Domain"

    return "Invalid"