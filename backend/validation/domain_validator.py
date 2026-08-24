import re
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,63}$"
)


def normalize_domain(domain):
    """
    Normalize user-provided domain input.
    """

    if not domain:
        return None

    domain = domain.strip().lower()

    # Remove URL scheme if supplied
    if domain.startswith("http://"):
        domain = domain[7:]

    elif domain.startswith("https://"):
        domain = domain[8:]

    # Remove path/query/fragment
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]

    # Remove trailing dot
    domain = domain.rstrip(".")

    return domain


def validate_domain(domain):
    """
    Validate whether the supplied input has a valid domain format.

    Returns:
        (True, normalized_domain)
        or
        (False, error_message)
    """

    if not domain or not domain.strip():
        return False, "Domain cannot be empty."

    normalized = normalize_domain(domain)

    if not normalized:
        return False, "Invalid domain."

    if len(normalized) > 253:
        return False, "Domain name is too long."

    if not DOMAIN_PATTERN.match(normalized):
        return False, f"Invalid domain format: {normalized}"

    return True, normalized


if __name__ == "__main__":

    print("=" * 50)
    print("DOMAIN VALIDATOR")
    print("=" * 50)

    domain = input("Enter domain: ")

    valid, result = validate_domain(domain)

    if valid:
        print("\n[+] Domain is valid.")
        print(f"[+] Normalized domain: {result}")
    else:
        print("\n[!] Domain validation failed.")
        print(f"[!] Reason: {result}")