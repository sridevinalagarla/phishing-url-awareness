import re
from urllib.parse import urlparse


def inspect_url(raw_url):
    """Check visible URL text for selected warning signs."""

    url = raw_url.strip()
    findings = []

    # Check empty input
    if not url:
        return ["No URL entered."]

    # Add default scheme if missing
    candidate = url if "://" in url else "http://" + url

    # Parse URL safely
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()

    except ValueError:
        return ["Invalid URL format."]

    # Check hostname
    if not host:
        return ["Could not identify a hostname."]

    # Warning 1: @ symbol
    if "@" in candidate:
        findings.append(
            "Contains an @ symbol; inspect carefully."
        )

    # Warning 2: URL length
    if len(url) > 100:
        findings.append(
            "Unusually long URL (over 100 characters)."
        )

    # Warning 3: IP address instead of domain name
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append(
            "Uses an IP address instead of a familiar domain."
        )

    # Warning 4: Many hostname segments
    labels = [part for part in host.split(".") if part]

    if len(labels) >= 5:
        findings.append(
            "Contains many hostname segments/subdomains."
        )

    # Warning 5: Punycode hostname
    if "xn--" in host:
        findings.append(
            "Contains a punycode-style hostname."
        )

    # Warning 6: HTTP scheme
    if parsed.scheme.lower() == "http":
        findings.append(
            "Uses HTTP. HTTPS alone does not prove trust."
        )

    # No warning signs found
    if not findings:
        findings.append(
            "No listed warning signs found. This does NOT prove safety."
        )

    return findings


def main():

    print("=" * 50)
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")
    print("=" * 50)

    # Allow checking multiple URLs
    while True:

        raw_url = input(
            "\nEnter a sample URL (or type 'exit' to quit): "
        )

        # Exit option
        if raw_url.strip().lower() == "exit":
            print("\nThank you for using the checker!")
            break

        # Inspect URL
        findings = inspect_url(raw_url)

        print("\nResult:")

        for item in findings:
            print("- " + item)

        # Handle empty input
        if not raw_url.strip():
            print("\nStatus: Please enter a URL.")

        # No listed warning signs
        elif findings == [
            "No listed warning signs found. This does NOT prove safety."
        ]:
            print("\nStatus: No listed warning signs detected.")

        # Warning signs detected
        elif findings == ["Could not identify a hostname."] or findings == [
            "Invalid URL format."
        ]:
            print("\nStatus: Invalid URL. Please check your input.")

        else:
            warning_count = len(findings)

            print(
                f"\nStatus: REVIEW CAREFULLY - "
                f"{warning_count} warning sign(s) detected."
            )

        print("\nNever enter passwords from unexpected links.")


# Program execution starts here
if __name__ == "__main__":
    main()