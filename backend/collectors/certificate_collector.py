import json
import urllib.parse
import urllib.request


def get_certificates(domain):
    base_url = "https://api.certspotter.com/v1/issuances"

    params = {
        "domain": domain,
        "include_subdomains": "true",
        "match_wildcards": "true"
    }

    url = base_url + "?" + urllib.parse.urlencode(params)

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Domain-OSINT-Research-Project/1.0"
            }
        )

        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))

        certificates = []

        for entry in data:
            certificates.append({
                "id": entry.get("id"),
                "certificate_sha256": entry.get("cert_sha256"),
                "public_key_sha256": entry.get("pubkey_sha256"),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "revoked": entry.get("revoked", False)
            })

        return certificates

    except Exception as error:
        print(f"Certificate collection error: {error}")
        return []