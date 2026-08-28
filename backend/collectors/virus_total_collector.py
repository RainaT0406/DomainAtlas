import os
import requests

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ============================================================
# VIRUSTOTAL API
# ============================================================

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ============================================================
# DOMAIN LOOKUP
# ============================================================

def collect_virustotal_domain(domain: str):

    if not VIRUSTOTAL_API_KEY:
        raise ValueError(
            "VIRUSTOTAL_API_KEY is not configured in .env"
        )

    url = f"{VT_BASE_URL}/domains/{domain}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    print(f"[*] Looking up domain in VirusTotal: {domain}")

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code == 404:
            print("[!] Domain not found in VirusTotal.")
            return {}

        if response.status_code == 401:
            raise ValueError(
                "VirusTotal API key is invalid or unauthorized."
            )

        if response.status_code == 429:
            raise ValueError(
                "VirusTotal API rate limit exceeded."
            )

        response.raise_for_status()

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        result = {

            "domain": domain,

            "reputation": attributes.get(
                "reputation"
            ),

            "last_analysis_stats": attributes.get(
                "last_analysis_stats",
                {}
            ),

            "categories": attributes.get(
                "categories",
                {}
            ),

            "registrar": attributes.get(
                "registrar"
            ),

            "creation_date": attributes.get(
                "creation_date"
            ),

            "last_modification_date": attributes.get(
                "last_modification_date"
            ),

            "last_dns_records": attributes.get(
                "last_dns_records",
                []
            ),

            "popularity_ranks": attributes.get(
                "popularity_ranks",
                {}
            )
        }

        print("[+] VirusTotal domain lookup complete.")

        return result

    except requests.RequestException as error:

        raise RuntimeError(
            f"VirusTotal request failed: {error}"
        )


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    domain = input("Enter domain: ").strip()

    if not domain:
        print("[!] Domain cannot be empty.")
        raise SystemExit(1)

    try:

        result = collect_virustotal_domain(domain)

        print("\nVirusTotal Result:")
        print(result)

    except Exception as error:

        print(f"\n[!] Error: {error}")