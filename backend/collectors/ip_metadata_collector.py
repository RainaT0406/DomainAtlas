import json
import urllib.request


def get_ip_metadata(ip):
    url = f"https://ipwho.is/{ip}"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

        if not data.get("success", False):
            return {
                "ip": ip,
                "asn": None,
                "organization": None
            }

        connection = data.get("connection", {})

        return {
            "ip": ip,
            "asn": connection.get("asn"),
            "organization": connection.get("org")
        }

    except Exception as error:
        print(f"IP metadata error for {ip}: {error}")

        return {
            "ip": ip,
            "asn": None,
            "organization": None
        }


def get_all_ip_metadata(ips):
    results = []

    for ip in ips:
        print(f"[*] Looking up IP metadata: {ip}")

        metadata = get_ip_metadata(ip)
        results.append(metadata)

    return results

if __name__ == "__main__":
    ip = input("Enter IP address: ").strip()

    result = get_ip_metadata(ip)

    print("\nIP Metadata:")
    print(result)

