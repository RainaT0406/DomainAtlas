import subprocess


def get_subdomains(domain):
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=True
        )

        subdomains = result.stdout.strip().splitlines()

        return subdomains

    except subprocess.CalledProcessError as error:
        print(f"Subfinder error: {error}")
        return []


if __name__ == "__main__":
    domain = input("Enter domain: ").strip()

    subdomains = get_subdomains(domain)

    print("\nSubdomains:")

    for subdomain in subdomains:
        print(f"  {subdomain}")