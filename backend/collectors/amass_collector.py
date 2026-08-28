import re
import subprocess


def get_amass_subdomains(domain):

    try:

        print("[*] Running Amass...")

        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )

        subdomains = set()

        # Remove ANSI terminal color/control sequences
        ansi_escape = re.compile(
            r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
        )

        output = ansi_escape.sub(
            "",
            result.stdout
        )

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            if " (FQDN) --> " not in line:
                continue

            source = line.split(
                " (FQDN) --> ",
                1
            )[0].strip()

            if (
                source.endswith(f".{domain}")
                and source != domain
            ):
                subdomains.add(source)

        print(
            f"[+] Amass found: {len(subdomains)}"
        )

        return sorted(subdomains)

    except subprocess.TimeoutExpired:

        print(
            "[!] Amass timed out after 60 seconds."
        )

        print(
            "[!] Continuing without Amass."
        )

        return []

    except subprocess.CalledProcessError as error:

        print(
            f"[!] Amass failed: {error}"
        )

        print(
            "[!] Continuing without Amass."
        )

        return []

    except FileNotFoundError:

        print(
            "[!] Amass executable not found."
        )

        print(
            "[!] Continuing without Amass."
        )

        return []


if __name__ == "__main__":

    domain = input(
        "Enter domain: "
    ).strip()

    subdomains = get_amass_subdomains(
        domain
    )

    print("\nAmass Subdomains:")

    for subdomain in subdomains:

        print(
            f"  {subdomain}"
        )