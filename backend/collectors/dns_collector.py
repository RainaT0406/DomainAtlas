import dns.resolver


def get_dns_records(domain):
    records = {}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            records[record_type] = [
                answer.to_text() for answer in answers
            ]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            records[record_type] = []

    return records


if __name__ == "__main__":
    domain = input("Enter domain: ").strip()

    results = get_dns_records(domain)

    print("\nDNS Records:")
    for record_type, values in results.items():
        print(f"\n{record_type}:")
        for value in values:
            print(f"  {value}")