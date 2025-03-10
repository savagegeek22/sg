import dns.resolver

def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        for rdata in answers:
            mx_records.append((rdata.exchange.to_text(), rdata.preference))
        return sorted(mx_records, key=lambda x: x[1])  # Sort by priority
    except dns.resolver.NXDOMAIN:
        return "No MX record found"
    except Exception as e:
        return f"Error checking MX records: {e}"

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for txt_record in answers:
            if txt_record.to_text().startswith('"v=spf1'):
                return txt_record.to_text().strip('"')
        return "No SPF record found"
    except Exception as e:
        return f"Error checking SPF: {e}"

def check_dkim(domain):
    selector = "default"  # Common selector; change if necessary
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for txt_record in answers:
            return txt_record.to_text().strip('"')
    except dns.resolver.NXDOMAIN:
        return "No DKIM record found"
    except Exception as e:
        return f"Error checking DKIM: {e}"

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for txt_record in answers:
            return txt_record.to_text().strip('"')
    except dns.resolver.NXDOMAIN:
        return "No DMARC record found"
    except Exception as e:
        return f"Error checking DMARC: {e}"

def validate_mx_fqdn(mx_records):
    invalid_fqdns = []
    for exchange, priority in mx_records:
        try:
            dns.resolver.resolve(exchange, 'A')  # Try resolving A record for the MX
        except Exception as e:
            invalid_fqdns.append((exchange, f"Invalid FQDN: {e}"))
    return invalid_fqdns

def print_section(title, content, divider="="):
    print(f"\n{divider * 50}")
    print(f"{title}")
    print(f"{divider * 50}")
    print(content)

def main():
    domain = input("Enter the domain to check: ")
    print(f"\nChecking email DNS records for: {domain}")

    # Check MX records
    mx_records = check_mx(domain)
    if isinstance(mx_records, str):
        print_section("MX Records", mx_records)
    else:
        mx_output = "\n".join([f"{exchange} (Priority: {priority})" for exchange, priority in mx_records])
        print_section("MX Records", mx_output)

        # Validate MX FQDNs
        invalid_fqdns = validate_mx_fqdn(mx_records)
        if invalid_fqdns:
            invalid_output = "\n".join([f"{fqdn}: {error}" for fqdn, error in invalid_fqdns])
            print_section("Invalid MX FQDNs", invalid_output, "-")
        else:
            print_section("MX FQDN Validation", "All MX FQDNs are valid.", "-")

    # Check SPF
    spf = check_spf(domain)
    print_section("SPF Record", spf)

    # Check DKIM
    dkim = check_dkim(domain)
    print_section("DKIM Record", dkim)

    # Check DMARC
    dmarc = check_dmarc(domain)
    print_section("DMARC Record", dmarc)

if __name__ == "__main__":
    main()
