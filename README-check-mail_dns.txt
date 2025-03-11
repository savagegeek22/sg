--- Imports

import dns.resolver

 Above imports the dns.resolver module from the dnspython library, which is used to query DNS records.
----

--- Function: check_mx(domain)
def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')  # Query MX records
        mx_records = []
        for rdata in answers:
            mx_records.append((rdata.exchange.to_text(), rdata.preference))  # Store (mail server, priority)
        return sorted(mx_records, key=lambda x: x[1])  # Sort by priority
    except dns.resolver.NXDOMAIN:
        return "No MX record found"
    except Exception as e:
        return f"Error checking MX records: {e}"

 Above queries the MX (Mail Exchange) records of the domain.
Extracts and sorts the records based on priority.
If no MX records exist (NXDOMAIN), returns a message.
Catches other errors and returns an error message.
----


--- Function: check_spf(domain)

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')  # Query TXT records
        for txt_record in answers:
            if txt_record.to_text().startswith('"v=spf1'):  # SPF records start with "v=spf1"
                return txt_record.to_text().strip('"')  # Remove quotes
        return "No SPF record found"
    except Exception as e:
        return f"Error checking SPF: {e}"

 Above Looks for the SPF (Sender Policy Framework) record in the TXT records.
If found, returns it after removing surrounding quotes.
If not found or an error occurs, returns an appropriate message.
---


--- Function: check_dkim(domain)

def check_dkim(domain):
    selector = "default"  # Common selector; change if necessary
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"  # Construct DKIM record name
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for txt_record in answers:
            return txt_record.to_text().strip('"')  # Remove quotes
    except dns.resolver.NXDOMAIN:
        return "No DKIM record found"
    except Exception as e:
        return f"Error checking DKIM: {e}"

 Above Checks for the DKIM (DomainKeys Identified Mail) record using the "default" selector.
Constructs the DNS name: default._domainkey.<domain>.
If found, returns it after removing surrounding quotes.
If missing (NXDOMAIN error) or another error occurs, returns an appropriate message.
---


---Function: check_dmarc(domain)

def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"  # Construct DMARC record name
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for txt_record in answers:
            return txt_record.to_text().strip('"')  # Remove quotes
    except dns.resolver.NXDOMAIN:
        return "No DMARC record found"
    except Exception as e:
        return f"Error checking DMARC: {e}"
 
 Above Checks for the DMARC (Domain-based Message Authentication, Reporting & Conformance) record.
Constructs the DNS name: _dmarc.<domain>.
If found, returns it after removing surrounding quotes.
If missing (NXDOMAIN error) or another error occurs, returns an appropriate message.
---


---Function: validate_mx_fqdn(mx_records)

def validate_mx_fqdn(mx_records):
    invalid_fqdns = []
    for exchange, priority in mx_records:
        try:
            dns.resolver.resolve(exchange, 'A')  # Try resolving A record for the MX
        except Exception as e:
            invalid_fqdns.append((exchange, f"Invalid FQDN: {e}"))
    return invalid_fqdns

 Above Takes the list of MX records and checks if each mail server (exchange) has a valid A record (IPv4 address).
If an MX record does not resolve, it is marked as invalid.
---


---Function: print_section(title, content, divider="=")

def print_section(title, content, divider="="):
    print(f"\n{divider * 50}")
    print(f"{title}")
    print(f"{divider * 50}")
    print(content)

 Above Prints a formatted section to make output more readable.
Uses a divider (= by default) for clarity.
---


---Function: main()

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

 Above Prompts the user to enter a domain name.
Calls check_mx() and displays MX records.
Calls validate_mx_fqdn() to verify MX record validity.
Calls check_spf(), check_dkim(), and check_dmarc() to retrieve SPF, DKIM, and DMARC records.
Prints the results in formatted sections.
---

                                        
--- Script Execution

if __name__ == "__main__":
    main()

 Above ensures that main() runs only if the script is executed directly, not imported as a module.

                                        
                                        
---Example Output

Enter the domain to check: example.com

Checking email DNS records for: example.com

==================================================
MX Records
==================================================
mail.example.com (Priority: 10)

--------------------------------------------------
MX FQDN Validation
--------------------------------------------------
All MX FQDNs are valid.

==================================================
SPF Record
==================================================
v=spf1 include:_spf.example.com ~all

==================================================
DKIM Record
==================================================
v=DKIM1; k=rsa; p=MIIBIjANB...

==================================================
DMARC Record
==================================================
v=DMARC1; p=reject; rua=mailto:dmarc@example.com

---Summary
The script retrieves and validates email-related DNS records.
It sorts and formats the MX records.
It checks SPF, DKIM, and DMARC for proper email authentication.
It validates the MX hostnames to ensure they resolve.

---
