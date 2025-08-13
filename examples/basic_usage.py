#!/usr/bin/env python3
"""
Basic usage examples for the DomainIQ library.

This script demonstrates the core functionality of the DomainIQ Python client
including WHOIS lookups, DNS queries, domain reports, and more.
"""

import sys
from pathlib import Path

# Add the parent directory to Python path for local development
sys.path.insert(0, str(Path(__file__).parent.parent))

from domainiq import DomainIQClient, DomainIQError
from domainiq.models import DNSRecordType


def main() -> int:
    """Main example function."""
    print("DomainIQ Python Library - Basic Usage Examples")
    print("=" * 50)

    try:
        # Create client with default configuration
        # API key will be loaded from environment variable, config file, or prompt
        client = DomainIQClient()

        # Example 1: WHOIS Lookup
        print("\n1. WHOIS Lookup Example")
        print("-" * 30)
        domain = "example.com"
        whois_result = client.whois_lookup(domain=domain, full=True)
        if whois_result:
            print(f"Domain: {whois_result.domain}")
            print(f"Registrar: {whois_result.registrar}")
            print(f"Creation Date: {whois_result.creation_date}")
            print(f"Expiration Date: {whois_result.expiration_date}")
            print(f"Registrant: {whois_result.registrant_name}")
            print(f"Organization: {whois_result.registrant_organization}")
        else:
            print("No WHOIS data found")

        # Example 2: DNS Lookup
        print("\n2. DNS Lookup Example")
        print("-" * 30)
        dns_result = client.dns_lookup(
            query=domain,
            record_types=[DNSRecordType.A, DNSRecordType.MX, DNSRecordType.NS]
        )
        if dns_result:
            print(f"DNS records for {dns_result.domain}:")
            for record in dns_result.records:
                print(f"  {record.type}: {record.value}")
        else:
            print("No DNS data found")

        # Example 3: Domain Categorization
        print("\n3. Domain Categorization Example")
        print("-" * 30)
        domains_to_categorize = ["example.com", "google.com", "github.com"]
        categories = client.domain_categorize(domains_to_categorize)
        for category in categories:
            print(f"{category.domain}: {', '.join(category.categories)}")

        # Example 4: Domain Report
        print("\n4. Domain Report Example")
        print("-" * 30)
        report = client.domain_report(domain)
        if report:
            print(f"Domain Report for {report.domain}")
            print(f"Risk Score: {report.risk_score}")
            if report.categories:
                print(f"Categories: {', '.join(report.categories)}")
            if report.related_domains:
                print(f"Related Domains: {', '.join(report.related_domains[:5])}")
        else:
            print("No domain report available")

        # Example 5: Bulk Operations
        print("\n5. Bulk DNS Lookup Example")
        print("-" * 30)
        bulk_domains = ["example.com", "google.com", "github.com"]
        bulk_results = client.bulk_dns(bulk_domains)
        print(f"Processed {len(bulk_results)} domains:")
        for result in bulk_results[:3]:  # Show first 3 results
            print(f"  {result.get('domain', 'N/A')}: {result.get('ip', 'N/A')}")

        # Example 6: Domain Search
        print("\n6. Domain Search Example")
        print("-" * 30)
        search_results = client.domain_search(
            keywords=["example"],
            match="any",
            limit=5
        )
        if search_results:
            print("Found domains matching 'example':")
            # The actual structure depends on the API response
            print(f"Total results: {search_results.get('total', 'Unknown')}")
        else:
            print("No search results found")

        # Example 7: Email Report
        print("\n7. Email Report Example")
        print("-" * 30)
        email_report = client.email_report("admin@example.com")
        if email_report:
            print("Email report generated successfully")
            # Print some basic info about the report
            if isinstance(email_report, dict):
                print(f"Report contains {len(email_report)} fields")
        else:
            print("No email report available")

        # Example 8: Monitor List (if monitoring is enabled)
        print("\n8. Monitor List Example")
        print("-" * 30)
        try:
            monitors = client.monitor_list()
            if monitors:
                print(f"Found {len(monitors)} active monitors:")
                for monitor in monitors[:3]:  # Show first 3
                    print(f"  {monitor.name} ({monitor.type})")
            else:
                print("No active monitors found")
        except DomainIQError as e:
            print(f"Monitor access failed: {e}")

        # Example 9: Using Context Manager
        print("\n9. Context Manager Example")
        print("-" * 30)
        with DomainIQClient() as context_client:
            whois_data = context_client.whois_lookup(domain="github.com")
            if whois_data:
                print(f"GitHub registrar: {whois_data.registrar}")

        print("\n" + "=" * 50)
        print("Basic usage examples completed successfully!")

    except DomainIQError as e:
        print(f"DomainIQ Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
