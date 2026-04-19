"""
Security research examples using the DomainIQ library.

This script demonstrates how to use DomainIQ for cybersecurity research,
threat intelligence, and domain analysis workflows.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add the parent directory to Python path for local development
sys.path.insert(0, str(Path(__file__).parent.parent))

from domainiq import DomainIQClient, DomainIQError
from domainiq.utils import validate_domain

# Security analysis constants
NEW_DOMAIN_THRESHOLD_DAYS = 30
SUSPICIOUS_DOMAIN_THRESHOLD_DAYS = 60
MIN_DOMAIN_LENGTH_FOR_VARIATIONS = 3
MAX_TYPOSQUAT_VARIATIONS = 50
_HIGH_RISK_CATEGORIES: frozenset[str] = frozenset(
    ["malware", "phishing", "spam", "suspicious", "botnet"]
)
_SUSPICIOUS_REGISTRARS: frozenset[str] = frozenset(
    ["namecheap", "godaddy", "domains by proxy"]
)


class SecurityResearcher:
    """Helper class for security research workflows."""

    def __init__(self, client: DomainIQClient) -> None:
        self.client = client

    def analyze_suspicious_domains(self, domains: list[str]) -> dict[str, Any]:
        """Analyze a list of potentially suspicious domains.

        Args:
            domains: List of domain names to analyze

        Returns:
            Analysis report with risk indicators
        """
        print(f"Analyzing {len(domains)} suspicious domains...")

        analysis: dict[str, Any] = {
            "domains_analyzed": len(domains),
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "results": [],
            "risk_indicators": {
                "newly_registered": [],
                "privacy_protected": [],
                "suspicious_registrars": [],
                "related_domains": [],
                "high_risk_categories": [],
            },
        }

        for domain in domains:
            if not validate_domain(domain):
                print(f"Skipping invalid domain: {domain}")
                continue

            domain_analysis = self._analyze_single_domain(domain)
            analysis["results"].append(domain_analysis)

            self._check_risk_indicators(domain_analysis, analysis["risk_indicators"])

        return analysis

    def _analyze_single_domain(self, domain: str) -> dict[str, Any]:
        """Analyze a single domain for security indicators."""
        print(f"  Analyzing {domain}...")

        domain_data: dict[str, Any] = {
            "domain": domain,
            "whois": None,
            "dns": None,
            "categories": None,
            "report": None,
            "risk_score": 0,
            "risk_factors": [],
        }

        try:
            self._collect_whois_data(domain, domain_data)
            self._collect_dns_data(domain, domain_data)
            self._collect_category_data(domain, domain_data)
            self._collect_report_data(domain, domain_data)

        except DomainIQError as e:
            print(f"    Error analyzing {domain}: {e}")
            domain_data["error"] = str(e)

        return domain_data

    def _collect_whois_data(self, domain: str, domain_data: dict[str, Any]) -> None:
        """Collect and analyze WHOIS data for a domain."""
        whois_result = self.client.whois_lookup(domain=domain, full=True)
        if not whois_result:
            return

        domain_data["whois"] = {
            "registrar": whois_result.registrar,
            "creation_date": (
                whois_result.creation_date.isoformat()
                if whois_result.creation_date
                else None
            ),
            "expiration_date": (
                whois_result.expiration_date.isoformat()
                if whois_result.expiration_date
                else None
            ),
            "registrant_name": whois_result.registrant_name,
            "registrant_organization": whois_result.registrant_organization,
            "registrant_email": whois_result.registrant_email,
            "nameservers": whois_result.nameservers,
        }

        if whois_result.creation_date:
            days_old = (
                datetime.now(tz=UTC) - whois_result.creation_date.replace(tzinfo=UTC)
            ).days
            if days_old < NEW_DOMAIN_THRESHOLD_DAYS:
                domain_data["risk_factors"].append(
                    f"Newly registered ({days_old} days old)"
                )
                domain_data["risk_score"] += 3

        if (
            whois_result.registrant_name
            and "privacy" in whois_result.registrant_name.lower()
        ):
            domain_data["risk_factors"].append("Privacy protection enabled")
            domain_data["risk_score"] += 1

    def _collect_dns_data(self, domain: str, domain_data: dict[str, Any]) -> None:
        """Collect DNS data for a domain."""
        dns_result = self.client.dns_lookup(domain)
        if not dns_result:
            return

        domain_data["dns"] = {
            "record_count": len(dns_result.records),
            "records": [
                {
                    "type": record.type,
                    "value": record.value,
                    "ttl": record.ttl,
                }
                for record in dns_result.records
            ],
        }

    def _collect_category_data(self, domain: str, domain_data: dict[str, Any]) -> None:
        """Collect and analyze category data for a domain."""
        categories = self.client.domain_categorize([domain])
        if not categories or not categories[0].categories:
            return

        domain_data["categories"] = categories[0].categories

        for cat in categories[0].categories:
            if any(risk_cat in cat.lower() for risk_cat in _HIGH_RISK_CATEGORIES):
                domain_data["risk_factors"].append(f"High-risk category: {cat}")
                domain_data["risk_score"] += 5

    def _collect_report_data(self, domain: str, domain_data: dict[str, Any]) -> None:
        """Collect domain report data."""
        report = self.client.domain_report(domain)
        if not report:
            return

        domain_data["report"] = {
            "risk_score": report.risk_score,
            "related_domains": (
                report.related_domains[:10] if report.related_domains else []
            ),
        }
        if report.risk_score:
            domain_data["risk_score"] += report.risk_score

    def _check_risk_indicators(
        self,
        domain_analysis: dict[str, Any],
        risk_indicators: dict[str, list[Any]],
    ) -> None:
        """Check domain analysis for various risk indicators."""
        domain = domain_analysis["domain"]

        # Check for newly registered domains
        if any(
            "Newly registered" in factor for factor in domain_analysis["risk_factors"]
        ):
            risk_indicators["newly_registered"].append(domain)

        # Check for privacy protection
        if any(
            "privacy" in factor.lower() for factor in domain_analysis["risk_factors"]
        ):
            risk_indicators["privacy_protected"].append(domain)

        # Check for suspicious registrars
        if domain_analysis["whois"] and domain_analysis["whois"]["registrar"]:
            registrar = domain_analysis["whois"]["registrar"].lower()
            if any(susp in registrar for susp in _SUSPICIOUS_REGISTRARS):
                risk_indicators["suspicious_registrars"].append(
                    {
                        "domain": domain,
                        "registrar": domain_analysis["whois"]["registrar"],
                    }
                )

        # Check for related domains
        if domain_analysis["report"] and domain_analysis["report"]["related_domains"]:
            risk_indicators["related_domains"].extend(
                [
                    {"parent": domain, "related": related}
                    for related in domain_analysis["report"]["related_domains"][:5]
                ]
            )

        # Check for high-risk categories
        if any(
            "High-risk category" in factor for factor in domain_analysis["risk_factors"]
        ):
            risk_indicators["high_risk_categories"].append(domain)

    def investigate_email_infrastructure(self, email: str) -> dict[str, Any]:
        """Investigate the infrastructure associated with an email address.

        Args:
            email: Email address to investigate

        Returns:
            Infrastructure analysis report
        """
        print(f"Investigating email infrastructure: {email}")

        investigation: dict[str, Any] = {
            "email": email,
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "email_report": None,
            "reverse_search": None,
            "domain_analysis": None,
        }

        try:
            email_report = self.client.email_report(email)
            if email_report:
                investigation["email_report"] = email_report

            reverse_results = self.client.reverse_search("email", email)
            if reverse_results:
                investigation["reverse_search"] = reverse_results

            if "@" in email:
                domain = email.split("@")[1]
                investigation["domain_analysis"] = self._analyze_single_domain(domain)

        except DomainIQError as e:
            print(f"Error investigating email {email}: {e}")
            investigation["error"] = str(e)

        return investigation

    def monitor_typosquatting(self, target_domain: str) -> dict[str, Any]:
        """Monitor for potential typosquatting domains.

        Args:
            target_domain: Domain to monitor for typosquats

        Returns:
            Typosquatting analysis report
        """
        print(f"Monitoring typosquatting for: {target_domain}")

        variations = self._generate_typosquat_variations(target_domain)

        analysis: dict[str, Any] = {
            "target_domain": target_domain,
            "variations_checked": len(variations),
            "registered_variations": [],
            "suspicious_variations": [],
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }

        for variation in variations:
            try:
                whois_result = self.client.whois_lookup(domain=variation)
                if whois_result:
                    analysis["registered_variations"].append(
                        {
                            "domain": variation,
                            "registrar": whois_result.registrar,
                            "creation_date": (
                                whois_result.creation_date.isoformat()
                                if whois_result.creation_date
                                else None
                            ),
                            "registrant": whois_result.registrant_name,
                        }
                    )

                    if whois_result.creation_date:
                        days_old = (
                            datetime.now(tz=UTC)
                            - whois_result.creation_date.replace(tzinfo=UTC)
                        ).days
                        if days_old < SUSPICIOUS_DOMAIN_THRESHOLD_DAYS:
                            analysis["suspicious_variations"].append(variation)

            except DomainIQError:
                pass

        return analysis

    def _generate_typosquat_variations(self, domain: str) -> list[str]:
        """Generate basic typosquatting variations of a domain."""
        if "." not in domain:
            return []

        base_domain, tld = domain.rsplit(".", 1)
        variations: list[str] = []

        # Character substitution variations
        common_substitutions = {
            "a": ["e", "o"],
            "e": ["a", "i"],
            "i": ["e", "o"],
            "o": ["a", "i", "u"],
            "m": ["n"],
            "n": ["m"],
            "w": ["vv"],
            "c": ["g"],
            "g": ["c"],
        }

        for i, char in enumerate(base_domain):
            if char in common_substitutions:
                for substitute in common_substitutions[char]:
                    variation = base_domain[:i] + substitute + base_domain[i + 1 :]
                    variations.append(f"{variation}.{tld}")

        # Character omission variations
        for i in range(len(base_domain)):
            if len(base_domain) > MIN_DOMAIN_LENGTH_FOR_VARIATIONS:
                variation = base_domain[:i] + base_domain[i + 1 :]
                variations.append(f"{variation}.{tld}")

        # Character addition variations
        common_additions = ["a", "e", "i", "o", "u", "s"]
        for i in range(len(base_domain) + 1):
            for add_char in common_additions:
                variation = base_domain[:i] + add_char + base_domain[i:]
                variations.append(f"{variation}.{tld}")
                if len(variations) > MAX_TYPOSQUAT_VARIATIONS:
                    break
            if len(variations) > MAX_TYPOSQUAT_VARIATIONS:
                break

        return list(set(variations))  # Remove duplicates


def _run_suspicious_domain_analysis(
    researcher: SecurityResearcher,
) -> dict[str, Any]:
    """Run Example 1: Analyze suspicious domains."""
    print("\n1. Analyzing Suspicious Domains")
    print("-" * 40)
    print("Note: Using example domains for demonstration")
    analysis = researcher.analyze_suspicious_domains(["example.com"])

    print(f"Analysis completed for {analysis['domains_analyzed']} domains")
    print("Risk indicators found:")
    for indicator_type, items in analysis["risk_indicators"].items():
        if items:
            print(f"  {indicator_type}: {len(items)}")

    return analysis


def _run_email_investigation(
    researcher: SecurityResearcher,
) -> dict[str, Any]:
    """Run Example 2: Email infrastructure investigation."""
    print("\n2. Email Infrastructure Investigation")
    print("-" * 40)
    investigation = researcher.investigate_email_infrastructure("admin@example.com")
    print(f"Investigation completed for: {investigation['email']}")
    if investigation.get("domain_analysis"):
        risk = investigation["domain_analysis"]["risk_score"]
        print(f"Risk score for email domain: {risk}")

    return investigation


def _run_typosquat_monitoring(
    researcher: SecurityResearcher,
) -> dict[str, Any]:
    """Run Example 3: Typosquatting monitoring."""
    print("\n3. Typosquatting Monitoring")
    print("-" * 40)
    typosquat_analysis = researcher.monitor_typosquatting("example.com")
    checked = typosquat_analysis["variations_checked"]
    print(f"Checked {checked} variations")
    registered = typosquat_analysis["registered_variations"]
    print(f"Found {len(registered)} registered variations")
    if typosquat_analysis["suspicious_variations"]:
        suspicious = typosquat_analysis["suspicious_variations"]
        print(f"Suspicious variations: {len(suspicious)}")

    return typosquat_analysis


def _run_bulk_analysis(client: DomainIQClient) -> None:
    """Run Example 4: Bulk domain analysis."""
    print("\n4. Bulk Domain Analysis")
    print("-" * 40)
    ioc_domains = ["example.com", "google.com"]

    for domain in ioc_domains:
        print(f"Analyzing IOC domain: {domain}")
        try:
            whois_data = client.whois_lookup(domain=domain)
            categories = client.domain_categorize([domain])
            dns_data = client.dns_lookup(domain)

            registrar = whois_data.registrar if whois_data else "Unknown"
            print(f"  Registrar: {registrar}")
            if categories and categories[0].categories:
                cats = categories[0].categories
                print(f"  Categories: {cats}")
            else:
                print("  Categories: None")
            dns_count = len(dns_data.records) if dns_data else 0
            print(f"  DNS records: {dns_count}")
        except DomainIQError as e:
            print(f"  Error: {e}")


def _run_export(
    analysis: dict[str, Any],
    investigation: dict[str, Any],
    typosquat_analysis: dict[str, Any],
) -> None:
    """Run Example 5: Export results."""
    print("\n5. Exporting Results")
    print("-" * 40)

    output_file = Path("security_analysis_results.json")
    with output_file.open("w") as f:
        json.dump(
            {
                "suspicious_domain_analysis": analysis,
                "email_investigation": investigation,
                "typosquatting_analysis": typosquat_analysis,
            },
            f,
            indent=2,
            default=str,
        )

    print(f"Results exported to: {output_file}")


def main() -> int:
    """Main security research examples."""
    print("DomainIQ Security Research Examples")
    print("=" * 50)

    try:
        with DomainIQClient() as client:
            researcher = SecurityResearcher(client)

            analysis = _run_suspicious_domain_analysis(researcher)
            investigation = _run_email_investigation(researcher)
            typosquat_analysis = _run_typosquat_monitoring(researcher)
            _run_bulk_analysis(client)
            _run_export(analysis, investigation, typosquat_analysis)

            print("\n" + "=" * 50)
            print("Security research examples completed!")

    except DomainIQError as e:
        print(f"DomainIQ Error: {e}")
        return 1
    except (OSError, ValueError, RuntimeError) as e:
        print(f"Unexpected error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
