"""
Asynchronous usage examples for the DomainIQ library.

This script demonstrates how to use the AsyncDomainIQClient for improved
performance with concurrent operations.
"""

import asyncio
import sys
import time
from pathlib import Path

# Add the parent directory to Python path for local development
sys.path.insert(0, str(Path(__file__).parent.parent))

from domainiq import DomainIQError
from domainiq.async_client import AsyncDomainIQClient
from domainiq.config import Config
from domainiq.models import DNSRecordType


async def basic_async_examples() -> None:
    """Basic async operations examples."""
    print("Basic Async Operations")
    print("-" * 30)

    async with AsyncDomainIQClient() as client:
        # Single async WHOIS lookup
        whois_result = await client.whois_lookup(domain="example.com")
        if whois_result:
            print(f"WHOIS for example.com - Registrar: {whois_result.registrar}")

        # Single async DNS lookup
        dns_result = await client.dns_lookup("example.com", [DNSRecordType.A])
        if dns_result:
            print(f"DNS A records: {len(dns_result.records)}")

        # Domain report
        report = await client.domain_report("example.com")
        if report:
            print(f"Domain report risk score: {report.risk_score}")


async def concurrent_operations_examples() -> None:
    """Demonstrate concurrent operations for better performance."""
    print("\nConcurrent Operations Examples")
    print("-" * 30)

    domains = [
        "example.com",
        "google.com",
        "github.com",
        "stackoverflow.com",
        "python.org",
        "microsoft.com",
        "apple.com",
        "amazon.com",
    ]

    async with AsyncDomainIQClient() as client:
        # Example 1: Concurrent WHOIS lookups
        print(f"Performing concurrent WHOIS lookups for {len(domains)} domains...")
        start_time = time.time()

        whois_results = await client.concurrent_whois_lookup(
            targets=domains,
            max_concurrent=5,  # Limit concurrent requests
        )

        elapsed = time.time() - start_time
        successful_lookups = sum(1 for result in whois_results if result is not None)

        msg = (
            f"Completed {successful_lookups}/{len(domains)} "
            f"WHOIS lookups in {elapsed:.2f}s"
        )
        print(msg)

        # Show some results
        for i, result in enumerate(whois_results[:3]):
            if result:
                print(f"  {domains[i]}: {result.registrar}")

        # Example 2: Concurrent DNS lookups
        print(f"\nPerforming concurrent DNS lookups for {len(domains)} domains...")
        start_time = time.time()

        dns_results = await client.concurrent_dns_lookup(
            domains=domains,
            record_types=[DNSRecordType.A, DNSRecordType.MX],
            max_concurrent=3,
        )

        elapsed = time.time() - start_time
        successful_dns = sum(1 for result in dns_results if result is not None)

        msg_dns = (
            f"Completed {successful_dns}/{len(domains)} DNS lookups in {elapsed:.2f}s"
        )
        print(msg_dns)

        # Show some results
        for dns_result in dns_results[:3]:
            if dns_result:
                print(f"  {dns_result.domain}: {len(dns_result.records)} records")


async def advanced_async_patterns() -> None:
    """Advanced async patterns and error handling."""
    print("\nAdvanced Async Patterns")
    print("-" * 30)

    async with AsyncDomainIQClient() as client:
        # Example 1: Gather multiple different operations
        print("Running multiple different operations concurrently...")

        tasks = [
            client.whois_lookup(domain="example.com"),
            client.dns_lookup("example.com"),
            client.domain_categorize(["example.com"]),
            client.domain_report("example.com"),
        ]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            print("Results:")
            for idx, result in enumerate(results):
                if isinstance(result, (DomainIQError, ValueError, OSError)):
                    print(f"  Task {idx + 1}: Failed - {result}")
                else:
                    print(f"  Task {idx + 1}: Success - {type(result).__name__}")

        except (DomainIQError, ValueError, OSError) as e:
            print(f"Error in gather: {e}")

        # Example 2: Bulk operations with async
        print("\nBulk DNS lookup with async client...")
        bulk_domains = ["example.com", "google.com", "github.com"]
        bulk_results = await client.bulk_dns(bulk_domains)
        print(f"Bulk DNS results: {len(bulk_results)} records")

        # Example 3: Monitor operations
        print("\nMonitor operations...")
        try:
            monitors = await client.monitor_list()
            print(f"Found {len(monitors)} monitors")
        except DomainIQError as e:
            print(f"Monitor access failed: {e}")


async def error_handling_examples() -> None:
    """Demonstrate error handling in async operations."""
    print("\nError Handling Examples")
    print("-" * 30)

    # Example with invalid domain
    async with AsyncDomainIQClient() as client:
        try:
            # This might fail
            await client.whois_lookup(domain="invalid..domain")
        except DomainIQError as e:
            print(f"Expected error caught: {type(e).__name__}: {e}")

        # Example with timeout handling
        try:
            # Create client with very short timeout
            config = Config(api_key=client.config.api_key, timeout=0.1)
            async with AsyncDomainIQClient(config) as timeout_client:
                await timeout_client.whois_lookup(domain="example.com")
        except DomainIQError as e:
            print(f"Timeout error: {type(e).__name__}: {e}")


async def performance_comparison() -> None:
    """Compare sync vs async performance."""
    print("\nPerformance Comparison")
    print("-" * 30)

    domains = ["example.com", "google.com", "github.com", "python.org"]

    # Async version
    print("Running async version...")
    start_time = time.time()

    async with AsyncDomainIQClient() as client:
        async_results = await client.concurrent_whois_lookup(
            targets=domains,
            max_concurrent=4,
        )

    async_time = time.time() - start_time
    async_successful = sum(1 for r in async_results if r is not None)

    print(f"Async: {async_successful}/{len(domains)} completed in {async_time:.2f}s")

    # For comparison info (sync version would be much slower)
    estimated_sync_time = len(domains) * 2.0  # Estimate 2s per domain
    print(f"Estimated sync time: ~{estimated_sync_time:.1f}s")
    improvement = estimated_sync_time / async_time
    print(f"Async performance improvement: ~{improvement:.1f}x faster")


async def main() -> int:
    """Main async function."""
    print("DomainIQ Async Client - Usage Examples")
    print("=" * 50)

    try:
        await basic_async_examples()
        await concurrent_operations_examples()
        await advanced_async_patterns()
        await error_handling_examples()
        await performance_comparison()

        print("\n" + "=" * 50)
        print("Async usage examples completed successfully!")

    except DomainIQError as e:
        print(f"DomainIQ Error: {e}")
        return 1
    except (OSError, ValueError, RuntimeError) as e:
        print(f"Unexpected error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    import importlib.util

    if importlib.util.find_spec("aiohttp") is None:
        print("Error: aiohttp is required for async examples")
        print("Install it with: pip install aiohttp")
        sys.exit(1)

    result = asyncio.run(main())
    sys.exit(result)
