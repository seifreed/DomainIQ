# Copyright (C) 2024 seifreed
# This file is part of domainIQ.py - https://github.com/seifreed/DomainIQ
# See the file 'LICENSE.md' for copying permission.

import os
import requests
from pathlib import Path
import argparse
import json

class DomainIQAPI:
    def __init__(self):
        self.api_key = self.load_api_key()
        self.base_url = 'https://www.domainiq.com/api'

    def load_api_key(self):
        config_path = Path.home() / '.domainIQ'
        if config_path.exists():
            with open(config_path, 'r') as file:
                api_key = file.read().strip()
        else:
            api_key = input("Enter your DomainIQ API key: ")
            with open(config_path, 'w') as file:
                file.write(api_key)
        return api_key

    def make_request(self, params: dict):
        params['key'] = self.api_key
        params['output_mode'] = 'json'  # Ensure the response is in JSON format
        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()  # Raise an HTTPError for bad responses
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"An HTTP error occurred: {e}")
            if e.response is not None:
                print("Response content:", e.response.text)  # Print the response content for more details
            return None
        except requests.exceptions.RequestException as e:
            print(f"A request error occurred: {e}")
            return None
        except ValueError as e:
            print(f"Error decoding JSON: {e}")
            return None

    def make_csv_request(self, params: dict):
        params['key'] = self.api_key
        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()  # Raise an HTTPError for bad responses
            return response.text  # Return the raw CSV content
        except requests.exceptions.HTTPError as e:
            print(f"An HTTP error occurred: {e}")
            if e.response is not None:
                print("Response content:", e.response.text)  # Print the response content for more details
            return None
        except requests.exceptions.RequestException as e:
            print(f"A request error occurred: {e}")
            return None

    def whois_lookup(self, domain: str, ip: str = None, full: bool = False, current_only: bool = False):
        params = {'service': 'whois'}
        if domain:
            params['domain'] = domain
        if ip:
            params['ip'] = ip
        if full:
            params['full'] = 1
        if current_only:
            params['current_only'] = 1
        return self.make_request(params)

    def dns_lookup(self, q: str, types: list = None):
        params = {'service': 'dns', 'q': q}
        if types:
            params['types'] = ','.join(types)
        return self.make_request(params)

    def domain_categorize(self, domains: list):
        params = {'service': 'categorize', 'domains': '>>'.join(domains)}
        return self.make_request(params)

    def domain_snapshot(self, domain: str, full: bool = False, no_cache: bool = False, raw: bool = False, width: int = 250, height: int = 125):
        params = {'service': 'snapshot', 'domain': domain}
        if full:
            params['full'] = 1
        if no_cache:
            params['no_cache'] = 1
        if raw:
            params['raw'] = 1
        if width:
            params['width'] = width
        if height:
            params['height'] = height
        return self.make_request(params)

    def domain_snapshot_history(self, domain: str, width: int = 250, height: int = 125, limit: int = 10):
        params = {'service': 'snapshot_history', 'domain': domain, 'width': width, 'height': height, 'limit': limit}
        return self.make_request(params)

    def domain_report(self, domain: str):
        params = {'service': 'domain_report', 'domain': domain}
        return self.make_request(params)

    def name_report(self, name: str):
        params = {'service': 'name_report', 'name': name}
        return self.make_request(params)

    def organization_report(self, organization: str):
        params = {'service': 'organization_report', 'organization': organization}
        return self.make_request(params)

    def email_report(self, email: str):
        params = {'service': 'email_report', 'email': email}
        return self.make_request(params)

    def ip_report(self, ip: str):
        params = {'service': 'ip_report', 'ip': ip}
        return self.make_request(params)

    def domain_search(self, keywords: list, conditions: list = None, match: str = 'any', **kwargs):
        params = {'service': 'domain_search', 'match': match}
        for idx, keyword in enumerate(keywords):
            params[f'keyword[{idx}]'] = keyword
        if conditions:
            for idx, condition in enumerate(conditions):
                params[f'condition[{idx}]'] = condition
        params.update(kwargs)
        return self.make_request(params)

    def reverse_search(self, search_type: str, search: str, match: str = 'contains'):
        params = {'service': 'reverse_search', 'type': search_type, 'search': search, 'match': match}
        return self.make_request(params)

    def reverse_dns(self, domain: str):
        params = {'service': 'reverse_dns', 'domain': domain}
        return self.make_request(params)

    def reverse_ip(self, search_type: str, data: str):
        params = {'service': 'reverse_ip', 'type': search_type, 'data': data}
        return self.make_request(params)

    def reverse_mx(self, search_type: str, data: str, recursive: bool = False):
        params = {'service': 'reverse_mx', 'type': search_type, 'data': data}
        if recursive:
            params['recursive'] = '1'
        return self.make_request(params)

    def bulk_dns(self, domains: list):
        domain_str = '>>'.join(domains)
        params = {'service': 'bulk_dns', 'domains': domain_str}
        return self.make_csv_request(params)

    def bulk_whois(self, lookup_type: str, items: list):
        item_str = '>>'.join(items)
        params = {'service': 'bulk_whois', 'type': lookup_type, 'domains': item_str}
        return self.make_csv_request(params)

    def bulk_whois_ip(self, domains: list):
        domain_str = '>>'.join(domains)
        params = {'service': 'bulk_whois_ip', 'domains': domain_str}
        return self.make_csv_request(params)

    def csv_to_json(self, csv_content: str):
        import csv
        from io import StringIO

        f = StringIO(csv_content)
        reader = csv.DictReader(f, delimiter=',')
        return list(reader)

    # Monitoring functions
    def monitor_list(self):
        params = {'service': 'monitor', 'action': 'list'}
        return self.make_request(params)

    def monitor_report_items(self, report_id: int):
        params = {'service': 'monitor', 'action': 'report_items', 'report': report_id}
        return self.make_request(params)

    def monitor_report_summary(self, report_id: int, item_id: int = None, days_range: int = None):
        params = {'service': 'monitor', 'action': 'report_summary', 'report': report_id}
        if item_id is not None:
            params['item'] = item_id
        if days_range is not None:
            params['range'] = days_range
        return self.make_request(params)

    def monitor_report_changes(self, report_id: int, change_id: int):
        params = {'service': 'monitor', 'action': 'report_changes', 'report': report_id, 'change': change_id}
        return self.make_request(params)

    def create_monitor_report(self, report_type: str, name: str, email_alert: bool = True):
        params = {
            'service': 'monitor',
            'action': 'report_create',
            'type': report_type,
            'name': name,
            'email_alert': '1' if email_alert else '0'
        }
        return self.make_request(params)

    def add_monitor_item(self, report_id: int, item_type: str, items: list, **kwargs):
        item_str = '>>'.join(items)
        params = {
            'service': 'monitor',
            'action': 'report_item_add',
            'report_id': report_id,
            'type': item_type,
            'items': item_str
        }
        params.update(kwargs)
        return self.make_request(params)

    def enable_typos(self, report_id: int, item_id: int, strength: int = 41):
        params = {
            'service': 'monitor',
            'action': 'enable_typos',
            'report_id': report_id,
            'item_id': item_id,
            'strength': strength
        }
        return self.make_request(params)

    def disable_typos(self, report_id: int, item_id: int):
        params = {
            'service': 'monitor',
            'action': 'disable_typos',
            'report_id': report_id,
            'item_id': item_id
        }
        return self.make_request(params)

    def modify_typo_strength(self, report_id: int, item_id: int, strength: int):
        params = {
            'service': 'monitor',
            'action': 'modify_typo_strength',
            'report_id': report_id,
            'item_id': item_id,
            'strength': strength
        }
        return self.make_request(params)

    def delete_monitor_item(self, item_id: int):
        params = {
            'service': 'monitor',
            'action': 'report_item_delete',
            'item_id': item_id
        }
        return self.make_request(params)

    def delete_monitor_report(self, report_id: int):
        params = {
            'service': 'monitor',
            'action': 'report_delete',
            'report_id': report_id
        }
        return self.make_request(params)

def main():
    parser = argparse.ArgumentParser(description="DomainIQ API Script")
    parser.add_argument('--whois_lookup', type=str, help='Get WHOIS data for the specified domain or IP address')
    parser.add_argument('--dns_lookup', type=str, help="Get DNS records for the specified domain or hostname")
    parser.add_argument('--types', type=str, help="Specify the types of DNS records to retrieve, comma-separated")
    parser.add_argument('--domain_categorize', nargs='+', help="Categorize the specified domain names. Usage: --domain_categorize domain1 domain2 ...")
    parser.add_argument('--domain_snapshot', type=str, help="Get a snapshot of the specified domain")
    parser.add_argument('--domain_snapshot_history', type=str, help="Get the snapshot history of the specified domain")
    parser.add_argument('--snapshot_limit', type=int, help="Limit the number of results in snapshot history")
    parser.add_argument('--full', action='store_true', help="Retrieve full WHOIS record or full domain snapshot")
    parser.add_argument('--current_only', action='store_true', help="Use only the current WHOIS record")
    parser.add_argument('--no_cache', action='store_true', help="Do not use a recently-cached snapshot")
    parser.add_argument('--raw', action='store_true', help="Return raw PNG/JPEG image directly")
    parser.add_argument('--width', type=int, help="Specify the width of the snapshot thumbnail")
    parser.add_argument('--height', type=int, help="Specify the height of the snapshot thumbnail")

    # Other arguments remain unchanged...
    parser.add_argument('--domain_report', type=str, help='Get domain report for the specified domain')
    parser.add_argument('--name_report', type=str, help="Get registrant name report for the specified name")
    parser.add_argument('--organization_report', type=str, help="Get registrant organization report for the specified organization")
    parser.add_argument('--email_report', type=str, help="Get registrant email report for the specified email")
    parser.add_argument('--ip_report', type=str, help="Get IP address summary report for the specified IP address")
    parser.add_argument('--domain_search', nargs='+', help="Perform a search for domain names matching one or more keywords. Usage: --domain_search keyword1 [keyword2 ...]")
    parser.add_argument('--conditions', nargs='+', help="Specify the conditions for each keyword in domain search. Usage: --conditions condition1 [condition2 ...]")
    parser.add_argument('--match', type=str, choices=['any', 'all'], default='any', help="Specify the match type for multiple keywords in domain search. Default is 'any'")
    parser.add_argument('--count_only', action='store_true', help="Get only the count of matched domains in domain search")
    parser.add_argument('--exclude_dashed', action='store_true', help="Exclude domains with dashes (-) in domain search")
    parser.add_argument('--exclude_numbers', action='store_true', help="Exclude domains with numbers in domain search")
    parser.add_argument('--exclude_idn', action='store_true', help="Exclude IDN domains in domain search")
    parser.add_argument('--min_length', type=int, help="Minimum length of matched domains in domain search")
    parser.add_argument('--max_length', type=int, help="Maximum length of matched domains in domain search")
    parser.add_argument('--min_create_date', type=str, help="Minimum WHOIS creation date in domain search (YYYY-MM-DD)")
    parser.add_argument('--max_create_date', type=str, help="Maximum WHOIS creation date in domain search (YYYY-MM-DD)")
    parser.add_argument('--search_limit', type=int, help="Limit the number of results in domain search")
    parser.add_argument('--reverse_search_type', type=str, choices=['email', 'name', 'org'], help="Specify the type for reverse search")
    parser.add_argument('--reverse_search', type=str, help="Specify the search string for reverse search")
    parser.add_argument('--reverse_match', type=str, choices=['contains', 'begins', 'ends'], default='contains', help="Specify the match type for reverse search")
    parser.add_argument('--reverse_dns', type=str, help="Perform a reverse DNS search for the specified domain")
    parser.add_argument('--reverse_ip_type', type=str, choices=['ip', 'subnet', 'block', 'range', 'domain'], help="Specify the type for reverse IP search")
    parser.add_argument('--reverse_ip_data', type=str, help="Specify the data for reverse IP search")
    parser.add_argument('--reverse_mx_type', type=str, choices=['hostname', 'ip', 'subnet', 'block', 'range'], help="Specify the type for reverse MX search")
    parser.add_argument('--reverse_mx_data', type=str, help="Specify the data for reverse MX search")
    parser.add_argument('--recursive', action='store_true', help="Specify to recursively check MX hostnames to discover more domains")
    parser.add_argument('--bulk_dns', nargs='+', help="Perform a bulk DNS lookup for the specified domains. Usage: --bulk_dns domain1 domain2 ...")
    parser.add_argument('--bulk_whois', nargs='+', help="Perform a bulk WHOIS lookup for the specified domains or IP addresses. Usage: --bulk_whois domain1 domain2 ...")
    parser.add_argument('--bulk_whois_type', type=str, choices=['live', 'registry', 'cached'], default='live', help="Specify the type of WHOIS lookup. Default is 'live'")
    parser.add_argument('--bulk_whois_ip', nargs='+', help="Perform a bulk domain IP WHOIS lookup for the specified domains. Usage: --bulk_whois_ip domain1 domain2 ...")

    # Monitoring arguments
    parser.add_argument('--monitor_list', action='store_true', help="Get a list of active monitors")
    parser.add_argument('--monitor_report_items', type=int, help="Get a list of items in a monitor. Specify the report ID")
    parser.add_argument('--monitor_report_summary', type=int, help="Get a summary of daily changes detected for a given report item. Specify the report ID")
    parser.add_argument('--monitor_item', type=int, help="Specify the item ID for monitoring summary")
    parser.add_argument('--monitor_range', type=int, help="Specify the range of days for monitoring summary")
    parser.add_argument('--monitor_report_changes', type=int, help="Get a list of items changed in a daily change report. Specify the report ID")
    parser.add_argument('--monitor_change', type=int, help="Specify the change ID for monitoring changes")

    # Arguments for monitoring control
    parser.add_argument('--create_monitor_report', nargs=2, metavar=('TYPE', 'NAME'), help="Create a new monitor report. Specify the type and name of the report")
    parser.add_argument('--email_alert', action='store_true', help="Enable email alerts for the monitor report. Used with --create_monitor_report")
    parser.add_argument('--add_monitor_item', nargs=3, metavar=('REPORT_ID', 'ITEM_TYPE', 'ITEMS'), help="Add items to a monitor report. Specify the report ID, item type, and items (comma-separated)")
    parser.add_argument('--enable_typos', nargs=2, metavar=('REPORT_ID', 'ITEM_ID'), help="Enable typo monitoring for a keyword monitor item. Specify the report ID and item ID")
    parser.add_argument('--disable_typos', nargs=2, metavar=('REPORT_ID', 'ITEM_ID'), help="Disable typo monitoring for a keyword monitor item. Specify the report ID and item ID")
    parser.add_argument('--modify_typo_strength', nargs=3, metavar=('REPORT_ID', 'ITEM_ID', 'STRENGTH'), help="Change the typo monitoring strength for a keyword monitor item. Specify the report ID, item ID, and strength (5-41)")
    parser.add_argument('--delete_monitor_item', type=int, help="Remove an individual monitoring item from a monitor report. Specify the item ID")
    parser.add_argument('--delete_monitor_report', type=int, help="Remove an entire monitor report. Specify the report ID")

    args = parser.parse_args()
    
    domainiq = DomainIQAPI()
    
    if args.whois_lookup:
        report = domainiq.whois_lookup(args.whois_lookup, full=args.full, current_only=args.current_only)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.dns_lookup:
        report = domainiq.dns_lookup(args.dns_lookup, types=args.types.split(',') if args.types else None)
        if report:
            print(json.dumps(report, indent=4))

    if args.domain_categorize:
        report = domainiq.domain_categorize(args.domain_categorize)
        if report:
            print(json.dumps(report, indent=4))

    if args.domain_snapshot:
        report = domainiq.domain_snapshot(args.domain_snapshot, full=args.full, no_cache=args.no_cache, raw=args.raw, width=args.width, height=args.height)
        if report:
            print(json.dumps(report, indent=4))

    if args.domain_snapshot_history:
        report = domainiq.domain_snapshot_history(args.domain_snapshot_history, width=args.width, height=args.height, limit=args.snapshot_limit)
        if report:
            print(json.dumps(report, indent=4))

    if args.domain_report:
        report = domainiq.domain_report(args.domain_report)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.name_report:
        report = domainiq.name_report(args.name_report)
        if report:
            print(json.dumps(report, indent=4))

    if args.organization_report:
        report = domainiq.organization_report(args.organization_report)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.email_report:
        report = domainiq.email_report(args.email_report)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.ip_report:
        report = domainiq.ip_report(args.ip_report)
        if report:
            print(json.dumps(report, indent=4))

    if args.domain_search:
        additional_params = {
            'count_only': 1 if args.count_only else None,
            'exclude_dashed': args.exclude_dashed,
            'exclude_numbers': args.exclude_numbers,
            'exclude_idn': args.exclude_idn,
            'min_length': args.min_length,
            'max_length': args.max_length,
            'min_create_date': args.min_create_date,
            'max_create_date': args.max_create_date,
            'limit': args.search_limit
        }
        # Remove None values
        additional_params = {k: v for k, v in additional_params.items() if v is not None}
        
        report = domainiq.domain_search(args.domain_search, args.conditions, args.match, **additional_params)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.reverse_search_type and args.reverse_search:
        report = domainiq.reverse_search(args.reverse_search_type, args.reverse_search, args.reverse_match)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.reverse_dns:
        report = domainiq.reverse_dns(args.reverse_dns)
        if report:
            print(json.dumps(report, indent=4))
    
    if args.reverse_ip_type and args.reverse_ip_data:
        report = domainiq.reverse_ip(args.reverse_ip_type, args.reverse_ip_data)
        if report:
            print(json.dumps(report, indent=4))

    if args.reverse_mx_type and args.reverse_mx_data:
        report = domainiq.reverse_mx(args.reverse_mx_type, args.reverse_mx_data, args.recursive)
        if report:
            print(json.dumps(report, indent=4))

    if args.bulk_dns:
        report = domainiq.bulk_dns(args.bulk_dns)
        if report:
            json_report = domainiq.csv_to_json(report)
            print(json.dumps(json_report, indent=4))  # Print the CSV content as JSON

    if args.bulk_whois:
        report = domainiq.bulk_whois(args.bulk_whois_type, args.bulk_whois)
        if report:
            json_report = domainiq.csv_to_json(report)
            print(json.dumps(json_report, indent=4))  # Print the CSV content as JSON

    if args.bulk_whois_ip:
        report = domainiq.bulk_whois_ip(args.bulk_whois_ip)
        if report:
            json_report = domainiq.csv_to_json(report)
            print(json.dumps(json_report, indent=4))  # Print the CSV content as JSON

    if args.monitor_list:
        report = domainiq.monitor_list()
        if report:
            print(json.dumps(report, indent=4))

    if args.monitor_report_items:
        report = domainiq.monitor_report_items(args.monitor_report_items)
        if report:
            print(json.dumps(report, indent=4))

    if args.monitor_report_summary:
        report = domainiq.monitor_report_summary(args.monitor_report_summary, args.monitor_item, args.monitor_range)
        if report:
            print(json.dumps(report, indent=4))

    if args.monitor_report_changes and args.monitor_change:
        report = domainiq.monitor_report_changes(args.monitor_report_changes, args.monitor_change)
        if report:
            print(json.dumps(report, indent=4))

    if args.create_monitor_report:
        report_type, name = args.create_monitor_report
        report = domainiq.create_monitor_report(report_type, name, args.email_alert)
        if report:
            print(json.dumps(report, indent=4))

    if args.add_monitor_item:
        report_id, item_type, items = args.add_monitor_item
        items_list = items.split(',')
        report = domainiq.add_monitor_item(report_id, item_type, items_list)
        if report:
            print(json.dumps(report, indent=4))

    if args.enable_typos:
        report_id, item_id = map(int, args.enable_typos)
        report = domainiq.enable_typos(report_id, item_id)
        if report:
            print(json.dumps(report, indent=4))

    if args.disable_typos:
        report_id, item_id = map(int, args.disable_typos)
        report = domainiq.disable_typos(report_id, item_id)
        if report:
            print(json.dumps(report, indent=4))

    if args.modify_typo_strength:
        report_id, item_id, strength = map(int, args.modify_typo_strength)
        report = domainiq.modify_typo_strength(report_id, item_id, strength)
        if report:
            print(json.dumps(report, indent=4))

    if args.delete_monitor_item:
        report = domainiq.delete_monitor_item(args.delete_monitor_item)
        if report:
            print(json.dumps(report, indent=4))

    if args.delete_monitor_report:
        report = domainiq.delete_monitor_report(args.delete_monitor_report)
        if report:
            print(json.dumps(report, indent=4))

if __name__ == "__main__":
    main()
