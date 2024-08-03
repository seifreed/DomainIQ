# DomainIQ API Script

This project provides a Python script to interact with the DomainIQ API. You can perform various queries related to domains, WHOIS, DNS, and more.

## Requirements

- Python 3.12 or higher
- `requests` library

You can install the `requests` library with the following command:
```
pip install requests
```

## Configuration

To use this script, you need a DomainIQ API key. The first time you run the script, it will prompt you to enter your API key, which will be stored in the ~/.domainIQ file for future use.

## Usage

The script supports a variety of commands and options that can be used to perform different types of queries. 

````
usage: domainIQ.py [-h] [--whois_lookup WHOIS_LOOKUP] [--dns_lookup DNS_LOOKUP] [--types TYPES] [--domain_categorize DOMAIN_CATEGORIZE [DOMAIN_CATEGORIZE ...]]
                   [--domain_snapshot DOMAIN_SNAPSHOT] [--domain_snapshot_history DOMAIN_SNAPSHOT_HISTORY] [--snapshot_limit SNAPSHOT_LIMIT] [--full]
                   [--current_only] [--no_cache] [--raw] [--width WIDTH] [--height HEIGHT] [--domain_report DOMAIN_REPORT] [--name_report NAME_REPORT]
                   [--organization_report ORGANIZATION_REPORT] [--email_report EMAIL_REPORT] [--ip_report IP_REPORT]
                   [--domain_search DOMAIN_SEARCH [DOMAIN_SEARCH ...]] [--conditions CONDITIONS [CONDITIONS ...]] [--match {any,all}] [--count_only]
                   [--exclude_dashed] [--exclude_numbers] [--exclude_idn] [--min_length MIN_LENGTH] [--max_length MAX_LENGTH] [--min_create_date MIN_CREATE_DATE]
                   [--max_create_date MAX_CREATE_DATE] [--search_limit SEARCH_LIMIT] [--reverse_search_type {email,name,org}] [--reverse_search REVERSE_SEARCH]
                   [--reverse_match {contains,begins,ends}] [--reverse_dns REVERSE_DNS] [--reverse_ip_type {ip,subnet,block,range,domain}]
                   [--reverse_ip_data REVERSE_IP_DATA] [--reverse_mx_type {hostname,ip,subnet,block,range}] [--reverse_mx_data REVERSE_MX_DATA] [--recursive]
                   [--bulk_dns BULK_DNS [BULK_DNS ...]] [--bulk_whois BULK_WHOIS [BULK_WHOIS ...]] [--bulk_whois_type {live,registry,cached}]
                   [--bulk_whois_ip BULK_WHOIS_IP [BULK_WHOIS_IP ...]] [--monitor_list] [--monitor_report_items MONITOR_REPORT_ITEMS]
                   [--monitor_report_summary MONITOR_REPORT_SUMMARY] [--monitor_item MONITOR_ITEM] [--monitor_range MONITOR_RANGE]
                   [--monitor_report_changes MONITOR_REPORT_CHANGES] [--monitor_change MONITOR_CHANGE] [--create_monitor_report TYPE NAME] [--email_alert]
                   [--add_monitor_item REPORT_ID ITEM_TYPE ITEMS] [--enable_typos REPORT_ID ITEM_ID] [--disable_typos REPORT_ID ITEM_ID]
                   [--modify_typo_strength REPORT_ID ITEM_ID STRENGTH] [--delete_monitor_item DELETE_MONITOR_ITEM] [--delete_monitor_report DELETE_MONITOR_REPORT]

DomainIQ API Script

options:
  -h, --help            show this help message and exit
  --whois_lookup WHOIS_LOOKUP
                        Get WHOIS data for the specified domain or IP address
  --dns_lookup DNS_LOOKUP
                        Get DNS records for the specified domain or hostname
  --types TYPES         Specify the types of DNS records to retrieve, comma-separated
  --domain_categorize DOMAIN_CATEGORIZE [DOMAIN_CATEGORIZE ...]
                        Categorize the specified domain names. Usage: --domain_categorize domain1 domain2 ...
  --domain_snapshot DOMAIN_SNAPSHOT
                        Get a snapshot of the specified domain
  --domain_snapshot_history DOMAIN_SNAPSHOT_HISTORY
                        Get the snapshot history of the specified domain
  --snapshot_limit SNAPSHOT_LIMIT
                        Limit the number of results in snapshot history
  --full                Retrieve full WHOIS record or full domain snapshot
  --current_only        Use only the current WHOIS record
  --no_cache            Do not use a recently-cached snapshot
  --raw                 Return raw PNG/JPEG image directly
  --width WIDTH         Specify the width of the snapshot thumbnail
  --height HEIGHT       Specify the height of the snapshot thumbnail
  --domain_report DOMAIN_REPORT
                        Get domain report for the specified domain
  --name_report NAME_REPORT
                        Get registrant name report for the specified name
  --organization_report ORGANIZATION_REPORT
                        Get registrant organization report for the specified organization
  --email_report EMAIL_REPORT
                        Get registrant email report for the specified email
  --ip_report IP_REPORT
                        Get IP address summary report for the specified IP address
  --domain_search DOMAIN_SEARCH [DOMAIN_SEARCH ...]
                        Perform a search for domain names matching one or more keywords. Usage: --domain_search keyword1 [keyword2 ...]
  --conditions CONDITIONS [CONDITIONS ...]
                        Specify the conditions for each keyword in domain search. Usage: --conditions condition1 [condition2 ...]
  --match {any,all}     Specify the match type for multiple keywords in domain search. Default is 'any'
  --count_only          Get only the count of matched domains in domain search
  --exclude_dashed      Exclude domains with dashes (-) in domain search
  --exclude_numbers     Exclude domains with numbers in domain search
  --exclude_idn         Exclude IDN domains in domain search
  --min_length MIN_LENGTH
                        Minimum length of matched domains in domain search
  --max_length MAX_LENGTH
                        Maximum length of matched domains in domain search
  --min_create_date MIN_CREATE_DATE
                        Minimum WHOIS creation date in domain search (YYYY-MM-DD)
  --max_create_date MAX_CREATE_DATE
                        Maximum WHOIS creation date in domain search (YYYY-MM-DD)
  --search_limit SEARCH_LIMIT
                        Limit the number of results in domain search
  --reverse_search_type {email,name,org}
                        Specify the type for reverse search
  --reverse_search REVERSE_SEARCH
                        Specify the search string for reverse search
  --reverse_match {contains,begins,ends}
                        Specify the match type for reverse search
  --reverse_dns REVERSE_DNS
                        Perform a reverse DNS search for the specified domain
  --reverse_ip_type {ip,subnet,block,range,domain}
                        Specify the type for reverse IP search
  --reverse_ip_data REVERSE_IP_DATA
                        Specify the data for reverse IP search
  --reverse_mx_type {hostname,ip,subnet,block,range}
                        Specify the type for reverse MX search
  --reverse_mx_data REVERSE_MX_DATA
                        Specify the data for reverse MX search
  --recursive           Specify to recursively check MX hostnames to discover more domains
  --bulk_dns BULK_DNS [BULK_DNS ...]
                        Perform a bulk DNS lookup for the specified domains. Usage: --bulk_dns domain1 domain2 ...
  --bulk_whois BULK_WHOIS [BULK_WHOIS ...]
                        Perform a bulk WHOIS lookup for the specified domains or IP addresses. Usage: --bulk_whois domain1 domain2 ...
  --bulk_whois_type {live,registry,cached}
                        Specify the type of WHOIS lookup. Default is 'live'
  --bulk_whois_ip BULK_WHOIS_IP [BULK_WHOIS_IP ...]
                        Perform a bulk domain IP WHOIS lookup for the specified domains. Usage: --bulk_whois_ip domain1 domain2 ...
  --monitor_list        Get a list of active monitors
  --monitor_report_items MONITOR_REPORT_ITEMS
                        Get a list of items in a monitor. Specify the report ID
  --monitor_report_summary MONITOR_REPORT_SUMMARY
                        Get a summary of daily changes detected for a given report item. Specify the report ID
  --monitor_item MONITOR_ITEM
                        Specify the item ID for monitoring summary
  --monitor_range MONITOR_RANGE
                        Specify the range of days for monitoring summary
  --monitor_report_changes MONITOR_REPORT_CHANGES
                        Get a list of items changed in a daily change report. Specify the report ID
  --monitor_change MONITOR_CHANGE
                        Specify the change ID for monitoring changes
  --create_monitor_report TYPE NAME
                        Create a new monitor report. Specify the type and name of the report
  --email_alert         Enable email alerts for the monitor report. Used with --create_monitor_report
  --add_monitor_item REPORT_ID ITEM_TYPE ITEMS
                        Add items to a monitor report. Specify the report ID, item type, and items (comma-separated)
  --enable_typos REPORT_ID ITEM_ID
                        Enable typo monitoring for a keyword monitor item. Specify the report ID and item ID
  --disable_typos REPORT_ID ITEM_ID
                        Disable typo monitoring for a keyword monitor item. Specify the report ID and item ID
  --modify_typo_strength REPORT_ID ITEM_ID STRENGTH
                        Change the typo monitoring strength for a keyword monitor item. Specify the report ID, item ID, and strength (5-41)
  --delete_monitor_item DELETE_MONITOR_ITEM
                        Remove an individual monitoring item from a monitor report. Specify the item ID
  --delete_monitor_report DELETE_MONITOR_REPORT
                        Remove an entire monitor report. Specify the report ID
````

## WHOIS Lookup

#### Perform a WHOIS lookup for a domain or IP address.

python domainIQ.py --whois_lookup [domain_or_ip] [--full] [--current_only]

    --whois_lookup: Specifies the domain or IP for the WHOIS lookup.
    --full: (Optional) Retrieve the full WHOIS record.
    --current_only: (Optional) Use only the current WHOIS record.

### DNS Lookup

#### Retrieve DNS records for the specified domain or hostname.

python domainIQ.py --dns_lookup [domain_or_hostname] [--types A,MX]

    --dns_lookup: Specifies the domain or hostname for the DNS lookup.
    --types: (Optional) Specify the DNS record types to retrieve, comma-separated (e.g., A,MX).

### Domain Categorize

#### Categorize one or more domain names.

python domainIQ.py --domain_categorize [domain1 domain2 ...]

    --domain_categorize: Specifies the domains to categorize.

### Domain Snapshot

#### Get a snapshot of the specified domain.

python domainIQ.py --domain_snapshot [domain] [--full] [--no_cache] [--raw] [--width WIDTH] [--height HEIGHT]

    --domain_snapshot: Specifies the domain to snapshot.
    --full: (Optional) Retrieve a full-size image of the page.
    --no_cache: (Optional) Do not use a recently-cached snapshot.
    --raw: (Optional) Return the raw PNG/JPEG image directly.
    --width: (Optional) Specify the width of the snapshot thumbnail (default: 250).
    --height: (Optional) Specify the height of the snapshot thumbnail (default: 125).

### Domain Snapshot History

#### Retrieve the snapshot history of the specified domain.

python domainIQ.py --domain_snapshot_history [domain] [--snapshot_limit LIMIT] [--width WIDTH] [--height HEIGHT]

    --domain_snapshot_history: Specifies the domain to get the snapshot history.
    --snapshot_limit: (Optional) Limit the number of results (default: 10).
    --width: (Optional) Specify the width of the snapshot thumbnail (default: 250).
    --height: (Optional) Specify the height of the snapshot thumbnail (default: 125).

### Domain Report

#### Get a domain report for the specified domain.

python domainIQ.py --domain_report [domain]

    --domain_report: Specifies the domain to get the report.

### Name Report

#### Get a registrant name report for the specified name.

python domainIQ.py --name_report [name]

    --name_report: Specifies the registrant name to get the report.

### Organization Report

#### Get a registrant organization report for the specified organization.

python domainIQ.py --organization_report [organization]

    --organization_report: Specifies the registrant organization to get the report.

### Email Report

#### Get a registrant email report for the specified email.

python domainIQ.py --email_report [email]

    --email_report: Specifies the email to get the report.

### IP Report

#### Get an IP address summary report for the specified IP address.

python domainIQ.py --ip_report [ip]

    --ip_report: Specifies the IP address to get the report.

### Domain Search

#### Perform a search for domain names matching one or more keywords.

python domainIQ.py --domain_search [keyword1 keyword2 ...] [--conditions condition1 condition2 ...] [--match any|all] [--count_only] [--exclude_dashed] [--exclude_numbers] [--exclude_idn] [--min_length MIN] [--max_length MAX] [--min_create_date YYYY-MM-DD] [--max_create_date YYYY-MM-DD] [--search_limit LIMIT]

    --domain_search: Specifies the keywords for the search.
    --conditions: (Optional) Specifies the conditions for each keyword.
    --match: (Optional) Specifies the match type for multiple keywords (default: any).
    --count_only: (Optional) Get only the count of matched domains.
    --exclude_dashed: (Optional) Exclude domains with dashes.
    --exclude_numbers: (Optional) Exclude domains with numbers.
    --exclude_idn: (Optional) Exclude IDN domains.
    --min_length: (Optional) Minimum length of matched domains.
    --max_length: (Optional) Maximum length of matched domains.
    --min_create_date: (Optional) Minimum WHOIS creation date.
    --max_create_date: (Optional) Maximum WHOIS creation date.
    --search_limit: (Optional) Limit the number of results.

### Reverse Search

#### Perform a reverse search for email, name, or organization.

python domainIQ.py --reverse_search_type [email|name|org] --reverse_search [search_string] [--reverse_match contains|begins|ends]

    --reverse_search_type: Specifies the type for reverse search.
    --reverse_search: Specifies the search string.
    --reverse_match: (Optional) Specifies the match type (default: contains).

### Reverse DNS

#### Perform a reverse DNS search for the specified domain.

python domainIQ.py --reverse_dns [domain]

    --reverse_dns: Specifies the domain for reverse DNS search.

### Reverse IP

#### Perform a reverse IP search.

python domainIQ.py --reverse_ip_type [ip|subnet|block|range|domain] --reverse_ip_data [data]

    --reverse_ip_type: Specifies the type for reverse IP search.
    --reverse_ip_data: Specifies the data for reverse IP search.

### Reverse MX

#### Perform a reverse MX search.

python domainIQ.py --reverse_mx_type [hostname|ip|subnet|block|range] --reverse_mx_data [data] [--recursive]

    --reverse_mx_type: Specifies the type for reverse MX search.
    --reverse_mx_data: Specifies the data for reverse MX search.
    --recursive: (Optional) Recursively check MX hostnames to discover more domains.

### Bulk DNS Lookup

#### Perform a bulk DNS lookup for the specified domains.

python domainIQ.py --bulk_dns [domain1 domain2 ...]

    --bulk_dns: Specifies the domains for the bulk DNS lookup.

### Bulk WHOIS Lookup

#### Perform a bulk WHOIS lookup for the specified domains or IP addresses.

python domainIQ.py --bulk_whois [domain1 domain2 ...] [--bulk_whois_type live|registry|cached]

    --bulk_whois: Specifies the domains or IP addresses for the bulk WHOIS lookup.
    --bulk_whois_type: (Optional) Specifies the type of WHOIS lookup (default: live).

### Bulk WHOIS IP Lookup

#### Perform a bulk domain IP WHOIS lookup for the specified domains.

python domainIQ.py --bulk_whois_ip [domain1 domain2 ...]

    --bulk_whois_ip: Specifies the domains for the bulk IP WHOIS lookup.

### Monitoring

#### List Active Monitors

#### Get a list of active monitors.

python domainIQ.py --monitor_list

    --monitor_list: Lists all active monitors.

### Monitor Report Items

#### Get a list of items in a monitor.

python domainIQ.py --monitor_report_items [report_id]

    --monitor_report_items: Specifies the report ID to get the items.

### Monitor Report Summary

#### Get a summary of daily changes detected for a given report item.

python domainIQ.py --monitor_report_summary [report_id] [--monitor_item ITEM_ID] [--monitor_range RANGE]

    --monitor_report_summary: Specifies the report ID to get the summary.
    --monitor_item: (Optional) Specifies the item ID for the summary.
    --monitor_range: (Optional) Specifies the range of days for the summary.

### Monitor Report Changes

#### Get a list of items changed in a daily change report.

python domainIQ.py --monitor_report_changes [report_id] --monitor_change [change_id]

    --monitor_report_changes: Specifies the report ID to get the changes.
    --monitor_change: Specifies the change ID to get the changes.

### Create Monitor Report

#### Create a new monitor report.

python domainIQ.py --create_monitor_report [type] [name] [--email_alert]

    --create_monitor_report: Specifies the type and name of the report.
    --email_alert: (Optional) Enable email alerts for the monitor report.

### Add Monitor Item

#### Add items to a monitor report.

python domainIQ.py --add_monitor_item [report_id] [item_type] [items]

    --add_monitor_item: Specifies the report ID, item type, and items (comma-separated).

### Enable Typos

#### Enable typo monitoring for a keyword monitor item.

python domainIQ.py --enable_typos [report_id] [item_id]

    --enable_typos: Specifies the report ID and item ID.

### Disable Typos

#### Disable typo monitoring for a keyword monitor item.

python domainIQ.py --disable_typos [report_id] [item_id]

    --disable_typos: Specifies the report ID and item ID.

### Modify Typo Strength

#### Change the typo monitoring strength for a keyword monitor item.

python domainIQ.py --modify_typo_strength [report_id] [item_id] [strength]

    --modify_typo_strength: Specifies the report ID, item ID, and strength (5-41).

### Delete Monitor Item

#### Remove an individual monitoring item from a monitor report.

python domainIQ.py --delete_monitor_item [item_id]

    --delete_monitor_item: Specifies the item ID to delete.

### Delete Monitor Report

#### Remove an entire monitor report.

python domainIQ.py --delete_monitor_report [report_id]

    --delete_monitor_report: Specifies the report ID to delete.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.
