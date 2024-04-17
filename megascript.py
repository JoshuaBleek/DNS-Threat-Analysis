import csv
import re
import logging
import ipaddress
import whois
from datetime import datetime

# File paths and settings
dns_log_file_path = '/var/log/named/dnsquery.log'
whitelist_file = 'whitelist_tlds.csv'
malicious_domains_file = 'malicious_domains.txt'
logs_folder = 'logs/'
top_1m_csv_path = 'top-1m.csv'
logs_folder = logs_folder.rstrip('/') + '/'
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f'{logs_folder}dns_monitoring_{current_time}.log'
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load malicious domains from a file
with open(malicious_domains_file) as file:
    malicious_domains = set(line.strip().lower() for line in file)

top_domains = read_top_domains(top_1m_csv_path)

# Regular expression to extract domains from log entries
domain_pattern = re.compile(r'\(([^)]+)\)')

def is_ip_address(string):
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def extract_domain_names(log_entry):
    matches = domain_pattern.findall(log_entry)
    return {match for match in matches if '.' in match and not is_ip_address(match)}

def is_malformed_domain(domain):
    return not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain)

def analyze_domain(domain, processed_domains):
    if domain in processed_domains:
        return False
    processed_domains.add(domain)
    domain_is_malformed = is_malformed_domain(domain)
    domain_in_malicious = domain.lower() in malicious_domains
    domain_in_top_domains = domain in top_domains
    result = domain_in_malicious or domain_is_malformed or not domain_in_top_domains
    if result:
        logging.warning(f"Malicious or malformed domain detected: {domain}")
    return result

def analyze_logs():
    with open(dns_log_file_path, 'r') as log_file:
        lines = log_file.readlines()
    total_lines = len(lines)
    processed_domains = set()
    suspicious_count = 0

    for i, line in enumerate(lines):
        domains = extract_domain_names(line)
        for domain in domains:
            if analyze_domain(domain, processed_domains):
                suspicious_count += 1
        print(f"\rProcessing line {i+1}/{total_lines} ({(i+1)/total_lines*100:.2f}%)", end='')

    if suspicious_count == 0:
        logging.info("No suspicious activity detected.")
    else:
        logging.info(f"Analysis complete. {suspicious_count} suspicious domains detected.")

    logging.info("DNS log analysis completed.")

# Read top-1m.csv file
def read_top_domains(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        return {row[1] for row in reader}

# Call the main function
analyze_logs()
