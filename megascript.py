import csv
import re
import logging
import ipaddress
import math
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

# Read the top-1m.csv file
def read_top_domains(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        top_domains = {row[1] for row in reader}
    return top_domains

top_domains = read_top_domains(top_1m_csv_path)

def read_whitelist(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader, None)  # Skip header
        whitelist = {row[0] for row in reader}
    return whitelist

whitelist = read_whitelist(whitelist_file)

def is_baby_domain(domain, age_threshold_days=30):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is not None and (datetime.now() - creation_date).days <= age_threshold_days:
            return True
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {str(e).split('\n')[0]}")
    return False

def is_ip_address(string):
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def is_malformed_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    return not re.match(pattern, domain)

def extract_domain_names(log_entry):
    pattern = r'\(([^)]+)\)'
    matches = re.findall(pattern, log_entry)
    return {match for match in matches if '.' in match and not is_ip_address(match)}

# Set up specific loggers
loggers = {
    'malicious': logging.getLogger('malicious'),
    'malicious_not_topmil': logging.getLogger('malicious_not_topmil'),
    'malformed_or_high_entropy': logging.getLogger('malformed_or_high_entropy'),
    'baby_domain': logging.getLogger('baby_domain'),
}

for key in loggers:
    loggers[key].setLevel(logging.WARNING)
    handler = logging.FileHandler(f'{logs_folder}{key}_{current_time}.log')
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    loggers[key].addHandler(handler)

def analyze_domain(domain, processed_domains):
    if domain in processed_domains:
        return False
    processed_domains.add(domain)

    domain_in_top_domains = domain in top_domains
    domain_in_malicious = domain.lower() in malicious_domains
    domain_is_malformed = is_malformed_domain(domain)
    domain_is_baby = is_baby_domain(domain)

    suspicious = False
    if domain_in_malicious:
        loggers['malicious'].warning(f"{datetime.now().strftime('%H:%M:%S,%f')} - Malicious domain detected: {domain}")
        suspicious = True
    if not domain_in_top_domains:
        if domain_is_malformed:
            loggers['malformed_or_high_entropy'].warning(f"{datetime.now().strftime('%H:%M:%S,%f')} - Malformed/high entropy domain: {domain}")
        if domain_is_baby:
            loggers['baby_domain'].warning(f"{datetime.now().strftime('%H:%M:%S,%f')} - Baby domain detected: {domain}")
    return suspicious

# Analyzing DNS logs
logging.info("Starting DNS log analysis.")
suspicious_count = 0
processed_domains = set()

with open(dns_log_file_path, 'r') as log_file:
    lines = log_file.readlines()[-10000:]
    total_lines = len(lines)

    for i, line in enumerate(lines):
        domains = extract_domain_names(line)
        for domain in domains:
            if analyze_domain(domain, processed_domains):
                suspicious_count += 1

        print(f"\rProgress: {((i + 1) / total_lines) * 100:.2f}%", end='')

if suspicious_count == 0:
    logging.info("No suspicious activity detected.")
else:
    logging.info(f"Analysis complete. {suspicious_count} suspicious domains detected.")

logging.info("DNS log analysis completed.")
