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

# Specific loggers for different types of domain checks
loggers = {
    'malicious': logging.getLogger('malicious'),
    'malformed_or_high_entropy': logging.getLogger('malformed_or_high_entropy'),
    'baby_domain': logging.getLogger('baby_domain'),
}

for key, logger in loggers.items():
    logger.setLevel(logging.WARNING)
    handler = logging.FileHandler(f'{logs_folder}{key}_{current_time}.log')
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

# Load malicious domains from a file
with open(malicious_domains_file) as file:
    malicious_domains = set(line.strip().lower() for line in file)

# Load top domains from a file
def read_top_domains(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        return {row[1] for row in reader}

top_domains = read_top_domains(top_1m_csv_path)

# Define regular expression for domain extraction
domain_pattern = re.compile(r'\(([^)]+)\)')

def is_ip_address(string):
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def is_malformed_domain(domain):
    return not re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain)

def is_baby_domain(domain, age_threshold_days=30):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is not None and (datetime.now() - creation_date).days <= age_threshold_days:
            return True
    except Exception as e:
        loggers['baby_domain'].error(f"WHOIS lookup failed for {domain}: {e}")
    return False

def extract_domain_names(log_entry):
    matches = domain_pattern.findall(log_entry)
    return {match for match in matches if '.' in match and not is_ip_address(match)}

def analyze_domain(domain):
    if domain in malicious_domains:
        loggers['malicious'].warning(f"Malicious domain detected: {domain}")
        return True
    elif domain in top_domains:
        return True
    else:
        domain_is_malformed = is_malformed_domain(domain)
        domain_is_baby = is_baby_domain(domain)
        if domain_is_malformed:
            loggers['malformed_or_high_entropy'].warning(f"Malformed/high entropy domain detected: {domain}")
        if domain_is_baby:
            loggers['baby_domain'].warning(f"Baby domain detected: {domain}")
        return domain_is_malformed or domain_is_baby

# Analyzing DNS logs
def analyze_logs():
    with open(dns_log_file_path, 'r') as log_file:
        lines = log_file.readlines()
    total_lines = len(lines)
    processed_domains = set()
    suspicious_count = 0

    for i, line in enumerate(lines):
        domains = extract_domain_names(line)
        for domain in domains:
            if analyze_domain(domain):
                suspicious_count += 1
        progress = ((i + 1) / total_lines) * 100
        print(f"\rProgress: {progress:.2f}% - Processed {i+1} of {total_lines} lines", end='')

    logging.info(f"DNS log analysis completed. {suspicious_count} suspicious domains detected.")

# Run the analysis
analyze_logs()
