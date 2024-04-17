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

# Setup specific loggers for different types of domain checks
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

# Load domains lists
def load_domains(file_path):
    with open(file_path) as file:
        return set(line.strip().lower() for line in file)

malicious_domains = load_domains(malicious_domains_file)
top_domains = load_domains(top_1m_csv_path)

# Regular expression for domain extraction
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
        # Extract TLD from the domain
        tld = domain.split('.')[-1]
        
        # Check if the TLD is one of the desired TLDs
        if tld in ['com', 'net', 'edu']:
            domain_info = whois.query(domain)
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

def analyze_domain(domain, processed_domains):
    if domain in processed_domains:
        return False  # Skip duplicate domains
    processed_domains.add(domain)

    if domain in malicious_domains:
        loggers['malicious'].warning(f"Malicious domain detected: {domain}")
        return True
    if domain in top_domains:
        logging.info(f"WHOIS check skipped for {domain}: Domain in top domains list")
        return False  # Skip WHOIS test if it's in the top domains list
    if domain.endswith('.com') or domain.endswith('.net') or domain.endswith('.edu'):
        logging.info(f"WHOIS check skipped for {domain}: Common TLD")
        return False  # Skip WHOIS test for common TLDs
    
    logging.info(f"Performing WHOIS check for {domain}")  # Log that a WHOIS check is being performed
    domain_is_malformed = is_malformed_domain(domain)
    domain_is_baby = is_baby_domain(domain)
    if domain_is_malformed:
        loggers['malformed_or_high_entropy'].warning(f"Malformed/high entropy domain detected: {domain}")
        return True
    if domain_is_baby:
        loggers['baby_domain'].warning(f"Baby domain detected: {domain}")
        return True
    # If the domain passes WHOIS test, print/log a message
    logging.info(f"Domain passed WHOIS test: {domain}")
    return False





# Analyzing DNS logs
def analyze_logs():
    processed_domains = set()
    suspicious_count = 0
    line_count = 0
    with open(dns_log_file_path, 'r') as log_file:
        for line in log_file:
            line_count += 1
            domains = extract_domain_names(line)
            for domain in domains:
                if analyze_domain(domain, processed_domains):
                    suspicious_count += 1
            if line_count % 100 == 0:  # Update progress every 100 lines
                print(f"Progress: Processed {line_count} lines.")  # Print progress updates to command line

    logging.info(f"DNS log analysis completed. {suspicious_count} suspicious domains detected.")

# Run the analysis
analyze_logs()
