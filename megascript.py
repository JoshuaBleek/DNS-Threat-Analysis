import csv
import re
import logging
import ipaddress
import requests
import whois
from datetime import datetime
from newfreq import FreqCounter  

# File paths and settings
dns_log_file_path = '/var/log/named/dnsquery.log'
whitelist_file = 'whitelist_tlds.csv'  # Filename of the whitelist CSV
logs_folder = 'logs/'
top_1m_csv_path = 'top-1m.csv'  # Path to top-1m.csv file
logs_folder = logs_folder.rstrip('/') + '/'
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f'{logs_folder}dns_monitoring_{current_time}.log'
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize and load the frequency counter
freq_counter = FreqCounter()
# freq_counter.load('path_to_your_data_file')  # Load your frequency data

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
        # Skip header and read TLDs
        next(reader, None)
        whitelist = {row[0] for row in reader}
    return whitelist

whitelist = read_whitelist(whitelist_file)

def is_baby_domain(domain, age_threshold_days=30):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):  # Handle multiple dates
            creation_date = creation_date[0]
        if (datetime.now() - creation_date).days <= age_threshold_days:
            return True
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {str(e)}")
    return False

# Modify the analyze_domain function
def analyze_domain(domain):
    global logged_domains
    current_timestamp = get_current_timestamp()
    domain_timestamp = f"{domain}-{current_timestamp}"

    if domain in top_domains or domain in logged_domains:
        return False

    # Check against the whitelist
    domain_tld = '.' + domain.split('.')[-1]
    if domain_tld in whitelist:
        return False
    
 # Baby domain check
    if is_baby_domain(domain):
        logging.warning(f"{current_timestamp} - Baby domain detected: {domain}")
        logged_domains.add(domain)
        return True

    if is_malformed_domain(domain):
        logging.warning(f"{current_timestamp} - Malformed domain detected: {domain}")
        logged_domains.add(domain)  # Add domain to logged_domains
        return True
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
    unique_domains = {match for match in matches if '.' in match and not is_ip_address(match)}
    return unique_domains

logged_domains = set()  # Set to track domains with timestamps that have been logged
def get_current_timestamp():
    return datetime.now().strftime("%H:%M:%S,%f")

def analyze_domain(domain):
    global logged_domains

    # Skip if it's a top domain or already logged
    if domain in top_domains or domain in logged_domains:
        return False

    current_timestamp = get_current_timestamp()

    if is_malformed_domain(domain):
        logging.warning(f"{current_timestamp} - Malformed domain detected: {domain}")
        logged_domains.add(domain)  # Add domain to logged_domains
        return True

    # WhoAPI check for domain age
    """
    domain_creation_date = whoapi_request(domain, 'whois', '4887141fc5b83e5aa166c9be3d2fac44')
    if domain_creation_date:
        # Add logic here to determine if the domain is young (e.g., less than 30 days old)
        logging.info(f"Domain {domain} was created on {domain_creation_date}")

    # Frequency analysis
    probability = freq_counter.probability(domain)[0]
    if probability < 20:
        logging.warning(f"{current_timestamp} - Suspicious domain detected (based on probability): {domain} - Probability: {probability}")
        return True

    return False
    """

# Analyzing DNS logs
logging.info("Starting DNS log analysis.")
suspicious_count = 0

with open(dns_log_file_path, 'r') as log_file:
    lines = log_file.readlines()#[-10000000:]

for line in lines:
    domains = extract_domain_names(line)
    for domain in domains:
        if analyze_domain(domain):
            suspicious_count += 1

if suspicious_count == 0:
    logging.info("No suspicious activity detected.")
else:
    logging.info(f"Analysis complete. {suspicious_count} suspicious domains detected.")

logging.info("DNS log analysis completed.")
