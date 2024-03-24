import csv
import re
import logging
import ipaddress
from datetime import datetime
from newfreq import FreqCounter  # Assuming freq3 is your updated frequency analysis module

# File paths and settings
dns_log_file_path = '/var/log/named/dnsquery.log'
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

# Placeholder for checking if a domain is a 'baby domain'
def is_baby_domain(domain):
    # Implement or integrate an API call here
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
    return [match for match in matches if '.' in match and not is_ip_address(match)]

analyzed_domains = set()
def analyze_domain(domain):
    if domain in top_domains:
        return False  # Skip if it's a top domain
    if domain in analyzed_domains:
        return False  # Skip analysis if domain was already analyzed
    analyzed_domains.add(domain)
    if is_baby_domain(domain):
        logging.warning(f'Baby domain detected: {domain}')
        return True
    if is_malformed_domain(domain):
        logging.warning(f'Malformed domain detected: {domain}')
        return True
    probability = freq_counter.probability(domain)[0]
    if probability < 20:  # Set your threshold here
        logging.warning(f'Suspicious domain detected (based on probability): {domain} - Probability: {probability}')
        return True
    return False

# Analyzing DNS logs
logging.info("Starting DNS log analysis.")
suspicious_count = 0

with open(dns_log_file_path, 'r') as log_file:
    for line in log_file:
        domains = extract_domain_names(line)
        for domain in domains:
            if analyze_domain(domain):
                suspicious_count += 1

if suspicious_count == 0:
    logging.info("No suspicious activity detected.")
else:
    logging.info(f"Analysis complete. {suspicious_count} suspicious domains detected.")

logging.info("DNS log analysis completed.")
