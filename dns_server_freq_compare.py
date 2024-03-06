import re
import logging
import ipaddress
from datetime import datetime
from freq3 import FreqCounter  # Assuming freq3 is your updated frequency analysis module

# Define the path to the DNS log file
dns_log_file_path = '/var/log/named/dnsquery.log'

# Define the path to the logs folder
logs_folder = 'logs/'

# Ensure the folder path ends with a slash
if not logs_folder.endswith('/'):
    logs_folder += '/'

# Configure logging with a more readable timestamp format
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f'{logs_folder}dns_monitoring_{current_time}.log'
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize frequency counter
freq_counter = FreqCounter()
# Make sure to load your frequency counter with appropriate data here

# Common domains and IPs to exclude
common_domains = {"google.com", "nvidia.com", "microsoft.com", "gstatic.com", "in-addr.arpa"}  # Add more as needed

def is_ip_address(string):
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def extract_domain_names(log_entry):
    pattern = r'\(([^)]+)\)'
    matches = re.findall(pattern, log_entry)
    return [match for match in matches if '.' in match and not is_ip_address(match) and match not in common_domains]

threshold = 20

def analyze_domain_frequency(domain):
    probability = freq_counter.probability(domain)
    if probability < threshold:
        logging.warning(f'Suspicious domain detected: {domain} - Probability: {probability}')
        return True
    else:
        logging.info(f'Non-suspicious domain: {domain} - Probability: {probability}')
        return False

# Start of the script
logging.info("Starting DNS log analysis.")

# Counter for suspicious domains
suspicious_count = 0

# Main loop to read and process the log file
with open(dns_log_file_path, 'r') as log_file:
    for line in log_file:
        domains = extract_domain_names(line)
        for domain in domains:
            if analyze_domain_frequency(domain):
                suspicious_count += 1

# End of the script
if suspicious_count == 0:
    logging.info("No suspicious activity detected.")
else:
    logging.info(f"Analysis complete. {suspicious_count} suspicious domains detected.")

logging.info("DNS log analysis completed.")
