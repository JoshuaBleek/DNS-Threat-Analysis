import re
import time
import logging
from datetime import datetime

# New imports for frequency analysis
from freq3 import FreqCounter

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

# Initialize frequency counter
freq_counter = FreqCounter()

# Function to extract domain names from log entries
def extract_domain_names(log_entry):
    # This pattern matches domain names within parentheses
    pattern = r'\(([^)]+)\)'
    matches = re.findall(pattern, log_entry)
    return [match for match in matches if '.' in match]  # Filter out non-domain strings


# Function to analyze domain name frequency
def analyze_domain_frequency(domain):
    probability = freq_counter.measure_string_likelihood(domain)
    # Define a threshold for suspicious domain names
    threshold = 0.5  # This is an example value, adjust based on your requirements
    if probability < threshold:
        return True  # Suspicious
    else:
        return False  # Not suspicious

# Main loop to read and process the log file
# This might need to be a continuous loop or a scheduled task
with open(dns_log_file_path, 'r') as log_file:
    for line in log_file:
        domains = extract_domain_names(line)
        for domain in domains:
            if analyze_domain_frequency(domain):
                # Log the suspicious domain for further review
                logging.warning(f'Suspicious domain detected: {domain}')