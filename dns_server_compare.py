import re
import time
import logging
from datetime import datetime

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
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Load malicious domains from a file
with open('malicious_domains.txt') as file:
    malicious_domains = set(line.strip().lower() for line in file)

def extract_domain_from_log_line(line):
    # Regex to extract domain name from log line
    match = re.search(r'query: ([^\s]+)', line)
    if match:
        domain_name = match.group(1).lower().split()[0]  # Extract and normalize the domain name
        return domain_name
    return None

def monitor_dns_log():
    print("Monitoring DNS log for malicious domain activity. Press Ctrl+C to stop.")

    with open(dns_log_file_path, 'r') as log_file:
        # Move to the end of the file
        log_file.seek(0, 2)  
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(0.1)  # Wait briefly for new content
                continue

            domain_name = extract_domain_from_log_line(line)
            if domain_name and domain_name in malicious_domains:
                alert_message = f"Malicious domain detected: {domain_name}"
                print(alert_message)
                logging.warning(alert_message)  # Log the detection

if __name__ == '__main__':
    try:
        monitor_dns_log()
    except KeyboardInterrupt:
        print("Monitoring stopped.")
