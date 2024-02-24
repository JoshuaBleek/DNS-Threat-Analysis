import subprocess
import re
import logging
from datetime import datetime

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

def parse_tshark_line(line):
    # Regex to extract any DNS query/response and its type
    match = re.search(r'\sDNS\s\d+\s.*?\s0x[0-9a-f]+\s([A-Z]+)\s+([^\s]+)', line)
    if match:
        record_type = match.group(1)
        domain_name = match.group(2).lower()
        return domain_name, record_type
    return None

def print_dns_activity(activity_dict):
    for domain, record_types in activity_dict.items():
        print(f"{domain}:")
        for record_type, count in record_types.items():
            print(f"  {record_type}: {count} times")
        print()

tshark_cmd = ['sudo', 'tshark', '-i', 'enp0s3', '-f', "port 53"]
process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, text=True)

dns_activity = {}
desired_types = {'A', 'AAAA', 'SRV', 'PTR'}
detected_domains = set()

try:
    print("Capturing DNS packets. Press Ctrl+C to stop and print activity summary.")
    for line in process.stdout:
        parsed_data = parse_tshark_line(line)
        if parsed_data:
            domain_name, record_type = parsed_data
            domain_record_combo = (domain_name, record_type)

            if domain_name in malicious_domains:
                if domain_record_combo not in detected_domains:
                    alert_message = f"Malicious domain detected: {domain_name}, Type: {record_type}"
                    print(alert_message)
                    logging.warning(alert_message)  # Log the detection
                    detected_domains.add(domain_record_combo)  # Add to detected set

            if record_type in desired_types:
                if domain_name not in dns_activity:
                    dns_activity[domain_name] = {}
                if record_type not in dns_activity[domain_name]:
                    dns_activity[domain_name][record_type] = 0
                dns_activity[domain_name][record_type] += 1
except KeyboardInterrupt:
    print("\nDNS Activity Summary:")
    print_dns_activity(dns_activity)
    process.terminate()
