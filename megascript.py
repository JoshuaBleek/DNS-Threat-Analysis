import csv
import re
import logging
import ipaddress
import requests
from datetime import datetime
from newfreq import FreqCounter  # Assuming freq3 is your updated frequency analysis module

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
    
# Function to check if a domain is a 'baby domain'
    """
def whoapi_request(domain, r, apikey):
    try:
        res = requests.get('https://api.whoapi.com', params={
            'domain': domain,
            'r': r,
            '4887141fc5b83e5aa166c9be3d2fac44': apikey  # Your API key
        })
    
        if res.status_code == 200:
            data = res.json()
            if int(data['status']) == 0:
                return data['date_created']  # Return the creation date of the domain
            else:
                logging.error("API reports error: " + data['status_desc'])
        else:
            logging.error('Unexpected status code %d' % res.status_code)
    except Exception as e:
        logging.error("Error in WhoAPI request: " + str(e))
    except requests.exceptions.Timeout:
        logging.error(f"Request timed out for domain: {domain}")
    except Exception as e:
        logging.error(f"Error in WhoAPI request for domain {domain}: {str(e)}")
    return None
    """
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
    current_timestamp = get_current_timestamp()
    domain_timestamp = f"{domain}-{current_timestamp}"

    if domain in top_domains or domain in logged_domains:
        return False  # Skip if it's a top domain or already logged with this timestamp

    logged_domains.add(domain_timestamp)

    if is_malformed_domain(domain):
        logging.warning(f"{current_timestamp} - Malformed domain detected: {domain}")
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

# Read the last 100 lines of the log file
with open(dns_log_file_path, 'r') as log_file:
    lines = log_file.readlines()[-300:]

# Process only the last 100 lines
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
