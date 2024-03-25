import csv
import re
import logging
import ipaddress
import http.client
import json
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
def get_domain_age(domain):
    conn = http.client.HTTPSConnection("domain-age.p.rapidapi.com")
    headers = {
        'X-RapidAPI-Key': "a4e34dc3c3msh760ee3872ebdd85p139d56jsnbf108e6d63a1",
        'X-RapidAPI-Host': "domain-age.p.rapidapi.com"
    }

    try:
        conn.request("GET", f"/domain_age/{domain}", headers=headers)
        res = conn.getresponse()
        data = res.read()
        domain_info = json.loads(data.decode("utf-8"))
        return domain_info.get("age_days", None)  # Assumes 'age_days' is the field name for age in days
    except Exception as e:
        logging.error(f"Error checking domain age: {e}")
        return None

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

    logged_domains.add(domain_timestamp
                       )
    domain_age = get_domain_age(domain)
    
    if domain_age is not None and domain_age < 30:  # Adjust this threshold as needed
        logging.warning(f"{current_timestamp} - Suspiciously young domain detected: {domain} - Age: {domain_age} days")
        return True

    if get_domain_age(domain) or is_malformed_domain(domain):
        logging.warning(f"{current_timestamp} - Suspicious domain detected: {domain}")
        return True

    probability = freq_counter.probability(domain)[0]
    if probability < 20:
        logging.warning(f"{current_timestamp} - Suspicious domain detected (based on probability): {domain} - Probability: {probability}")
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
