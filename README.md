DNS Traffic Monitoring Tool
Overview
This project is a DNS traffic monitoring tool designed to analyze DNS logs and detect suspicious domain activities. It provides functionalities to analyze DNS queries, check domain reputation against a list of known malicious domains, identify malformed or high-entropy domains, and detect "baby" domains (recently created domains). Additionally, it logs DNS traffic from non-whitelisted domains for further analysis.

Features
Analyzes DNS logs from a specified log file (dns_log_file_path)
Detects and logs malicious domains based on a list of known malicious domains (malicious_domains_file)
Identifies malformed or high-entropy domains
Detects "baby" domains (recently created domains)
Logs DNS traffic from non-whitelisted domains for further analysis
Provides detailed logging with timestamps and severity levels
Dependencies
Python 3.x
ipaddress, whois, and datetime libraries (install via pip if not already installed)
Internet connection required for WHOIS lookups
Installation
Clone the repository to your local machine:
bash
Copy code
git clone https://github.com/your_username/dns-traffic-monitoring.git
Install the required dependencies:
bash
Copy code
pip install -r requirements.txt
Ensure that the log file paths and settings in config.py are correctly configured according to your environment.
Usage
Run the analyze_logs() function from the main script to start analyzing DNS logs:
bash
Copy code
python main.py
Monitor the logs generated in the logs/ folder for analysis results.
Configuration
dns_log_file_path: Path to the DNS log file to be analyzed
whitelist_file: Path to the whitelist file containing whitelisted TLDs
malicious_domains_file: Path to the file containing known malicious domains
top_1m_csv_path: Path to the CSV file containing the top 1 million domains
Contributing
Contributions are welcome! If you'd like to contribute to this project, please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

License
This project is licensed under the MIT License.
