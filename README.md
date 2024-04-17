# DNS Threat Analysis Tool

## Overview

This project is a DNS traffic monitoring tool designed to analyze DNS logs and detect suspicious domain activities. It provides functionalities to analyze DNS queries, check domain reputation against a list of known malicious domains, identify malformed or high-entropy domains, and detect "baby" domains (recently created domains). Additionally, it logs DNS traffic from non-whitelisted domains for further analysis.

## Features

- Analyzes DNS logs from a specified log file (`/var/log/named`)
- Detects and logs malicious domains based on a list of known malicious domains (`malicious_domains.txt`)
- Identifies malformed or high-entropy domains
- Detects "baby" domains (recently created domains)
- Logs DNS traffic from non-whitelisted domains for further analysis
- Provides detailed logging with timestamps

## Dependencies

- Python 3.x
- `ipaddress`, `whois`, and `datetime` libraries (install via `pip` if not already installed)
- Internet connection required for WHOIS lookups

## Installation

1. Clone the repository to your local machine:

```bash
git@github.com:JoshuaBleek/DNS-Threat-Analysis.git
```

2. Install top-1mil.csv (it was too big for github):

```bash
curl -OJL https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
```

## Usage

1. Run the `threat_analysis.py` script to start analyzing DNS logs:

```bash
python3 threat_analysis.py
```

2. Monitor the logs generated in the `logs/` folder for analysis results.

## Configuration

- `/var/log/named`: Path to the DNS log file to be analyzed (yours may differ from mine depending on configuration)
- `whitelist_tlds.txt`: Path to the whitelist file containing whitelisted TLDs
- `malicious_domains.txt`: Path to the file containing known malicious domains (to ensure up to date list you may want to use cron job)
- `top-1m.csv`: Path to the CSV file containing the top 1 million domains (to ensure up to date list you may want to use cron job)

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## Credit

1. The `malicious_domains.txt` file used in this project was obtained from [stamparm/blackbook](https://github.com/stamparm/blackbook).

2. The `top-1m.csv.zip` file used in this project was downloaded from [Cisco Umbrella](https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip).

3. My main man Karl G. who oversaw and guided me through this project
