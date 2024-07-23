import sys
import os
import re
import pandas as pd

def main():
    log_file = get_log_file_path_from_cmd_line()
    # Test the functions by calling them here, example usage:
    # Example: filter_log_by_regex(log_file, r'sshd', ignore_case=True, print_summary=True, print_records=True)
    # Step 5 tasks:
    sshd_records, _ = filter_log_by_regex(log_file, r'sshd', ignore_case=True, print_summary=True, print_records=True)
    invalid_user_records, _ = filter_log_by_regex(log_file, r'invalid user', ignore_case=True, print_summary=True, print_records=True)
    ip_records, _ = filter_log_by_regex(log_file, r'invalid user.*220.195.35.40', ignore_case=True, print_summary=True, print_records=True)
    error_records, _ = filter_log_by_regex(log_file, r'error', ignore_case=True, print_summary=True, print_records=True)
    pam_records, _ = filter_log_by_regex(log_file, r'pam', ignore_case=True, print_summary=True, print_records=True)

    # Generate reports
    port_traffic = tally_port_traffic(log_file)
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_file, port)

    generate_invalid_user_report(log_file)
    generate_source_ip_log(log_file, '220.195.35.40')

# TODO: Step 3
def get_log_file_path_from_cmd_line():
    if len(sys.argv) < 2:
        print("Error: Log file path must be provided as a command line argument.")
        sys.exit(1)

    log_file_path = sys.argv[1]

    if not os.path.isfile(log_file_path):
        print(f"Error: File '{log_file_path}' does not exist.")
        sys.exit(1)

    return log_file_path

# TODO: Steps 4-7
def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    pattern_flags = re.IGNORECASE if ignore_case else 0
    pattern = re.compile(regex, pattern_flags)
    
    matching_records = []
    captured_data = []
    
    with open(log_file, 'r') as file:
        for line in file:
            if pattern.search(line):
                matching_records.append(line.strip())
                match = pattern.search(line)
                if match:
                    captured_data.append(match.groups())

    if print_records:
        for record in matching_records:
            print(record)
    
    if print_summary:
        print(f"The log file contains {len(matching_records)} records that match the regex \"{regex}\".")

    return matching_records, captured_data

# TODO: Step 8
def tally_port_traffic(log_file):
    port_traffic = {}
    pattern = re.compile(r'DPT=(\d+)')

    with open(log_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                port = match.group(1)
                if port in port_traffic:
                    port_traffic[port] += 1
                else:
                    port_traffic[port] = 1

    return port_traffic

# TODO: Step 9
def generate_port_traffic_report(log_file, port_number):
    pattern = re.compile(r'(\w+ \d+ \d+:\d+:\d+) .*? SRC=(.*?) DST=(.*?) .*? SPT=(.*?) DPT=(.*?) ')

    report_data = []

    with open(log_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match and match.group(5) == str(port_number):
                report_data.append(match.groups())

    columns = ['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port']
    df = pd.DataFrame(report_data, columns=columns)

    report_filename = f"destination_port_{port_number}_report.csv"
    df.to_csv(report_filename, index=False)

# TODO: Step 11
def generate_invalid_user_report(log_file):
    pattern = re.compile(r'(\w+ \d+ \d+:\d+:\d+) .*? Invalid user (.*?) from (.*?) ')

    report_data = []

    with open(log_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                report_data.append(match.groups())

    columns = ['Date', 'Time', 'Username', 'IP Address']
    df = pd.DataFrame(report_data, columns=columns)

    report_filename = "invalid_users.csv"
    df.to_csv(report_filename, index=False)

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):
    regex = f'SRC={ip_address}'
    records, _ = filter_log_by_regex(log_file, regex)

    log_filename = f"source_ip_{ip_address.replace('.', '_')}.log"
    with open(log_filename, 'w') as file:
        for record in records:
            file.write(record + '\n')

if __name__ == '__main__':
    main()
