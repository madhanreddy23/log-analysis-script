import csv
from collections import defaultdict, Counter

# Configurable threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log(file_path):
    """
    Parses the log file and extracts relevant details.
    Returns:
        - A dictionary of IP addresses and their request counts.
        - A dictionary of endpoints and their access counts.
        - A dictionary of failed login attempts by IP addresses.
    """
    ip_request_count = Counter()
    endpoint_access_count = Counter()
    failed_login_attempts = Counter()

    with open(file_path, 'r') as file:
        for line in file:
            try:
                # Split the log line to extract parts
                parts = line.split()
                ip = parts[0]
                request = parts[5] + ' ' + parts[6]
                status_code = parts[8]

                # Count requests per IP
                ip_request_count[ip] += 1

                # Count endpoint accesses
                endpoint_access_count[parts[6]] += 1

                # Check for failed login attempts
                if status_code == "401" or "Invalid credentials" in line:
                    failed_login_attempts[ip] += 1

            except IndexError:
                # Skip malformed log entries
                continue

    return ip_request_count, endpoint_access_count, failed_login_attempts

def generate_output(ip_counts, endpoint_counts, failed_logins, threshold):
    """
    Generates the output to be displayed and saved in a CSV file.
    """
    print("IP Address Request Counts:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count:<15}")

    # Write results to a CSV file
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        # Write header for requests per IP
        csv_writer.writerow(["Requests per IP"])
        csv_writer.writerow(["IP Address", "Request Count"])
        csv_writer.writerows(sorted_ips)

        # Write header for most accessed endpoint
        csv_writer.writerow([])
        csv_writer.writerow(["Most Accessed Endpoint"])
        csv_writer.writerow(["Endpoint", "Access Count"])
        csv_writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write header for suspicious activity
        csv_writer.writerow([])
        csv_writer.writerow(["Suspicious Activity"])
        csv_writer.writerow(["IP Address", "Failed Login Count"])
        csv_writer.writerows(suspicious_ips.items())

def main():
    # Parse the log file
    ip_counts, endpoint_counts, failed_logins = parse_log(LOG_FILE)

    # Generate output and display in terminal and save to CSV
    generate_output(ip_counts, endpoint_counts, failed_logins, FAILED_LOGIN_THRESHOLD)

if __name__ == "__main__":
    main()
