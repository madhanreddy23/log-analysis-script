import random
import time

def generate_large_log(file_name, num_entries=100000):
    ips = [
        "192.168.1.1", "203.0.113.5", "10.0.0.2", 
        "198.51.100.23", "192.168.1.100", "10.0.0.5", 
        "203.0.113.10", "192.168.1.15", "198.51.100.30"
    ]
    endpoints = ["/home", "/login", "/about", "/contact", "/register", "/dashboard", "/profile", "/feedback"]
    status_codes = ["200", "401", "404", "500", "403"]
    response_sizes = ["128", "256", "512", "1024", "2048"]
    failure_message = ["", "Invalid credentials"]

    with open(file_name, 'w') as file:
        for _ in range(num_entries):
            ip = random.choice(ips)
            endpoint = random.choice(endpoints)
            status = random.choice(status_codes)
            response_size = random.choice(response_sizes)
            fail_msg = random.choice(failure_message) if status == "401" else ""
            timestamp = time.strftime("[%d/%b/%Y:%H:%M:%S +0000]", time.gmtime(random.randint(1609459200, 1672531199)))
            log_line = f"{ip} - - {timestamp} \"GET {endpoint} HTTP/1.1\" {status} {response_size} {fail_msg}\n"
            file.write(log_line)

# Generate a large log file with 100,000 entries
generate_large_log("sample.log", num_entries=100000)
