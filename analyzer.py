def load_logs(file_path):
    with open(file_path, "r") as file:
        return file.readlines()


def parse_log_line(line):
    parts = line.strip().split()

    timestamp = f"{parts[0]} {parts[1]}"
    level = parts[2]

    if "Failed login attempt" in line:
        event = "failed_login"
        user = parts[8]          # admin / root
        ip = parts[-1]
    elif "logged in" in line:
        event = "login_success"
        user = parts[4]
        ip = parts[-1]
    else:
        event = "unknown"
        user = None
        ip = None

    return {
        "timestamp": timestamp,
        "level": level,
        "event": event,
        "user": user,
        "ip": ip
    }
def detect_bruteforce(parsed_logs, threshold=3):
    failed_counts = {}

    for log in parsed_logs:
        if log["event"] == "failed_login":
            ip = log["ip"]
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    alerts = []
    for ip, count in failed_counts.items():
        if count >= threshold:
            alerts.append({
                "ip": ip,
                "failed_attempts": count
            })

    return alerts



def main():
    logs = load_logs("sample_logs.txt")

    parsed_logs = []
    for log in logs:
        parsed = parse_log_line(log)
        parsed_logs.append(parsed)

    print("Parsed logs:")
    for entry in parsed_logs:
        print(entry)

    alerts = detect_bruteforce(parsed_logs)

    print("\nSecurity alerts:")
    if not alerts:
        print("No suspicious activity detected.")
    else:
        for alert in alerts:
            print(
                f"ALERT: Possible brute-force attack from {alert['ip']} "
                f"({alert['failed_attempts']} failed attempts)"
            )



if __name__ == "__main__":
    main()
