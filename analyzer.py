from datetime import datetime

def load_logs(file_path):
    with open(file_path, "r") as file:
        return file.readlines()


def parse_log_line(line):
    parts = line.strip().split()

    timestamp_str = f"{parts[0]} {parts[1]}"
    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
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

def detect_bruteforce_time_window(parsed_logs, threshold=3, window_seconds=30):
    failed_by_ip = {}

    for log in parsed_logs:
        if log["event"] == "failed_login":
            ip = log["ip"]
            failed_by_ip.setdefault(ip, []).append(log["timestamp"])

    alerts = []

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()

        for i in range(len(timestamps) - threshold + 1):
            start = timestamps[i]
            end = timestamps[i + threshold - 1]

            if (end - start).total_seconds() <= window_seconds:
                alerts.append({
                    "ip": ip,
                    "failed_attempts": threshold,
                    "time_window": window_seconds
                })
                break

    return alerts




def main():
    logs = load_logs("sample_logs.txt")

    parsed_logs = []
    for log in logs:
        parsed_logs.append(parse_log_line(log))

    alerts = detect_bruteforce_time_window(parsed_logs)

    print("=== Security Log Analyzer ===")

    if not alerts:
        print("No suspicious activity detected.")
    else:
        print("\nSecurity Alerts:")
        for alert in alerts:
            print(
                f"- Possible brute-force attack detected\n"
                f"  Source IP: {alert['ip']}\n"
                f"  Failed Attempts: {alert['failed_attempts']}\n"
                f"  Time Window: {alert['time_window']} seconds\n"
            )




if __name__ == "__main__":
    main()
