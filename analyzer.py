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


def main():
    logs = load_logs("sample_logs.txt")

    parsed_logs = []
    for log in logs:
        parsed = parse_log_line(log)
        parsed_logs.append(parsed)

    print("Parsed logs:")
    for entry in parsed_logs:
        print(entry)


if __name__ == "__main__":
    main()
