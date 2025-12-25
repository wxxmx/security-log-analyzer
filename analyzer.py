def load_logs(file_path):
    with open(file_path, "r") as file:
        return file.readlines()


def main():
    logs = load_logs("sample_logs.txt")
    print("Loaded logs:")
    for log in logs:
        print(log.strip())


if __name__ == "__main__":
    main()

