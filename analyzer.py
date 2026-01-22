from parser.auth_parser import parse_auth_log


def read_log(file_path):
    with open(file_path, "r") as file:
        return file.readlines()


def main():
    logs = read_log("logs/auth.log")

    events = []
    for line in logs:
        event = parse_auth_log(line)
        if event:
            events.append(event)

    for event in events:
        print(event)


if __name__ == "__main__":
    main()