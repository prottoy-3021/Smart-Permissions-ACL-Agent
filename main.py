
from permission_agent.parser import parse_request
from permission_agent.engine import execute_request


def main():
    print("Smart Permissions & ACL Agent")
    print("Type 'exit' to quit.")

    while True:
        text = input("\nDescribe the permission change: ").strip()

        if text.lower() == "exit":
            break

        try:
            request = parse_request(text)
            execute_request(request, apply=False)
        except (ValueError, RuntimeError) as error:
            print(f"Request rejected: {error}")


if __name__ == "__main__":
    main()
