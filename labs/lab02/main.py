import argparse
from datetime import timedelta
from pathlib import Path

from labs.lab02.task1 import SESSION_TIMEOUT_SEC, Admin, User, UserAccount
from labs.lab02.task2 import analyze_arp_table


def run_demo():
    print("--- Demo OOP (Task 1) ---")
    user = User("alice", "alice@company.com", "user")
    user.set_password("SecurePass123!")

    admin = Admin(
        "bob_admin", "bob@company.com", permissions=["read_logs", "delete_users"]
    )
    admin.set_password("AdminPass456!")

    account = UserAccount(user)

    print("Attempting login with wrong password...")
    success = account.login("alice", "WrongPass!", "192.168.1.10")
    print(f"Login success: {success}")

    print("Attempting login with correct password...")
    success = account.login("alice", "SecurePass123!", "192.168.1.10")
    print(f"Login success: {success}")

    print(f"Is authenticated: {account.is_authenticated()}")

    print("Changing email via validation...")
    try:
        account["email"] = "alice_new@company.com"
        print(f"New email: {account['email']}")
    except ValueError as e:
        print(f"Error: {e}")

    print("Trying invalid email...")
    try:
        account["email"] = "invalid-email"
    except ValueError as e:
        print(f"Expected error caught: {e}")

    print("Admin permissions demo...")
    admin.grant_permission("manage_firewall")
    admin.revoke_permission("delete_users")
    print(f"Has 'manage_firewall': {admin.has_permission('manage_firewall')}")
    print(f"Has 'delete_users': {admin.has_permission('delete_users')}")
    print(f"Admin info: {admin}")

    print(f"Simulating inactivity longer than {SESSION_TIMEOUT_SEC} seconds...")
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print(f"Is authenticated after timeout: {account.is_authenticated()}")

    print("Logging in again and logging out...")
    account.login("alice", "SecurePass123!", "192.168.1.10")
    account.logout()
    print(f"Is authenticated after logout: {account.is_authenticated()}")

    print("Audit Log:")
    account.audit_log.show_all()


def main():
    parser = argparse.ArgumentParser(description="Lab 02 Cybersecurity Utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Demo command
    subparsers.add_parser("demo", help="Run OOP demo")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze ARP table")
    analyze_parser.add_argument(
        "--arp-file", type=Path, required=True, help="Path to ARP table CSV file"
    )
    analyze_parser.add_argument(
        "--output-json", type=Path, help="Path to output JSON report"
    )
    analyze_parser.add_argument(
        "--detect-spoofing", action="store_true", help="Enable ARP spoofing detection"
    )
    analyze_parser.add_argument("--log-file", type=Path, help="Path to log file")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        analyze_arp_table(
            file_path=args.arp_file,
            log_file=args.log_file,
            detect_spoofing=args.detect_spoofing,
            output_json=args.output_json,
        )


if __name__ == "__main__":
    main()
