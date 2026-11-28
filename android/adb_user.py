"""Select one Android user for an entire setup operation."""
import argparse
import re
import subprocess


def user_id(value):
    if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > 2147483647:
        raise ValueError("Expected a numeric Android user ID.")
    return str(int(value))


def selected_user(adb, user):
    if user is None:
        user = subprocess.check_output([*adb, "shell", "am", "get-current-user"], text=True).strip()
    return user_id(user)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("adb")
    parser.add_argument("serial")
    parser.add_argument("--user", type=user_id)
    args = parser.parse_args()
    try:
        print(selected_user([args.adb, "-s", args.serial], args.user))
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")
