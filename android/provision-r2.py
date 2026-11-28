#!/usr/bin/env python3
"""Stream Linux Keptino setup to an authorized phone waiting in the R2 import screen."""
from pathlib import Path
import argparse
import secrets
import subprocess
import sys
import time

from adb_user import selected_user, user_id

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--user", type=user_id)
    args = parser.parse_args()
    adb = [args.adb, "-s", args.serial]
    app = "com.keptino.app"
    user = selected_user(adb, args.user)
    remote = ["run-as", app, "--user", user]
    directory = Path.home() / ".config/keptino"
    for key in ("pepper", "r2"):
        if not (directory / (key + ".cred")).is_file():
            sys.exit("Missing Linux credential: " + key + ".cred")
    subprocess.run([*adb, "shell", *remote, "true"], check=True)
    subprocess.run([*adb, "shell", "am", "start", "--user", user, "--activity-single-top", "-a", app + ".IMPORT_R2", "-n", app + "/.MainActivity"], check=True)
    print("Unlock your phone and tap Receive setup in Keptino. If a vault is open, save your edits and lock it first.", flush=True)
    pipe = "cache/r2-setup.pipe"
    deadline = time.monotonic() + 900
    while subprocess.run([*adb, "shell", *remote, "test", "-p", pipe], stdout=subprocess.DEVNULL).returncode:
        if time.monotonic() >= deadline:
            sys.exit("The phone did not open the setup pipe. No credentials were sent.")
        time.sleep(0.5)

    def credential(name):
        return subprocess.run(["/usr/bin/systemd-creds", "decrypt", "--user", "--name=" + name,
                               directory / (name + ".cred"), "-"], stdout=subprocess.PIPE, check=True).stdout

    pepper = credential("pepper").strip()
    r2 = credential("r2")
    if len(pepper) != 64 or any(ch not in b"0123456789abcdefABCDEF" for ch in pepper) or len(r2.split(b"\0")) != 4:
        sys.exit("Invalid Linux Keptino settings.")
    token = secrets.token_hex(16).encode("ascii")
    payload = b"KPR2\0" + pepper + b"\0" + r2 + b"\0" + token + b"\0"
    if len(payload) > 4096:
        sys.exit("Linux setup exceeds the transfer limit.")
    # nocreat prevents a regular file if the app cancels and unlinks its FIFO.
    subprocess.run([*adb, "shell", "-T", *remote, "dd", "of=" + pipe, "conv=nocreat,notrunc", "status=none"],
                   input=len(payload).to_bytes(4, "big") + payload, check=True, timeout=15)
    del payload, r2, pepper
    print("Approve the settings save on the phone after the R2 read check.", flush=True)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        receipt = subprocess.run([*adb, "shell", *remote, "cat", "cache/r2-setup.result"],
                                 capture_output=True).stdout.strip().split()
        if len(receipt) == 2 and receipt[0] == token:
            if receipt[1] == b"failed":
                sys.exit("Setup did not complete. See the message on the phone.")
            if receipt[1] in (b"found", b"empty"):
                print("Phone authenticated and saved R2 setup. " +
                      ("The vault object was found." if receipt[1] == b"found" else "No object exists under the selected vault name."))
                return
        time.sleep(0.5)
    sys.exit("No confirmation received from the phone. Check its setup status.")

if __name__ == "__main__":
    main()
