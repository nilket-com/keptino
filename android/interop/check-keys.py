#!/usr/bin/env python3
"""Run the security-key JNI and rekey sync tests on a disposable emulator."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--apk-dir", type=Path, default=root / "android/app/build/outputs/apk")
parser.add_argument("--installed-keycheck", action="store_true",
                    help="use the isolated physical-test installation already on ANDROID_SERIAL")
args = parser.parse_args()
serial = os.environ["ANDROID_SERIAL"]
if not args.installed_keycheck and not serial.startswith("emulator-"):
    raise SystemExit("Select a disposable emulator through ANDROID_SERIAL")
adb = [str(Path(os.environ["ANDROID_HOME"]) / "platform-tools/adb"), "-s", serial]


@contextmanager
def peer(command):
    with subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, text=True) as process:
        port = None
        try:
            address = process.stdout.readline().strip()
            port = int(address.rsplit(":", 1)[-1])
            subprocess.run([*adb, "reverse", f"tcp:{port}", f"tcp:{port}"], check=True)
            yield port
        finally:
            process.terminate()
            if port is not None:
                subprocess.run([*adb, "reverse", "--remove", f"tcp:{port}"], check=False)


with tempfile.TemporaryDirectory() as bucket, \
        peer(["cargo", "run", "--quiet", "--locked", "-p", "droid", "--example", "fixture-key"]) as key, \
        peer([sys.executable, "android/interop/b2mock.py", "--dir", bucket, "--port", "0",
              "--key-id", "test-key-id", "--app-key", "test-app-key"]) as cloud:
    package = "com.keptino.app.keycheck" if args.installed_keycheck else "com.keptino.app"
    if not args.installed_keycheck:
        for apk in ("debug/app-debug.apk", "androidTest/debug/app-debug-androidTest.apk"):
            subprocess.run([*adb, "install", "-r", args.apk_dir / apk], check=True)
    result = subprocess.run([*adb, "shell", "am", "instrument", "-w", "-r", "-e", "port", str(key),
                             "-e", "mockBaseUrl", f"http://127.0.0.1:{cloud}", "-e", "class",
                             "com.keptino.app.SecurityKeyTest",
                             f"{package}.test/androidx.test.runner.AndroidJUnitRunner"],
                            capture_output=True, text=True, timeout=300, check=True)
    output = result.stdout + result.stderr
    print(output)
    if not re.search(r"OK \([1-9]\d* tests\)", output) or re.search(r"STATUS_CODE: -[1-4]", output):
        raise SystemExit("Security-key instrumentation failed or skipped tests")
