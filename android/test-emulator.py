#!/usr/bin/env python3
"""Run the real JNI/storage/B2 and production UI round trips on an emulator.
Requires a running 64-bit emulator with >=8 GiB RAM, built APKs and Linux fixtures.
Writes the Android-produced vaults and instrumentation logs to build/reports/interop.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial', required=True, help='adb emulator serial')
args = parser.parse_args()
adb = str(Path(os.environ.get('ANDROID_HOME', Path.home() / 'Android/Sdk')) / 'platform-tools/adb')
for _ in range(120):
    boot = subprocess.run([adb, '-s', args.serial, 'shell', 'getprop', 'sys.boot_completed'], capture_output=True, text=True)
    if boot.returncode == 0 and boot.stdout.strip() == '1': break
    time.sleep(1)
else: raise RuntimeError('Emulator did not finish booting')
avd = subprocess.run([adb, '-s', args.serial, 'emu', 'avd', 'name'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
metadata = Path.home() / '.android' / 'avd' / (avd + '.ini')
if metadata.exists() and 'target=android-0' in metadata.read_text():
    raise RuntimeError('Invalid emulator target: recreate this AVD using Android command-line tools 23.0')
manifest = json.loads((root / 'droid/tests/fixtures/manifest.json').read_text())
report = root / 'build/reports/interop'
report.mkdir(parents=True, exist_ok=True)

def call(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)

def instrument(label, test_class, values):
    command = ['am', 'instrument', '-w', '-r', '-e', 'class', test_class]
    for key, value in values.items():
        command.extend(['-e', key, str(value)])
    command.append('com.digisafe.app.test/androidx.test.runner.AndroidJUnitRunner')
    output = subprocess.run([adb, '-s', args.serial, 'shell', shlex.join(command)], capture_output=True, text=True, timeout=360)
    text = output.stdout + output.stderr
    (report / (label + '.log')).write_text(text)
    if output.returncode or re.search(r'INSTRUMENTATION_STATUS_CODE: -[1234]', text) or not re.search(r'OK \(\d+ tests?\)', text):
        print(text[-12000:]); raise RuntimeError(label + ' failed; see report log')
    print(label + ': passed', flush=True)

def collect(remote, local):
    result = subprocess.run([adb, '-s', args.serial, 'exec-out', 'run-as', 'com.digisafe.app', 'cat', 'files/' + remote], check=True, capture_output=True)
    (report / local).write_bytes(result.stdout)

for apk in ['app/build/outputs/apk/debug/app-debug.apk', 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk']:
    call(adb, '-s', args.serial, 'install', '-r', str(root / apk))
with tempfile.TemporaryDirectory(prefix='digisafe-b2-test-') as directory:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    with (report / 'b2mock.log').open('w') as log:
        mock = subprocess.Popen([sys.executable, str(root / 'interop/b2mock.py'), '--dir', directory, '--port', str(port), '--key-id', 'test-key-id', '--app-key', 'test-app-key'], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if mock.poll() is not None: raise RuntimeError('B2 mock exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.05)
            else: raise RuntimeError('B2 mock did not start')
            call(adb, '-s', args.serial, 'reverse', f'tcp:{port}', f'tcp:{port}')
            common = {'password': manifest['password'], 'pepperHex': manifest['pepper_hex'], 'entry': 'bank'}
            instrument('native-debug-and-b2', 'com.digisafe.app.VaultIntegrationTest', dict(common, fixture='linux-debug.digisafe', dbName='vaultdebug', memoryKib=4096, mockBaseUrl=f'http://127.0.0.1:{port}'))
            collect('android-roundtrip.digisafe', 'android-debug-roundtrip.digisafe')
            instrument('production-ui', 'com.digisafe.app.VaultUiTest', dict(common, uiFixture='linux-release.digisafe', dbName='vaultrelease'))
            collect('android-ui-roundtrip.digisafe', 'android-ui-roundtrip.digisafe')
            (Path(directory) / 'vaultrelease.digisafe').write_bytes(base64.b64encode((root / 'droid/tests/fixtures/linux-release.digisafe').read_bytes()))
            instrument('production-ui-b2', 'com.digisafe.app.VaultUiTest', dict(common, uiFixture='linux-release.digisafe', dbName='vaultrelease', mockBaseUrl=f'http://127.0.0.1:{port}'))
            (report / 'android-b2-roundtrip.digisafe').write_bytes(base64.b64decode((Path(directory) / 'vaultrelease.digisafe').read_bytes(), validate=True))
        finally:
            subprocess.run([adb, '-s', args.serial, 'reverse', '--remove', f'tcp:{port}'], check=False)
            mock.terminate()
            try: mock.wait(timeout=5)
            except subprocess.TimeoutExpired: mock.kill(); mock.wait()
print('Android output files: ' + str(report))
for filename, profile in [('android-debug-roundtrip.digisafe', 'debug'), ('android-ui-roundtrip.digisafe', 'release'), ('android-b2-roundtrip.digisafe', 'release')]:
    result = subprocess.run([str(root / 'interop/run.sh'), 'check', str(report / filename), profile], cwd=root, capture_output=True, text=True, check=True, timeout=360)
    (report / (filename + '.linux.log')).write_text(result.stdout + result.stderr)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('[{')]
    if not rows: raise RuntimeError('Linux did not report entries for ' + filename)
    expected = {entry['name']: dict(entry) for entry in manifest['entries']}
    expected['bank']['password'] = 'android-edited-password 🔑'
    actual = {entry['name']: entry for entry in rows[-1]}
    if actual != expected: raise RuntimeError('Linux read-back mismatch: ' + filename)
    print('Linux verified ' + filename, flush=True)
print('Full Android/Linux compatibility checks passed.')
