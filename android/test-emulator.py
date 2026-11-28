#!/usr/bin/env python3
"""Run the real JNI/storage/B2 and production UI round trips on an emulator.
Requires a dedicated 64-bit emulator, built APKs and the committed Linux fixtures.
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
parser.add_argument('--device-pin', default='1234', metavar='PIN',
                    help='lock screen PIN to set on the dedicated emulator for the device credential tests (default 1234)')
parser.add_argument('--no-device-pin', action='store_true',
                    help='do not set a lock screen PIN; tests needing the credential prompt are skipped')
parser.add_argument('--argon2-4gib', action='store_true',
                    help='run the editor tests with the 4 GiB Argon2id fixture (requires a large emulator)')
args = parser.parse_args()
if args.argon2_4gib and args.no_device_pin:
    parser.error('--argon2-4gib needs the device PIN for the editor tests')
ui_fixture = 'linux-release.keptino' if args.argon2_4gib else 'linux-debug-unmarked.keptino'
ui_profile = 'release' if args.argon2_4gib else 'debug'
if not args.no_device_pin and not (args.device_pin.isdigit() and 4 <= len(args.device_pin) <= 16):
    parser.error('--device-pin must be 4 to 16 digits')
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

def shell(*cmd, check=True):
    return subprocess.run([adb, '-s', args.serial, 'shell', *cmd], check=check, capture_output=True, text=True, timeout=60)

def set_device_pin(pin):
    """A secure lock screen is required for a Keystore key bound to the device credential.
    The emulator must have no credential yet: this script owns the dedicated AVD's lock."""
    shell('input', 'keyevent', 'KEYCODE_WAKEUP')
    shell('wm', 'dismiss-keyguard', check=False)
    # SystemUI can still own the lock screen immediately after boot completes.
    # Leave it before setting the PIN so the activity can receive its own prompt.
    for _ in range(40):
        if re.search(r'^\s*(?:showing|mIsShowing)=false\s*$', shell('dumpsys', 'window', 'policy').stdout, re.M):
            break
        time.sleep(.5)
    else:
        raise RuntimeError('Unlock the dedicated emulator before starting the credential tests.')
    shell('svc', 'power', 'stayon', 'true')
    shell('settings', 'put', 'system', 'screen_off_timeout', '1800000')
    result = shell('locksettings', 'set-pin', pin, check=False)
    if result.returncode or 'error' in (result.stdout + result.stderr).lower():
        raise RuntimeError('Could not set the emulator lock screen PIN; the AVD must have no credential of its own, '
                           'or clear it first:\n' + result.stdout + result.stderr)
    print('Set emulator lock screen PIN for the device credential tests', flush=True)

def clear_device_pin(pin):
    result = shell('locksettings', 'clear', '--old', pin, check=False)
    shell('svc', 'power', 'stayon', 'false', check=False)
    if result.returncode:
        print('Warning: could not clear the emulator lock screen PIN: ' + result.stdout + result.stderr, file=sys.stderr)

def instrument(label, test_class, values):
    command = ['am', 'instrument', '-w', '-r', '-e', 'class', test_class]
    for key, value in values.items():
        command.extend(['-e', key, str(value)])
    if device_pin: command.extend(['-e', 'devicePin', device_pin])
    command.append('com.keptino.app.test/androidx.test.runner.AndroidJUnitRunner')
    output = subprocess.run([adb, '-s', args.serial, 'shell', shlex.join(command)], capture_output=True, text=True, timeout=900)
    text = output.stdout + output.stderr
    (report / (label + '.log')).write_text(text)
    # -1 error, -2 failure. -3 (ignored) and -4 (assumption failed) are skips: tests that need the
    # device credential prompt skip without a PIN.
    if output.returncode or re.search(r'INSTRUMENTATION_STATUS_CODE: -[12]\b', text) or not re.search(r'OK \(\d+ tests?', text):
        print(text[-12000:]); raise RuntimeError(label + ' failed; see report log')
    skipped = len(re.findall(r'INSTRUMENTATION_STATUS_CODE: -[34]\b', text))
    if device_pin and skipped:
        raise RuntimeError(f'{label} unexpectedly skipped {skipped} tests; see report log')
    print(label + ': passed' + (f' ({skipped} skipped: no device PIN)' if skipped else ''), flush=True)

def collect(remote, local):
    result = subprocess.run([adb, '-s', args.serial, 'exec-out', 'run-as', 'com.keptino.app', 'cat', 'files/' + remote], check=True, capture_output=True)
    (report / local).write_bytes(result.stdout)

for apk in ['app/build/outputs/apk/debug/app-debug.apk', 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk']:
    call(adb, '-s', args.serial, 'install', '-r', str(root / apk))
device_pin = None if args.no_device_pin else args.device_pin
if device_pin: set_device_pin(device_pin)
try:
  with tempfile.TemporaryDirectory(prefix='keptino-b2-test-') as directory:
      with socket.socket() as sock:
          sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
      with (report / 'b2mock.log').open('w') as log:
          mock = subprocess.Popen([sys.executable, str(root / 'interop/b2mock.py'), '--dir', directory, '--bucket-name', 'mobile-interop-bucket', '--port', str(port), '--key-id', 'test-key-id', '--app-key', 'test-app-key'], stdout=log, stderr=log)
          try:
              for _ in range(100):
                  if mock.poll() is not None: raise RuntimeError('B2 mock exited')
                  try:
                      with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                  except OSError: time.sleep(.05)
              else: raise RuntimeError('B2 mock did not start')
              call(adb, '-s', args.serial, 'reverse', f'tcp:{port}', f'tcp:{port}')
              common = {'password': manifest['password'], 'pepperHex': manifest['pepper_hex'], 'entry': 'bank'}
              # The signing rehearsal spans APK installs and has its own runner.
              native_tests = 'com.keptino.app.VaultIntegrationTest'
              instrument('native-debug-and-b2', native_tests, dict(common, fixture='linux-debug.keptino',
                         dbName='vaultdebug', memoryKib=4096, mockBaseUrl=f'http://127.0.0.1:{port}',
                         notClass=native_tests + '#signingUpdateKeepsVaultAndSettings'))
              collect('android-roundtrip.keptino', 'android-debug-roundtrip.keptino')
              for form, label in [('v2', 'format-2'), ('unmarked', 'unmarked')]:
                  instrument('native-' + label, 'com.keptino.app.VaultIntegrationTest#linuxFixtureEditAndExport',
                             dict(common, fixture=f'linux-debug-{form}.keptino', dbName=f'vaultdebug-{form}', memoryKib=8192))
                  collect('android-roundtrip.keptino', f'android-{label}-roundtrip.keptino')
              if device_pin is None:
                  print('No device PIN: the production UI runs need the credential prompt and are skipped', flush=True)
              else:
                  # Each run starts from revision 1. Use fresh local names so a
                  # prior run's trusted revision survives and cannot mask a regression.
                  run_id = Path(directory).name
                  local_name = run_id + '-local'
                  remote_name = run_id + '-remote'
                  instrument('generate-and-delete', 'com.keptino.app.VaultUiTest#generateRevertAndConfirmDelete', common)
                  instrument('screen-off', 'com.keptino.app.VaultUiTest#screenOffLocksVaultUnlessDisabled', {})
                  instrument('health-report', 'com.keptino.app.VaultUiTest#healthReportUsesSetEntriesAndClosesOnLock', {})
                  instrument('credential-cancel', 'com.keptino.app.VaultUiTest#cancelledCredentialPromptKeepsVaultLocked', {})
                  instrument('production-ui', 'com.keptino.app.VaultUiTest#productionLinuxVaultCanBeEditedAndSavedThroughUi', dict(common, uiFixture=ui_fixture, dbName=local_name))
                  collect('android-ui-roundtrip.keptino', 'android-ui-roundtrip.keptino')
                  (Path(directory) / (remote_name + '.keptino')).write_bytes(base64.b64encode((root / 'droid/tests/fixtures' / ui_fixture).read_bytes()))
                  instrument('production-ui-b2', 'com.keptino.app.VaultUiTest#productionLinuxVaultCanBeEditedAndSavedThroughUi', dict(common, uiFixture=ui_fixture, dbName=remote_name, mockBaseUrl=f'http://127.0.0.1:{port}'))
                  (report / 'android-b2-roundtrip.keptino').write_bytes(base64.b64decode((Path(directory) / (remote_name + '.keptino')).read_bytes(), validate=True))
          finally:
              subprocess.run([adb, '-s', args.serial, 'reverse', '--remove', f'tcp:{port}'], check=False)
              mock.terminate()
              try: mock.wait(timeout=5)
              except subprocess.TimeoutExpired: mock.kill(); mock.wait()
finally:
    if device_pin: clear_device_pin(device_pin)
print('Android output files: ' + str(report))
outputs = [('android-debug-roundtrip.keptino', 'debug'), ('android-format-2-roundtrip.keptino', 'debug'), ('android-unmarked-roundtrip.keptino', 'debug')]
if device_pin: outputs += [('android-ui-roundtrip.keptino', ui_profile), ('android-b2-roundtrip.keptino', ui_profile)]
for filename, profile in outputs:
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
