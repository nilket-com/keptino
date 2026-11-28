#!/usr/bin/env python3
"""Verify and install the release built by setup.sh. All private keys stay on the host."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import warnings

from adb_user import selected_user, user_id

PACKAGE = "com.keptino.app"
ANDROID = Path(__file__).resolve().parent
DIGEST = r"[0-9a-f]{64}"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def output(*args, password=None):
    return subprocess.run(args, input=password, stdout=subprocess.PIPE, check=True).stdout


def secret(label):
    fd = os.environ.get(f"KEPTINO_{label}_PASSWORD_FD")
    if fd is None:
        # getpass otherwise falls back to echoing stdin when no terminal exists.
        with open("/dev/tty", "w") as terminal, warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass(f"{label.title()} keystore password: ", stream=terminal).encode()
    else:
        with os.fdopen(os.dup(int(fd)), "rb") as stream:
            value = stream.readline().rstrip(b"\r\n")
    require(value and b"\n" not in value, "Expected a single nonempty keystore password.")
    return value + b"\n"


def key_digest(key, alias, password):
    keytool = Path(os.environ["JAVA_HOME"]) / "bin/keytool" if os.environ.get("JAVA_HOME") else "keytool"
    cert = output(keytool, "-exportcert", "-keystore", key, "-alias", alias,
                  "-storepass:file", "/dev/stdin", password=password)
    return hashlib.sha256(cert).hexdigest()


def manifest(apk, build_tools):
    info = output(build_tools / "aapt2", "dump", "badging", apk).decode()
    package = re.search(r"^package: name='([^']+)' versionCode='(\d+)'", info, re.M)
    require(package and package[1] == PACKAGE, f"Expected an APK for {PACKAGE}.")
    return int(package[2]), "application-debuggable" in info.splitlines()


def certificate(apk, signer, api):
    info = output(signer, "verify", "--min-sdk-version", api, "--max-sdk-version", api,
                  "--print-certs", apk).decode()
    digests = re.findall(rf"^Signer #\d+ certificate SHA-256 digest: ({DIGEST})$", info, re.M)
    require(len(digests) == 1, "Expected exactly one verified signer for the device API.")
    return digests[0]


def history(signer, path, expected, optional=False):
    result = subprocess.run([signer, "lineage", "--in", path, "--print-certs", "-v"],
                            capture_output=True, text=True)
    # The pinned Android build tools report absent lineage separately from a tool failure.
    if optional and result.returncode == 1 and "The provided APK does not contain a valid lineage." in result.stderr.splitlines():
        return None
    require(result.returncode == 0, f"Could not verify the signing lineage in {path.name}.")
    info = result.stdout
    pattern = rf"^Signer #\d+ in lineage certificate SHA-256 digest: ({DIGEST})$"
    signers = re.findall(pattern, info, re.M)
    require(len(signers) == 2 and signers[1] == expected and signers[0] != expected,
            "Expected a two-key lineage ending at the pinned release certificate.")
    old = info.split("Signer #2 in lineage certificate DN:", 1)[0]
    for cap in ("installed data", "shared UID", "rollback", "auth"):
        value = "true" if cap == "installed data" else "false"
        require(re.search(rf"^Has {cap} capability *: {value}$", old, re.M),
                f"Unexpected {cap} capability for the old signer.")
    permission = re.search(r"^Has permission capability *: (true|false)$", old, re.M)
    require(permission, "Missing old signer permission capability.")
    return signers[0], permission[1] == "true"


def installed(adb, user, destination):
    result = subprocess.run([*adb, "shell", "pm", "list", "packages", "-u", "--user", user, PACKAGE],
                            text=True, capture_output=True, check=True)
    require(not result.stderr.strip(), f"Could not enumerate packages for Android user {user}: {result.stderr.strip()}")
    packages = result.stdout.splitlines()
    require(all(line.startswith("package:") for line in packages), "Could not enumerate installed packages.")
    if f"package:{PACKAGE}" not in packages:
        return False
    paths = output(*adb, "shell", "pm", "path", "--user", user, PACKAGE).decode().splitlines()
    bases = [line.removeprefix("package:") for line in paths if line.startswith("package:/") and line.endswith("/base.apk")]
    require(len(bases) == 1, "Could not verify the installed base APK for the current Android user.")
    output(*adb, "pull", bases[0], destination)
    return True


def install(args, signing, temp):
    tools = args.sdk / "build-tools/36.0.0"
    signer = tools / "apksigner"
    adb = [args.sdk / "platform-tools/adb", "-s", args.serial]
    user = selected_user(adb, args.user)
    release = signing / "release.p12"
    require(release.is_file(), f"Set up and back up your release key first. See android/README.md ({release}).")
    pin = (signing / "release.sha256").read_text().strip().lower()
    require(re.fullmatch(DIGEST, pin), "release.sha256 must contain just the release certificate SHA-256 in hex.")
    api = output(*adb, "shell", "getprop", "ro.build.version.sdk").decode().strip()
    require(api.isdecimal() and int(api) >= 30, "Keptino requires Android API 30 or later for this install.")

    folder = ANDROID / "app/build/outputs/apk/release"
    apk = folder / "app-release-unsigned.apk"
    metadata = json.loads((folder / "output-metadata.json").read_text())
    version, debug = manifest(apk, tools)
    require(not debug and version > 0 and metadata["variantName"] == "release"
            and metadata["elements"][0]["versionCode"] == version, "Expected a non-debuggable release build.")
    base = temp / "base.apk"
    previous = None
    if installed(adb, user, base):
        current, was_debug = manifest(base, tools)
        require(version >= current, f"Refusing to downgrade installed version {current} to {version}.")
        previous = certificate(base, signer, api)
        require(previous == pin or was_debug, "Installed release has an unrelated signer.")

    lineage = signing / "release.lineage"
    saved = lineage.is_file()
    proof = temp / "release.lineage"
    ancestor = None
    if saved:
        shutil.copyfile(lineage, proof)
        ancestor, permission = history(signer, proof, pin)
        require(not permission, "The stored release lineage must revoke the old signer's permission capability.")
        require(previous in (None, pin, ancestor), "Installed signer is unrelated to the saved signing lineage.")
    if previous == pin:
        installed_history = history(signer, base, pin, optional=True)
        if installed_history:
            require(ancestor == installed_history[0], "Restore the original release.lineage backup before updating.")
    migrating = previous is not None and previous != pin
    if migrating:
        require(args.rotate_from, "Existing debug signer requires --rotate-from /path/to/original/debug.keystore.")
        require(args.rotate_from.is_file(), "Original debug keystore is missing. Installation stopped.")
    elif args.rotate_from:
        require(previous == pin and saved, "--rotate-from requires an existing debug install.")

    password = secret("RELEASE")
    require(key_digest(release, "keptino", password) == pin, "Release key differs from the pinned certificate.")
    transition = temp / "transition.lineage"
    if migrating:
        old_password = secret("OLD")
        require(key_digest(args.rotate_from, "androiddebugkey", old_password) == previous,
                "Old key does not match the installed certificate.")
        old_key = ["--ks", args.rotate_from, "--ks-key-alias", "androiddebugkey", "--ks-pass", "stdin"]
        if not saved:
            output(signer, "rotate", "--out", proof, "--old-signer", *old_key, "--set-installed-data", "true",
                   "--set-rollback", "false", "--set-auth", "false", "--set-permission", "false",
                   "--set-shared-uid", "false", "--new-signer", "--ks", release, "--ks-key-alias", "keptino",
                   "--ks-pass", "stdin", password=old_password + password)
            ancestor = previous
        # Android checks ownership of AndroidX's signature permission across the signer change.
        # Both APKs contain identical release code. Only the first grants that capability.
        output(signer, "lineage", "--in", proof, "--signer", *old_key, "--set-permission", "true",
               "--out", transition, password=old_password)

    def signed_apk(name, lineage_file, permission):
        signed = temp / name
        rotation = []
        if lineage_file:
            require(history(signer, lineage_file, pin) == (ancestor, permission), "Incorrect signing lineage or capabilities.")
            rotation = ["--lineage", lineage_file]
        # All supported API levels understand v3 and see the release signer.
        output(signer, "sign", "--rotation-min-sdk-version", "28", "--v1-signing-enabled", "false",
               "--v2-signing-enabled", "false", "--v4-signing-enabled", "false", *rotation,
               "--ks", release, "--ks-key-alias", "keptino", "--ks-pass", "stdin",
               "--out", signed, apk, password=password)
        require(certificate(signed, signer, api) == pin and manifest(signed, tools) == (version, False),
                "Signed APK failed signer, version or manifest verification.")
        if lineage_file:
            require(history(signer, signed, pin) == (ancestor, permission), "APK embeds a different signing lineage.")
        return signed

    final = signed_apk("release.apk", proof if ancestor else None, False)
    if migrating:
        first = signed_apk("transition.apk", transition, True)
        if not saved:
            os.link(proof, lineage)  # Never replace an existing operator backup.
            print(f"Back up the new signing lineage at {lineage}.", flush=True)
        print("Installing the release signer, then retiring the old signer's permission. "
              "If interrupted, rerun setup to finish.", flush=True)
        subprocess.run([*adb, "install", "-r", "--user", user, first], check=True)
    subprocess.run([*adb, "install", "-r", "--user", user, final], check=True)
    require(installed(adb, user, base) and certificate(base, signer, api) == pin and manifest(base, tools) == (version, False),
            "Android accepted the install but installed APK verification failed.")
    if ancestor:
        require(history(signer, base, pin) == (ancestor, False), "The installed APK did not retire the old signer.")
    print(f"Verified release version {version} on {args.serial} (API {api}, Android user {user}).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--user", type=user_id)
    parser.add_argument("--rotate-from", type=Path)
    args = parser.parse_args()
    signing = Path(os.environ.get("KEPTINO_SIGNING_DIR", "~/.config/keptino-signing")).expanduser().resolve()
    for path in [signing / "release.p12", signing / "release.sha256", signing / "release.lineage", args.rotate_from]:
        if path:
            require(not path.resolve().is_relative_to(ANDROID.parent), "Keep signing materials outside the checkout.")
    require(signing.is_dir(), f"Set up your signing directory at {signing} first. See android/README.md.")
    with tempfile.TemporaryDirectory(dir=signing) as directory:
        install(args, signing, Path(directory))


if __name__ == "__main__":
    try:
        main()
    except (OSError, EOFError, ValueError, KeyError, IndexError, getpass.GetPassWarning, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
