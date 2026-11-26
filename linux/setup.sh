#!/bin/bash
set -Eeuo pipefail
umask 077

trap 'printf "DigiSafe setup failed at line %s. Fix the error above and rerun setup.\n" "$LINENO" >&2' ERR

# Resolve assets and Cargo.toml relative to this script, regardless of the caller's cwd.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if (( EUID == 0 )); then
    printf "Run setup as your normal user; sudo is used only to install packages.\n" >&2
    exit 1
fi

# Remote storage providers for vault sync. The active one is named in
# ~/.config/digisafe/storage-provider (identifier plus newline); an absent file
# means the legacy Backblaze configuration. Each provider keeps its own
# <provider>.cred, encrypted by systemd-creds --user --name=<provider>.
#   backblaze: key name, key ID, application key          (3 NUL-separated fields)
#   aws:       bucket, region, access key ID, secret        (4 NUL-separated fields)
#   gcs:       bucket, location, HMAC access ID, HMAC secret
#   r2:        bucket, account ID (32 hex), access key ID, secret
providers=(backblaze aws gcs r2)
provider_file_name=storage-provider

usage() {
    printf 'Usage: %s [--reset-backblaze|--restore-pepper|--configure-storage PROVIDER]\n' "$0"
    printf 'PROVIDER is one of: backblaze (default), aws, gcs, r2\n'
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

is_provider() {
    local candidate=$1 provider
    for provider in "${providers[@]}"; do
        [[ $candidate == "$provider" ]] && return 0
    done
    return 1
}

provider_label() {
    case $1 in
        backblaze) printf 'Backblaze B2' ;;
        aws) printf 'AWS S3' ;;
        gcs) printf 'Google Cloud Storage' ;;
        r2) printf 'Cloudflare R2' ;;
    esac
}

provider_hint() {
    case $1 in
        backblaze) printf 'Use an application key restricted to the vault bucket.\n' ;;
        aws) printf 'Use an IAM access key pair granted s3:GetObject and s3:PutObject on vault objects and s3:ListBucket on the bucket, so a first unlock can tell a missing vault from denied access.\n' ;;
        gcs) printf 'Use an HMAC key for a service account with Storage Object User (roles/storage.objectUser) on a Standard bucket; enter its location, e.g. us-central1.\n' ;;
        r2) printf 'Use an Object Read & Write API token scoped to a Standard bucket in the default jurisdiction; the account ID is on the R2 overview page.\n' ;;
    esac
}

# Prompt for one credential field into the named variable. The value only ever
# lives in this shell's memory: it is never passed as an argument to an external
# process and never written to a plaintext file. Non-secret fields are echoed
# and trimmed; secrets are neither. Cancelled or empty input aborts without
# changing anything.
ask_echo_supported() {
    if [[ -z ${ask_echo_supported:-} ]]; then
        # -e/--echo has shipped since systemd 231; older releases fall back to hidden input.
        if systemd-ask-password --help 2>/dev/null | grep -q -- '--echo'; then
            ask_echo_supported=yes
        else
            ask_echo_supported=no
        fi
    fi
    [[ $ask_echo_supported == yes ]]
}

ask_field() {
    local -n __ask_target=$1
    local __ask_prompt=$2 __ask_echo=${3:-no} __ask_value
    local -a __ask_opts=(-n)
    if [[ $__ask_echo == yes ]] && ask_echo_supported; then
        __ask_opts+=(-e)
    fi
    if ! __ask_value=$(systemd-ask-password "${__ask_opts[@]}" "$__ask_prompt"); then
        fail 'Credential entry cancelled; nothing was changed.'
    fi
    if [[ $__ask_echo == yes ]]; then
        __ask_value=${__ask_value#"${__ask_value%%[![:space:]]*}"}
        __ask_value=${__ask_value%"${__ask_value##*[![:space:]]}"}
    fi
    if [[ -z $__ask_value ]]; then
        fail "Empty value for '${__ask_prompt%:}'; nothing was changed."
    fi
    __ask_target=$__ask_value
}

# Regions and locations are only ever used to build a hostname, so accept any
# single DNS label rather than a list of known regions that would age badly.
validate_dns_label() {
    local what=$1 value=$2 example=$3
    if [[ ! $value =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        fail "Invalid $what '$value': expected lowercase letters, digits and hyphens, such as $example."
    fi
}

validate_bucket() {
    local provider=$1 bucket=$2 pattern
    case $provider in
        aws) pattern='^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' ;;
        r2)  pattern='^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' ;;
        gcs) pattern='^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$' ;;
    esac
    if [[ ! $bucket =~ $pattern || $bucket == *..* || $bucket =~ [^.]{64} ]]; then
        fail "Invalid bucket name for $(provider_label "$provider"). Enter the name of an existing bucket."
    fi
}

# Encrypt stdin as <name>.cred in the temp dir. Nothing in the config dir
# changes until the caller moves the finished file into place.
encrypt_credential() {
    local name=$1
    systemd-creds encrypt --user --name="$name" - "$temp_dir/$name.cred"
    chmod 600 -- "$temp_dir/$name.cred"
}

provision_backblaze() {
    printf "Provisioning Backblaze API Bundle...\n"
    provider_hint backblaze
    local key_name key_id app_key
    ask_field key_name "Enter API Key Name:" yes
    ask_field key_id "Enter API Key ID:"
    ask_field app_key "Enter App Secret Key:"
    printf '%s\0%s\0%s' "$key_name" "$key_id" "$app_key" | encrypt_credential backblaze
    unset key_name key_id app_key
    mv -- "$temp_dir/backblaze.cred" "$config_dir/backblaze.cred"
}

provision_object_store() {
    local provider=$1 bucket location key_id secret
    printf 'Provisioning %s credentials...\n' "$(provider_label "$provider")"
    provider_hint "$provider"
    ask_field bucket "Enter bucket name:" yes
    validate_bucket "$provider" "$bucket"
    case $provider in
        aws)
            ask_field location "Enter AWS region (e.g. us-east-1):" yes
            validate_dns_label 'AWS region' "$location" 'us-east-1 or eu-central-1'
            ;;
        gcs)
            ask_field location "Enter bucket location (e.g. us-central1 or us):" yes
            validate_dns_label 'bucket location' "$location" 'us-central1, europe-west1 or us'
            ;;
        r2)
            ask_field location "Enter Cloudflare account ID (32 hex characters):" yes
            location=${location,,}
            if [[ ! $location =~ ^[0-9a-f]{32}$ ]]; then
                fail "Invalid Cloudflare account ID: expected exactly 32 hexadecimal characters."
            fi
            ;;
    esac
    ask_field key_id "Enter access key ID:"
    ask_field secret "Enter secret access key:"
    printf '%s\0%s\0%s\0%s' "$bucket" "$location" "$key_id" "$secret" | encrypt_credential "$provider"
    unset key_id secret
    mv -- "$temp_dir/$provider.cred" "$config_dir/$provider.cred"
}

provision_provider() {
    case $1 in
        backblaze) provision_backblaze ;;
        aws|gcs|r2) provision_object_store "$1" ;;
        *) fail "Unknown storage provider: $1" ;;
    esac
}

# Atomically record the active provider. Call only after its credential is in place.
select_storage_provider() {
    local provider=$1
    printf '%s\n' "$provider" > "$temp_dir/$provider_file_name"
    chmod 600 -- "$temp_dir/$provider_file_name"
    mv -- "$temp_dir/$provider_file_name" "$config_dir/$provider_file_name"
}

# Sets active_provider from the provider file; absent means legacy Backblaze.
read_storage_provider() {
    local file="$config_dir/$provider_file_name"
    if [[ ! -e $file ]]; then
        active_provider=backblaze
        return
    fi
    active_provider=$(<"$file")
    if ! is_provider "$active_provider"; then
        fail "Invalid storage provider in $file: '$active_provider'. Expected one of: ${providers[*]}. Run $0 --configure-storage PROVIDER to repair it."
    fi
}

# Sets selected_provider interactively; empty input keeps the Backblaze default.
choose_provider() {
    local choice
    printf 'Choose the remote storage used to sync the vault:\n'
    printf '  1) Backblaze B2 (default)\n  2) AWS S3\n  3) Google Cloud Storage\n  4) Cloudflare R2\n'
    read -r -p 'Provider [1-4 or name, default 1]: ' choice || choice=''
    case ${choice,,} in
        ''|1|backblaze|b2) selected_provider=backblaze ;;
        2|aws|s3) selected_provider=aws ;;
        3|gcs|gcp|google) selected_provider=gcs ;;
        4|r2|cloudflare) selected_provider=r2 ;;
        *) fail "Unknown storage provider '$choice'. Expected one of: ${providers[*]}." ;;
    esac
}

provision_pepper() {
    printf 'Deriving pepper from your original seed (requires 4 GiB of memory)...\n'
    systemd-ask-password -n "Enter original pepper seed:" | \
        argon2 digipepper -id -t 4 -m 22 -p 1 -l 32 -r -v 13 | \
        systemd-creds encrypt --user --name=digipepper - "$temp_dir/digipepper.cred"
    local pepper
    pepper=$(systemd-creds decrypt --user --name=digipepper "$temp_dir/digipepper.cred" -)
    if [[ ! "$pepper" =~ ^[[:xdigit:]]{64}$ ]]; then
        unset pepper
        printf 'Generated pepper is invalid; existing credential was preserved.\n' >&2
        exit 1
    fi
    unset pepper
    chmod 600 -- "$temp_dir/digipepper.cred"
    if [[ -e "$config_dir/digipepper.cred" ]]; then
        local backup
        backup=$(mktemp "$config_dir/digipepper.cred.backup.XXXXXXXX")
        cp -- "$config_dir/digipepper.cred" "$backup"
        printf 'Previous encrypted pepper saved to %s\n' "$backup"
    fi
    mv -- "$temp_dir/digipepper.cred" "$config_dir/digipepper.cred"
}

prepare_config_dir() {
    config_dir="$HOME/.config/digisafe"
    mkdir -p -- "$config_dir"
    chmod 700 -- "$config_dir"
    temp_dir=$(mktemp -d "$config_dir/.setup.XXXXXXXX")
    trap 'rm -rf -- "$temp_dir"' EXIT
}

require_credential_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null
    done
}

# Exercise user-scoped encryption before requesting any real secrets.
check_credential_encryption() {
    printf 'digisafe-setup-check' | systemd-creds encrypt --user --name=setup-check - "$temp_dir/check.cred"
    systemd-creds decrypt --user --name=setup-check "$temp_dir/check.cred" /dev/null
}

case "${1:-}" in
    --reset-backblaze|--restore-pepper)
        [[ $# == 1 ]] || { usage >&2; exit 2; }
        ;;
    --configure-storage)
        [[ $# == 2 ]] || { usage >&2; exit 2; }
        if ! is_provider "$2"; then
            printf "Unknown storage provider '%s'.\n" "$2" >&2
            usage >&2
            exit 2
        fi
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    '') ;;
    *) usage >&2; exit 2 ;;
esac

if [[ -n "${1:-}" ]]; then
    prepare_config_dir
    case "$1" in
        --restore-pepper)
            require_credential_tools argon2 systemd-creds systemd-ask-password
            provision_pepper
            printf 'Pepper credential restored. Try opening your existing vault.\n'
            ;;
        --reset-backblaze)
            require_credential_tools systemd-creds systemd-ask-password
            provision_backblaze
            read_storage_provider
            printf 'Backblaze credentials updated. Pepper unchanged.\n'
            if [[ $active_provider != backblaze ]]; then
                printf 'Vault sync still uses %s. Run %s --configure-storage backblaze to switch.\n' \
                    "$(provider_label "$active_provider")" "$0"
            fi
            ;;
        --configure-storage)
            require_credential_tools systemd-creds systemd-ask-password
            check_credential_encryption
            provision_provider "$2"
            select_storage_provider "$2"
            printf '%s credentials saved; vault sync now uses %s. Pepper unchanged.\n' \
                "$(provider_label "$2")" "$(provider_label "$2")"
            ;;
    esac
    exit 0
fi

printf "Checking DigiSafe dependencies...\n"
for tool in cargo rustc sudo apt-get dpkg-query; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf "Missing %s. Setup requires Debian/Ubuntu, sudo, and a working Rust toolchain.\n" "$tool" >&2
        exit 1
    fi
done
cargo --version
rustc --version

packages=(build-essential pkg-config dpkg-dev argon2 systemd libcap2-bin libwayland-dev libxkbcommon-dev)
missing=()
for package in "${packages[@]}"; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        missing+=("$package")
    fi
done
if (( ${#missing[@]} )); then
    sudo apt-get update
    sudo apt-get install -y "${missing[@]}"
fi
if ! cargo deb --version >/dev/null 2>&1; then
    # --force: cargo skips a crate it has on record even when the binary is broken.
    cargo install cargo-deb --locked --force
    cargo deb --version >/dev/null
fi
require_credential_tools argon2 systemd-creds systemd-ask-password
pkg-config --exists wayland-client xkbcommon

prepare_config_dir
check_credential_encryption

# Returns 0 when <name>.cred decrypts and has the expected field count; the
# plaintext only ever crosses a pipe, never a file or argv.
credential_format_ok() {
    local name=$1 credential=$2 expected_separators=2 separators
    [[ $name == backblaze ]] || expected_separators=3
    separators=$(systemd-creds decrypt --user --name="$name" "$credential" - 2>/dev/null | tr -dc '\0' | wc -c) || return 1
    (( separators == expected_separators ))
}

# Only the selected provider and the pepper are used by DigiSafe.
read_storage_provider
unreadable_credentials=0
for name in digipepper "$active_provider"; do
    credential="$config_dir/$name.cred"
    [[ -e "$credential" ]] || continue
    chmod 600 -- "$credential"
    if [[ ! -s "$credential" ]]; then
        printf "Existing credential is empty: %s. Restore or repair it before rerunning.\n" "$credential" >&2
        exit 1
    fi
    if ! systemd-creds decrypt --user --name="$name" "$credential" - >/dev/null; then
        printf 'Cannot decrypt %s.\n' "$credential" >&2
        case "$name" in
            digipepper)
                printf 'If you have the original pepper seed, run %s --restore-pepper. Otherwise keep this file for recovery in its original boot state.\n' "$0" >&2 ;;
            backblaze)
                printf 'To re-enter the Backblaze application key, run %s --reset-backblaze.\n' "$0" >&2 ;;
            *)
                printf 'To re-enter the %s credentials, run %s --configure-storage %s.\n' "$(provider_label "$name")" "$0" "$name" >&2 ;;
        esac
        unreadable_credentials=1
        continue
    fi
    if [[ "$name" == digipepper ]]; then
        pepper=$(systemd-creds decrypt --user --name=digipepper "$credential" -)
        if [[ ! "$pepper" =~ ^[[:xdigit:]]{64}$ ]]; then
            unset pepper
            printf 'Saved pepper is invalid: expected 64 hex characters. Restore the original pepper or recreate it using the original seed before opening an existing vault.\n' >&2
            exit 1
        fi
        unset pepper
    elif ! credential_format_ok "$name" "$credential"; then
        printf 'Saved %s credential has an unexpected format. Run %s --configure-storage %s to re-enter it.\n' \
            "$name" "$0" "$name" >&2
        exit 1
    fi
done
if (( unreadable_credentials )); then
    fail 'Setup stopped before the build. Rerun setup after recovering the listed credentials.'
fi

printf "Building and installing DigiSafe before requesting credentials...\n"
cargo deb --install

if [[ ! -e "$config_dir/digipepper.cred" ]]; then
    provision_pepper
else
    printf "Reusing existing pepper credential.\n"
fi

if [[ -e "$config_dir/$active_provider.cred" ]]; then
    printf "Reusing existing %s credentials.\n" "$(provider_label "$active_provider")"
elif [[ -e "$config_dir/$provider_file_name" ]]; then
    printf "Storage provider %s is selected but has no credentials yet.\n" "$(provider_label "$active_provider")"
    provision_provider "$active_provider"
else
    choose_provider
    provision_provider "$selected_provider"
    select_storage_provider "$selected_provider"
    active_provider=$selected_provider
fi

printf "DigiSafe setup finished. Vault sync uses %s.\n" "$(provider_label "$active_provider")"
