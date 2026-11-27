#!/bin/bash
set -Eeuo pipefail
umask 077

trap 'printf "Keptino setup failed at line %s. Fix the error above and rerun setup.\n" "$LINENO" >&2' ERR

# Resolve assets and Cargo.toml relative to this script, regardless of the caller's cwd.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if (( EUID == 0 )); then
    printf "Run setup as your normal user; sudo is used only to install packages.\n" >&2
    exit 1
fi

# Remote storage providers for vault sync. The active one is named in
# ~/.config/keptino/storage-provider (identifier plus newline); an absent file
# means the legacy Backblaze configuration. Each provider keeps its own
# <provider>.cred, encrypted by systemd-creds --user --name=<provider>.
#   backblaze: key name, key ID, application key          (3 NUL-separated fields)
#   aws:       bucket, region, access key ID, secret        (4 NUL-separated fields)
#   gcs:       bucket, location, HMAC access ID, HMAC secret
#   r2:        bucket, account ID (32 hex), access key ID, secret
providers=(backblaze aws gcs r2 s3)
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
        s3) printf 'S3-compatible endpoint' ;;
    esac
}

provider_hint() {
    case $1 in
        backblaze) printf 'Use an application key restricted to the vault bucket.\n' ;;
        aws) printf 'Use an IAM access key pair granted s3:GetObject and s3:PutObject on vault objects and s3:ListBucket on the bucket, so a first unlock can tell a missing vault from denied access.\n' ;;
        gcs) printf 'Use an HMAC key for a service account with Storage Object User (roles/storage.objectUser) on a Standard bucket; enter its location, e.g. us-central1.\n' ;;
        r2) printf 'Use an Object Read & Write API token scoped to a Standard bucket in the default jurisdiction; the account ID is on the R2 overview page.\n' ;;
        s3) printf 'Any store speaking path-style S3 over TLS, such as RustFS or MinIO on your own host: a key pair allowed to get and put objects in the bucket. The endpoint certificate must be trusted by this machine.\n' ;;
    esac
}

# Prompt for one credential field into the named variable. The value only ever
# lives in this shell's memory: it is never passed as an argument to an external
# process and never written to a plaintext file. Non-secret fields are echoed
# and trimmed; secrets are neither. Canceled or empty input aborts without
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
    local __ask_prompt=$2 __ask_echo=${3:-no} __ask_empty=${4:-} __ask_value
    local -a __ask_opts=(-n)
    if [[ $__ask_echo == yes ]] && ask_echo_supported; then
        __ask_opts+=(-e)
    fi
    if ! __ask_value=$(systemd-ask-password "${__ask_opts[@]}" "$__ask_prompt"); then
        fail 'Credential entry canceled; nothing was changed.'
    fi
    if [[ $__ask_echo == yes ]]; then
        __ask_value=${__ask_value#"${__ask_value%%[![:space:]]*}"}
        __ask_value=${__ask_value%"${__ask_value##*[![:space:]]}"}
    fi
    if [[ -z $__ask_value && $__ask_empty != allow_empty ]]; then
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
        s3)  pattern='^[a-z0-9._-]{1,222}$' ;;
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

# An S3-compatible store of the user's own: the endpoint is part of the
# credential, so one provider name covers RustFS, MinIO and the rest.
provision_s3() {
    local endpoint bucket region key_id secret
    printf 'Provisioning S3-compatible endpoint credentials...\n'
    provider_hint s3
    ask_field endpoint "Enter endpoint URL (https://host or https://host:port):" yes
    endpoint=${endpoint%/}
    if [[ ! $endpoint =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; then
        fail "Invalid endpoint '$endpoint': expected https://host or https://host:port with no path."
    fi
    ask_field bucket "Enter bucket name:" yes
    validate_bucket s3 "$bucket"
    ask_field region "Enter region (default us-east-1):" yes allow_empty
    region=${region:-us-east-1}
    validate_dns_label 'region' "$region" 'us-east-1'
    ask_field key_id "Enter access key ID:"
    ask_field secret "Enter secret access key:"
    printf '%s\0%s\0%s\0%s\0%s' "$endpoint" "$bucket" "$region" "$key_id" "$secret" | encrypt_credential s3
    unset key_id secret
    mv -- "$temp_dir/s3.cred" "$config_dir/s3.cred"
}

provision_provider() {
    case $1 in
        backblaze) provision_backblaze ;;
        aws|gcs|r2) provision_object_store "$1" ;;
        s3) provision_s3 ;;
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
    printf '  1) Backblaze B2 (default)\n  2) AWS S3\n  3) Google Cloud Storage\n  4) Cloudflare R2\n  5) Any S3-compatible endpoint (RustFS, MinIO, ...)\n'
    read -r -p 'Provider [1-5 or name, default 1]: ' choice || choice=''
    case ${choice,,} in
        ''|1|backblaze|b2) selected_provider=backblaze ;;
        2|aws) selected_provider=aws ;;
        3|gcs|gcp|google) selected_provider=gcs ;;
        4|r2|cloudflare) selected_provider=r2 ;;
        5|s3|custom|rustfs|minio) selected_provider=s3 ;;
        *) fail "Unknown storage provider '$choice'. Expected one of: ${providers[*]}." ;;
    esac
}

# A security key is a hidraw device; systemd's udev rules tag it for the
# logged-in user. Without them Keptino cannot open the key, so say so now.
check_security_key_access() {
    local rules
    for rules in /usr/lib/udev/rules.d/60-fido-id.rules /lib/udev/rules.d/60-fido-id.rules /etc/udev/rules.d/60-fido-id.rules; do
        [[ -r "$rules" ]] && return 0
    done
    printf 'No FIDO udev rules found (60-fido-id.rules). Security keys will not be usable until the udev package provides them.\n' >&2
}

# The pepper is derived by the installed keptino binary, which locks its
# memory for the 4 GiB derivation; --restore-pepper runs before the build, so
# it needs a package that already has --derive-pepper.
require_installed_keptino() {
    local installed
    installed=$(dpkg-query -W -f='${Version}' keptino 2>/dev/null) || installed=''
    if [[ -z "$installed" || ! -x /usr/bin/keptino ]] || ! dpkg --compare-versions "$installed" ge 0.2.2; then
        fail "Restoring the pepper needs Keptino 0.2.2 or newer installed (found '${installed:-none}'). Run $0 without arguments first to build and install it."
    fi
}

provision_pepper() {
    printf 'Deriving pepper from your original seed (requires 4 GiB of memory)...\n'
    systemd-ask-password -n "Enter original pepper seed:" | \
        /usr/bin/keptino --derive-pepper | \
        systemd-creds encrypt --user --name=pepper - "$temp_dir/pepper.cred"
    local pepper
    pepper=$(systemd-creds decrypt --user --name=pepper "$temp_dir/pepper.cred" -)
    if [[ ! "$pepper" =~ ^[[:xdigit:]]{64}$ ]]; then
        unset pepper
        printf 'Generated pepper is invalid; existing credential was preserved.\n' >&2
        exit 1
    fi
    unset pepper
    chmod 600 -- "$temp_dir/pepper.cred"
    if [[ -e "$config_dir/pepper.cred" ]]; then
        local backup
        backup=$(mktemp "$config_dir/pepper.cred.backup.XXXXXXXX")
        cp -- "$config_dir/pepper.cred" "$backup"
        printf 'Previous encrypted pepper saved to %s\n' "$backup"
    fi
    mv -- "$temp_dir/pepper.cred" "$config_dir/pepper.cred"
}

# A DigiSafe installation becomes a Keptino one in three independent steps,
# each of which does nothing when its work is already done, so an interrupted
# run finishes on the next one: the directory moves (a single rename), vault
# files take the .keptino extension, and the pepper is re-wrapped from the old
# credential name to the new one through a pipe, never a file. Provider
# credentials need no change: their systemd-creds name is unchanged. Nothing
# here needs the seed; if the TPM refuses the old pepper, the old file is kept
# and the usual seed prompt or --restore-pepper takes over.
legacy_config_dir="$HOME/.config/digisafe"

migrate_legacy_config_dir() {
    [[ -d "$legacy_config_dir" ]] || return 0
    if [[ -e "$config_dir" ]]; then
        printf 'Leaving the old DigiSafe directory %s in place: %s already exists.\n' "$legacy_config_dir" "$config_dir"
        return
    fi
    printf 'Moving the DigiSafe configuration %s to %s...\n' "$legacy_config_dir" "$config_dir"
    mv -- "$legacy_config_dir" "$config_dir"
}

# Renames every <db>.digisafe to <db>.keptino. When both exist, both are kept
# and Keptino opens the .keptino one. Hidden files are never touched: the old
# application left .<db>.digisafe temporaries behind interrupted saves.
migrate_legacy_vaults() {
    local vault target
    for vault in "$config_dir"/*.digisafe; do
        [[ -e "$vault" ]] || continue
        target="${vault%.digisafe}.keptino"
        if [[ -e "$target" ]]; then
            printf 'Both %s and %s exist; Keptino uses the .keptino file and leaves the other untouched.\n' \
                "$(basename -- "$vault")" "$(basename -- "$target")"
            continue
        fi
        mv -- "$vault" "$target"
        printf 'Renamed vault %s to %s\n' "$(basename -- "$vault")" "$(basename -- "$target")"
    done
}

migrate_legacy_pepper() {
    local old="$config_dir/digipepper.cred"
    [[ -e "$old" && ! -e "$config_dir/pepper.cred" ]] || return 0
    printf 'Re-wrapping the pepper credential under its new name...\n'
    if systemd-creds decrypt --user --name=digipepper "$old" - 2>/dev/null \
        | systemd-creds encrypt --user --name=pepper - "$temp_dir/pepper.cred" 2>/dev/null \
        && [[ -s "$temp_dir/pepper.cred" ]]; then
        chmod 600 -- "$temp_dir/pepper.cred"
        mv -- "$temp_dir/pepper.cred" "$config_dir/pepper.cred"
        rm -f -- "$old"
        printf 'Pepper credential is now %s.\n' "$config_dir/pepper.cred"
    else
        rm -f -- "$temp_dir/pepper.cred"
        printf 'The TPM would not release the old pepper credential; %s is kept for recovery. Setup will ask for the original pepper seed instead.\n' "$old" >&2
    fi
}

prepare_config_dir() {
    config_dir="$HOME/.config/keptino"
    migrate_legacy_config_dir
    mkdir -p -- "$config_dir"
    chmod 700 -- "$config_dir"
    temp_dir=$(mktemp -d "$config_dir/.setup.XXXXXXXX")
    trap 'rm -rf -- "$temp_dir"' EXIT
    migrate_legacy_vaults
    migrate_legacy_pepper
}

require_credential_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null
    done
}

# Exercise user-scoped encryption before requesting any real secrets.
check_credential_encryption() {
    printf 'keptino-setup-check' | systemd-creds encrypt --user --name=setup-check - "$temp_dir/check.cred"
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
            require_installed_keptino
            require_credential_tools systemd-creds systemd-ask-password
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

printf "Checking Keptino dependencies...\n"
for tool in cargo rustc sudo apt-get dpkg-query; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf "Missing %s. Setup requires Debian/Ubuntu, sudo, and a working Rust toolchain.\n" "$tool" >&2
        exit 1
    fi
done
cargo --version
rustc --version

packages=(build-essential pkg-config dpkg-dev systemd libcap2-bin libwayland-dev libxkbcommon-dev)
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
    # The version is pinned because `cargo install` ignores the dependency
    # cooldown in .cargo/config.toml; bump it deliberately after review.
    cargo install cargo-deb --version 3.6.3 --locked --force
    cargo deb --version >/dev/null
fi
require_credential_tools systemd-creds systemd-ask-password
pkg-config --exists wayland-client xkbcommon
check_security_key_access

prepare_config_dir
check_credential_encryption

# Returns 0 when <name>.cred decrypts and has the expected field count; the
# plaintext only ever crosses a pipe, never a file or argv.
credential_format_ok() {
    local name=$1 credential=$2 expected_separators=2 separators
    case $name in
        backblaze) expected_separators=2 ;;
        s3) expected_separators=4 ;;
        *) expected_separators=3 ;;
    esac
    separators=$(systemd-creds decrypt --user --name="$name" "$credential" - 2>/dev/null | tr -dc '\0' | wc -c) || return 1
    (( separators == expected_separators ))
}

# Only the selected provider and the pepper are used by Keptino.
read_storage_provider
unreadable_credentials=0
for name in pepper "$active_provider"; do
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
            pepper)
                printf 'If you have the original pepper seed, run %s --restore-pepper. Otherwise keep this file for recovery in its original boot state.\n' "$0" >&2 ;;
            backblaze)
                printf 'To re-enter the Backblaze application key, run %s --reset-backblaze.\n' "$0" >&2 ;;
            *)
                printf 'To re-enter the %s credentials, run %s --configure-storage %s.\n' "$(provider_label "$name")" "$0" "$name" >&2 ;;
        esac
        unreadable_credentials=1
        continue
    fi
    if [[ "$name" == pepper ]]; then
        pepper=$(systemd-creds decrypt --user --name=pepper "$credential" -)
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

# Dependency advisories are reported, never fatal: an offline host or a stale
# advisory database must not block an install. Install the tool with
# `cargo install cargo-audit --locked` to enable the check.
if cargo audit --version >/dev/null 2>&1; then
    printf 'Checking dependency advisories (accepted ones are listed with reasons in .cargo/audit.toml)...\n'
    if ! (cd .. && cargo audit); then
        printf 'cargo audit reported advisories above; review them. Setup continues.\n' >&2
    fi
else
    printf 'cargo-audit is not installed; skipping the dependency advisory check.\n'
fi

printf "Building and installing Keptino before requesting credentials...\n"
cargo deb --install

if [[ ! -e "$config_dir/pepper.cred" ]]; then
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

printf "Keptino setup finished. Vault sync uses %s.\n" "$(provider_label "$active_provider")"
