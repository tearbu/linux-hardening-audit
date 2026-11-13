#!/usr/bin/env bash
#
# linux-hardening-audit.sh
# ------------------------
# A read-only baseline hardening check for a Linux host. It inspects SSH
# configuration, sudo policy, world-writable files, empty-password
# accounts, and legacy plaintext services, then prints findings with
# severities and a summary count. It changes nothing on the system.
#
# Usage:
#   ./audit.sh                  Audit the live system (/etc), skipping
#                               anything that is missing or unreadable.
#   ./audit.sh --root DIR       Demo mode: audit the sample tree in DIR.
#                               Expected files inside DIR:
#                                 sshd_config  passwd  shadow
#                                 sudoers.d/   services.txt  file-listing.txt
#                               In demo mode the world-writable list is
#                               read from file-listing.txt instead of
#                               running find(1).
#
# Exit code is 0 as long as the audit itself ran; findings are data,
# not failures.

set -u

ROOT="/etc"
DEMO=0

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --root)
            [ $# -ge 2 ] || { echo "error: --root needs a directory" >&2; exit 2; }
            ROOT="$2"; DEMO=1; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "error: unknown argument: $1" >&2; exit 2 ;;
    esac
done

FINDINGS_FILE="$(mktemp)"
trap 'rm -f "$FINDINGS_FILE"' EXIT

# finding SEVERITY CHECK MESSAGE
finding() {
    local line
    line="$(printf '[%-8s] %-22s %s' "$1" "$2" "$3")"
    echo "$line" >> "$FINDINGS_FILE"
    echo "$line"
}

note() { echo "note: $1" >&2; }

first_value() {
    # first_value FILE KEY -> prints the value of the first uncommented
    # "KEY value" line in FILE (sshd_config semantics: first match wins).
    grep -E "^[[:space:]]*$2[[:space:]]+" "$1" 2>/dev/null | head -n 1 \
        | awk '{print $2}'
}

echo "Linux Hardening Audit"
echo "Target root: $ROOT  (mode: $([ "$DEMO" -eq 1 ] && echo demo || echo live))"
echo "----------------------------------------------------------------"

# ---------------------------------------------------------------- sshd ---
SSHD="$ROOT/sshd_config"
[ "$DEMO" -eq 1 ] || SSHD="/etc/ssh/sshd_config"
if [ -r "$SSHD" ]; then
    prl="$(first_value "$SSHD" PermitRootLogin)"
    case "$prl" in
        no) ;;
        yes)
            finding "High" "sshd" "PermitRootLogin is 'yes' - direct root SSH login is allowed" ;;
        "")
            finding "Medium" "sshd" "PermitRootLogin is not set (not explicitly disabled)" ;;
        *)
            finding "Medium" "sshd" "PermitRootLogin is '$prl', not 'no'" ;;
    esac

    pa="$(first_value "$SSHD" PasswordAuthentication)"
    case "$pa" in
        no) ;;
        yes)
            finding "Medium" "sshd" "PasswordAuthentication is 'yes' - password-based SSH login is allowed" ;;
        "")
            finding "Medium" "sshd" "PasswordAuthentication is not set (defaults to 'yes')" ;;
        *)
            finding "Low" "sshd" "PasswordAuthentication has unexpected value '$pa'" ;;
    esac

    port="$(first_value "$SSHD" Port)"
    if [ -z "$port" ] || [ "$port" = "22" ]; then
        finding "Info" "sshd" "SSH is on the default port 22 (informational only)"
    fi
else
    note "sshd_config not readable at $SSHD - skipping SSH checks"
fi

# --------------------------------------------------------------- sudoers ---
SUDOERS_DIR="$ROOT/sudoers.d"
if [ -d "$SUDOERS_DIR" ]; then
    for f in "$SUDOERS_DIR"/*; do
        [ -f "$f" ] || continue
        while IFS= read -r line; do
            finding "High" "sudoers" "$(basename "$f"): passwordless sudo granted: $line"
        done < <(grep 'NOPASSWD' "$f" 2>/dev/null | sed 's/^[[:space:]]*//')
    done
elif [ "$DEMO" -eq 1 ]; then
    note "no sudoers.d directory under $ROOT - skipping sudo checks"
fi

# ------------------------------------------------------- world-writable ---
if [ "$DEMO" -eq 1 ]; then
    LISTING="$ROOT/file-listing.txt"
    if [ -r "$LISTING" ]; then
        while IFS= read -r path; do
            [ -n "$path" ] || continue
            finding "Medium" "world-writable" "World-writable path: $path"
        done < "$LISTING"
    else
        note "file-listing.txt not found under $ROOT - skipping world-writable check"
    fi
else
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        finding "Medium" "world-writable" "World-writable file: $path"
    done <<EOF
$(find /etc /usr/local /opt /home /srv /var/www -xdev -type f -perm -0002 2>/dev/null | head -n 50)
EOF
fi

# -------------------------------------------------------- empty passwords ---
SHADOW="$ROOT/shadow"
if [ -r "$SHADOW" ]; then
    while IFS=: read -r user pw _rest; do
        if [ -z "$pw" ]; then
            finding "Critical" "accounts" "Account '$user' has an EMPTY password field in shadow"
        fi
    done < "$SHADOW"
else
    note "shadow file not readable at $SHADOW (needs root) - skipping empty-password check"
fi

# --------------------------------------------------------- legacy services ---
if [ "$DEMO" -eq 1 ]; then
    SERVICES="$ROOT/services.txt"
    if [ -r "$SERVICES" ]; then
        while IFS= read -r line; do
            svc="$(echo "$line" | awk '{print $1}')"
            case "$svc" in
                telnet|rsh|rlogin|rexec)
                    finding "High" "services" "Legacy plaintext service enabled: $line" ;;
            esac
        done < "$SERVICES"
    else
        note "services.txt not found under $ROOT - skipping services check"
    fi
else
    if command -v systemctl >/dev/null 2>&1; then
        for svc in telnet.socket rsh.socket rlogin.socket; do
            if systemctl is-enabled "$svc" >/dev/null 2>&1; then
                finding "High" "services" "Legacy plaintext service unit enabled: $svc"
            fi
        done
    else
        note "systemctl not available - skipping live services check"
    fi
fi

# --------------------------------------------------------------- summary ---
echo "----------------------------------------------------------------"
count() { grep -c "^\[$1" "$FINDINGS_FILE" 2>/dev/null || true; }
total=$(wc -l < "$FINDINGS_FILE" | tr -d ' ')
echo "Summary: Critical=$(count Critical) High=$(count High) Medium=$(count Medium) Low=$(count Low) Info=$(count Info) Total=$total"
exit 0
