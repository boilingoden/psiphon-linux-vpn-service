#!/bin/bash

# Psiphon Linux VPN Service - Zero Trust Network Security Implementation
# Security-First TUN Interface Setup with Kill Switch
#
# Features:
# - Zero-trust networking model with comprehensive kill switch
# - Native TUN interface support for secure packet tunneling
# - Automated binary verification and secure updates
# - Full IPv4/IPv6 traffic isolation through VPN tunnel
# - DNS leak prevention with secure resolution handling
#
# Security measures:
# - Default-deny firewall policy (fail-closed model)
# - Dedicated non-root user isolation
# - Secure process capability restrictions
# - Comprehensive traffic routing enforcement

set -euo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="1.4.2"
# Security and Configuration Parameters
# These values are critical for the security model - DO NOT MODIFY without understanding implications
readonly PSIPHON_USER="psiphon-user"     # Dedicated non-root user for process isolation
readonly PSIPHON_GROUP="psiphon-group"   # Restricted group for secure operations
readonly SOCKS_PORT=1081                 # Local SOCKS proxy port for tunneled traffic
readonly HTTP_PORT=8081                  # Local HTTP proxy port for tunneled traffic
readonly INSTALL_DIR="/opt/psiphon-tun"  # Base installation directory with restricted access
readonly PSIPHON_DIR="$INSTALL_DIR/psiphon" # Secure binary and config storage location
readonly PSIPHON_BINARY="$PSIPHON_DIR/psiphon-tunnel-core"
readonly PSIPHON_CONFIG_FILE="$PSIPHON_DIR/psiphon.config"
readonly LOG_FILE="$INSTALL_DIR/psiphon-tun.log"
readonly PSIPHON_LOG_FILE="$INSTALL_DIR/psiphon-core.log"
readonly PSIPHON_SPONSOR_HOMEPAGE_PATH="$INSTALL_DIR/data/ca.psiphon.PsiphonTunnel.tunnel-core/homepage"
readonly LOCK_FILE="/run/psiphon-tun.lock"
readonly PID_FILE="/run/psiphon-tun.pid"

readonly GITHUB_API="https://api.github.com/repos/Psiphon-Labs/psiphon-tunnel-core-binaries"
readonly PSIPHON_BINARY_URL="https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/raw/master/linux/psiphon-tunnel-core-x86_64"

readonly SERVICE_CONFIGURE_NAME="psiphon-tun"
readonly SERVICE_BINARY_NAME="psiphon-binary"
readonly SERVICE_HOMEPAGE_MONITOR="psiphon-homepage-monitor"
readonly SERVICE_HOMEPAGE_TRIGGER="psiphon-homepage-trigger"

# Network Security Configuration
readonly TUN_INTERFACE="PsiphonTUN"      # Dedicated TUN interface for isolated traffic
readonly TUN_SUBNET="10.200.3.0/24"      # IPv4 subnet for tunnel traffic isolation
readonly TUN_IP="10.200.3.1"             # IPv4 gateway address for tunnel
readonly TUN_PEER_IP="10.200.3.2"        # IPv4 peer address for point-to-point tunnel
readonly TUN_SUBNET6="fd42:42:42::/64"   # IPv6 subnet (ULA) for tunnel traffic isolation
readonly TUN_IP6="fd42:42:42::1"         # IPv6 gateway address for tunnel
readonly TUN_DNS_SERVERS="8.8.8.8,8.8.4.4" # Google DNS
readonly TUN_DNS_SERVERS6="2001:4860:4860::8888,2001:4860:4860::8844" # Google DNS IPv6

# WARP Integration Configuration
readonly WARP_CLI_PATH="/usr/bin/warp-cli"      # Path to WARP CLI executable
readonly WARP_SVC_PROCESS="warp-svc"            # WARP service process name
readonly WARP_STATUS_CONNECTED="Status update: Connected"       # Expected WARP status when connected
readonly WARP_INTERFACE="CloudflareWARP"                  # WARP interface name

# Secure fallback for interface selection: default route with non-loopback fallback
TUN_BYPASS_INTERFACE=$(ip -json route get 8.8.8.8 2>/dev/null | jq -r '.[0].dev // empty' ||
                              ip -json link show | jq -r '.[] | select(.link_type!="loopback") | .ifname' | head -n1)

SERVICE_MODE="false" # Set to true when running as a systemd service

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
function log() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${BLUE}[$timestamp]${NC} $message"
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
}

function error() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${RED}[$timestamp][ERROR]${NC} $message" >&2
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] ERROR: $message" >> "$LOG_FILE" 2>/dev/null || true
}

function success() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${GREEN}[$timestamp][SUCCESS]${NC} $message"
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] $message" >> "$LOG_FILE" 2>/dev/null || true
}

function warning() {
    local message="$1"
    # We want to avoid errors if date command fails
    # shellcheck disable=SC2155
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S') || true
    echo -e "${YELLOW}[$timestamp][WARNING]${NC} $message"
    # We want to avoid errors if log file is not writable
    # shellcheck disable=SC2015
    [[ -w "$LOG_FILE" || -w "$(dirname "$LOG_FILE")" ]] && echo "[$timestamp] WARNING: $message" >> "$LOG_FILE" 2>/dev/null || true
}

# Security Validation Functions

# Verify root privileges for secure operations
# Required for network configuration and process management
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Process isolation through file locking
# Prevents race conditions and ensures single instance execution
function acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid
        lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            error "Another instance is already running (PID: $lock_pid)"
            exit 1
        else
            # Remove stale lock file
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
}

# Check for required tools
function check_dependencies() {
    local missing_tools=()

    for tool in wget curl unzip ip nft jq dig; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        log "Installing missing tools..."
        if command -v apt-get >/dev/null 2>&1; then
            # On Debian/Ubuntu, nft comes from the nftables package
            local packages_to_install=()
            for tool in "${missing_tools[@]}"; do
                if [ "$tool" = "nft" ]; then
                    packages_to_install+=("nftables")
                elif [ "$tool" = "dig" ]; then
                    packages_to_install+=("dnsutils")
                else
                    packages_to_install+=("$tool")
                fi
            done
            apt-get update && apt-get install -y "${packages_to_install[@]}"
        elif command -v yum >/dev/null 2>&1; then
            # On RHEL/CentOS/Fedora
            local packages_to_install=()
            for tool in "${missing_tools[@]}"; do
                if [ "$tool" = "nft" ]; then
                    packages_to_install+=("nftables")
                elif [ "$tool" = "dig" ]; then
                    packages_to_install+=("bind-utils")
                else
                    packages_to_install+=("$tool")
                fi
            done
            yum install -y "${packages_to_install[@]}"
        elif command -v pacman >/dev/null 2>&1; then
            # On Arch Linux
            local packages_to_install=()
            for tool in "${missing_tools[@]}"; do
                if [ "$tool" = "nft" ]; then
                    packages_to_install+=("nftables")
                elif [ "$tool" = "dig" ]; then
                    packages_to_install+=("bind")
                else
                    packages_to_install+=("$tool")
                fi
            done
            pacman -S --noconfirm "${packages_to_install[@]}"
        else
            error "Cannot install missing tools. Please install manually: ${missing_tools[*]}"
            exit 1
        fi
    fi
}

# Create user and group
function create_user() {
    if ! getent group "$PSIPHON_GROUP" >/dev/null 2>&1; then
        log "Creating group $PSIPHON_GROUP..."
        groupadd --system "$PSIPHON_GROUP"
    fi

    if ! getent passwd "$PSIPHON_USER" >/dev/null 2>&1; then
        log "Creating user $PSIPHON_USER..."
        useradd --system --no-create-home --shell /bin/false \
                --home-dir /nonexistent --gid "$PSIPHON_GROUP" "$PSIPHON_USER"
    fi
}

# Create directory structure
function create_directories() {
    log "Creating directory structure..."

    mkdir -p "$INSTALL_DIR" "$PSIPHON_DIR" "$INSTALL_DIR/data"
    chown -R "$PSIPHON_USER:$PSIPHON_GROUP" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR" "$PSIPHON_DIR"
    chmod 700 "$INSTALL_DIR/data"
}


# Psiphon version management
function get_latest_psiphon_info() {
    local commits_api="$GITHUB_API/commits?path=linux/psiphon-tunnel-core-x86_64&per_page=1"
    local latest_commit

    if ! latest_commit=$(curl -s --connect-timeout 7 --max-time 60 "$commits_api"); then
        error "Failed to fetch commit info from GitHub"
        return 1
    fi

    if [[ -z "$latest_commit" ]] || [[ "$latest_commit" == "null" ]] || ! echo "$latest_commit" | jq empty 2>/dev/null; then
        error "Invalid response from GitHub API"
        return 1
    fi
    # We want to avoid errors if jq fails. We check later if commit_message is empty
    # shellcheck disable=SC2155
    local commit_message=$(echo "$latest_commit" | jq -r '.[0].commit.message' 2>/dev/null || echo "") || true

    if [[ -z "$commit_message" ]] || [[ "$commit_message" == "null" ]]; then
        error "Failed to parse commit information"
        return 1
    fi

    echo "$commit_message"
}

function get_binary_version_info() {
    if [[ ! -f "$PSIPHON_BINARY" ]]; then
        echo "|"
        return
    fi

    local version_output

    if ! version_output=$(exec runuser -u "$PSIPHON_USER" -- "$PSIPHON_BINARY" -v 2>/dev/null); then
        echo "|"
        return
    fi
    # We want to avoid errors if grep or sed fails. It's okay if build_date or revision is empty
    # shellcheck disable=SC2155
    local revision=$(echo "$version_output" | grep "Revision:" | sed 's/Revision: //' | xargs || echo "")

    echo "$revision"
}

# Secure binary download and validation
function download_psiphon() {
    local temp_file
    temp_file=$(mktemp)

    log "Downloading latest Psiphon binary..."

    if ! wget -q --connect-timeout 7 --timeout=567 --tries=3 "$PSIPHON_BINARY_URL" -O "$temp_file"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Failed to download Psiphon binary"
        return 1
    fi

    # Verify it's a valid binary
    if ! file "$temp_file" | grep -q "ELF.*executable"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Downloaded file is not a valid Linux executable"
        return 1
    fi

    # Make it executable and test version
    chmod +x "$temp_file"
    local version_output
    if ! version_output=$("$temp_file" -v 2>/dev/null); then
        rm -f "$temp_file" 2>/dev/null || true
        error "Downloaded binary cannot be executed or is invalid"
        return 1
    fi

    if ! echo "$version_output" | grep -q "Psiphon Console Client"; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Downloaded binary does not appear to be Psiphon"
        return 1
    fi

    # Extract version info
    local build_date revision
    build_date=$(echo "$version_output" | grep "Build Date:" | sed 's/Build Date: //' | xargs || echo "")
    revision=$(echo "$version_output" | grep "Revision:" | sed 's/Revision: //' | xargs || echo "")

    if [[ -z "$build_date" ]] || [[ -z "$revision" ]]; then
        rm -f "$temp_file" 2>/dev/null || true
        error "Cannot extract version information from binary"
        return 1
    fi

    log "Downloaded binary info:"
    log "  Build Date: $build_date"
    log "  Revision: $revision"

    # Install the binary securely
    # cp -f "$temp_file" "$PSIPHON_BINARY"
    # chmod 750 "$PSIPHON_BINARY"
    # chown "$PSIPHON_USER:$PSIPHON_GROUP" "$PSIPHON_BINARY"
    install -m 750 -o "$PSIPHON_USER" -g "$PSIPHON_GROUP" "$temp_file" "$PSIPHON_BINARY"


    # Clean up temp file before successful return
    rm -f "$temp_file" 2>/dev/null || true

    success "Psiphon binary installed successfully"
}

function check_and_update_psiphon() {
    log "Checking for Psiphon updates..."

    # Get latest commit info from GitHub
    local latest_commit_msg
    if ! latest_commit_msg=$(get_latest_psiphon_info); then
        warning "Failed to fetch latest Psiphon commit info from GitHub"
    fi

    # Get current binary info
    # We want to avoid errors if get_binary_version_info fails
    # We download anyway if we cannot determine current version
    # shellcheck disable=SC2155
    local current_revision=$(get_binary_version_info) || true

    log "Latest revision: $latest_commit_msg"
    log "Current binary Revision: $current_revision"

    # Check if we need to update
    local needs_update=false

    if [[ ! -f "$PSIPHON_BINARY" ]]; then
        log "Binary not found, downloading..."
        needs_update=true
    elif [[ -z "$current_revision" ]]; then
        log "Cannot determine current version, updating..."
        needs_update=true
    else
        if [[ "$latest_commit_msg" != *"$current_revision"* ]]; then
            # If timestamps are close or equal, check if revisions are different
            log "Different revision detected, updating..."
            needs_update=true
        fi
    fi

    if [[ "$needs_update" == true ]]; then
        log "Updating Psiphon binary..."
        if download_psiphon; then
            success "Psiphon updated successfully"

            # Show new version info
            local new_info new_build_date new_revision
            new_info=$(get_binary_version_info)
            new_build_date=$(echo "$new_info" | cut -d'|' -f1)
            new_revision=$(echo "$new_info" | cut -d'|' -f2)
            log "New version: Build Date: $new_build_date, Revision: $new_revision"

            return 0
        else
            error "Failed to update Psiphon"
            return 1
        fi
    else
        log "Psiphon is already up to date"
        return 0
    fi
}

# Create Psiphon configuration
function create_psiphon_config() {
    log "Creating Psiphon configuration..."

    # See the AvailableEgressRegions in Psiphon logs for valid region codes
    # Example:
    # Change to `"EgressRegion": "US",` if you want to force to choose US servers
    cat > "$PSIPHON_CONFIG_FILE" << 'EOF'
{
    "LocalHttpProxyPort": 8081,
    "LocalSocksProxyPort": 1081,
    "EgressRegion": "",
    "PropagationChannelId": "FFFFFFFFFFFFFFFF",
    "RemoteServerListDownloadFilename": "remote_server_list",
    "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
    "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
    "SponsorId": "FFFFFFFFFFFFFFFF",
    "UseIndistinguishableTLS": true
}
EOF

    ## removed parts:
    # ,
    # "EstablishTunnelTimeoutSeconds": 360,
    # "TunnelPoolSize": 1
    #
    # also for WARP test:
    # "UpstreamProxyURL": "socks5://127.0.0.1:40000",
    #

    chown "$PSIPHON_USER:$PSIPHON_GROUP" "$PSIPHON_CONFIG_FILE"
    chmod 600 "$PSIPHON_CONFIG_FILE"
}

# Systemd service
function create_systemd_services() {
    log "Creating systemd service..."

    local service_script="$INSTALL_DIR/psiphon-tun-service.sh"

    # Create service wrapper script
    tee "$service_script" >/dev/null <<EOF
#!/bin/bash
set -euo pipefail

INSTALL_DIR="$INSTALL_DIR"
SERVICE_SCRIPT="$INSTALL_DIR/psiphon-tun.sh"

case "\${1:-}" in
    start)
        "\$SERVICE_SCRIPT" systemd_start
        ;;
    stop)
        "\$SERVICE_SCRIPT" systemd_stop
        ;;
    reload)
        "\$SERVICE_SCRIPT" systemd_reload
        ;;
    restart)
        "\$SERVICE_SCRIPT" systemd_restart
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|reload}"
        exit 1
        ;;
esac
EOF

    chmod 755 "$service_script"
    chown root:root "$service_script"

    # Create main systemd service file
    tee /etc/systemd/system/$SERVICE_CONFIGURE_NAME.service >/dev/null <<EOF
[Unit]
Description=Psiphon TUN Service (Network Configuration)
After=network-online.target
Wants=network-online.target
Before=$SERVICE_BINARY_NAME.service
Documentation=https://github.com/boilingoden/psiphon-client-linux-service

[Service]
Type=simple
RemainAfterExit=yes
ExecStart=$service_script start
ExecStop=$service_script stop
ExecReload=$service_script reload
# TimeoutStartSec=120
# TimeoutStopSec=30
User=root
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /run /var/log /etc/resolv.conf /etc/systemd/resolved.conf.d
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_IPC_LOCK
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE CAP_IPC_LOCK
SecureBits=keep-caps-locked

[Install]
WantedBy=multi-user.target
EOF

    # Create tunnel service file
    tee /etc/systemd/system/$SERVICE_BINARY_NAME.service >/dev/null <<EOF
[Unit]
Description=Psiphon Binary Process
After=network-online.target $SERVICE_CONFIGURE_NAME.service
Requires=$SERVICE_CONFIGURE_NAME.service
Documentation=https://github.com/boilingoden/psiphon-client-linux-service
StartLimitIntervalSec=10
StartLimitBurst=3

[Service]
Type=exec
# ExecStartPre=/bin/sleep 2
ExecStart="$PSIPHON_BINARY" -config "$PSIPHON_CONFIG_FILE" -dataRootDirectory "$INSTALL_DIR/data" \\
    -tunDevice "$TUN_INTERFACE" -tunBindInterface "$TUN_BYPASS_INTERFACE" \\
    -tunDNSServers "$TUN_DNS_SERVERS,$TUN_DNS_SERVERS6" -formatNotices -useNoticeFiles
# ExecStop=/bin/kill -TERM \$MAINPID
# ExecReload=/bin/systemctl --no-block restart %n
User=$PSIPHON_USER
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_BINARY_NAME
Restart=always
RestartSec=7s

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /var/log
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
SecureBits=noroot-locked
ProtectClock=no
ProtectControlGroups=no

[Install]
WantedBy=multi-user.target
EOF

    # Create homepage monitor service
    tee /etc/systemd/system/$SERVICE_HOMEPAGE_MONITOR.path >/dev/null <<EOF
[Unit]
Description=Psiphon Homepage Monitor

[Path]
PathModified=$PSIPHON_SPONSOR_HOMEPAGE_PATH
Unit=$SERVICE_HOMEPAGE_TRIGGER.service

[Install]
WantedBy=multi-user.target
EOF

    # Get the active logged-in user
    # This checks for the active display manager session.
    ACTIVE_USER=$(logname)
    ACTIVE_USER_ID=$(id -u "$ACTIVE_USER" 2>/dev/null || echo "1000")
    # Create the trigger service
    tee /etc/systemd/system/$SERVICE_HOMEPAGE_TRIGGER.service >/dev/null <<EOF
[Unit]
Description=Psiphon Homepage Change Handler
# The service should only run after a graphical session has started.
PartOf=graphical.target
Requires=graphical.target

[Service]
Type=oneshot
Environment="DISPLAY=:0"
Environment="DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$ACTIVE_USER_ID/bus"
ExecStart=/bin/sh -c 'journalctl -u $SERVICE_BINARY_NAME -n 5 --no-pager 2>/dev/null | grep -q "Tunnels.*count.*1" && notify-send -a "$SERVICE_CONFIGURE_NAME" -u critical -i network-vpn -t 10000 "Psiphon Connected" || notify-send -a "$SERVICE_CONFIGURE_NAME" -u normal -i network-vpn-disconnected -t 10000 "Psiphon Status Changed" "run: systemctl status $SERVICE_BINARY_NAME to check connection status"'
User=$ACTIVE_USER

# TODO: Make this open the URL in the user's default browser **securely**
# ExecStart=/bin/sh -c 'URL=\$(runuser -pu "$PSIPHON_USER" -- jq -r ".data.url" "$PSIPHON_SPONSOR_HOMEPAGE_PATH");echo "$\URL"; runuser -pu "$ACTIVE_USER" -- systemd-run --user xdg-open "\$URL" 2>/dev/null &'
# User=root

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# ProtectHome=true
EOF

    # Copy this script to install directory
    cp -f "$0" "$INSTALL_DIR/psiphon-tun.sh"
    chmod 755 "$INSTALL_DIR/psiphon-tun.sh"
    chown root:root "$INSTALL_DIR/psiphon-tun.sh"

    systemctl daemon-reload

    success "Systemd service created"
}

# Change DNS Configuration
function change_dns_config() {
    log "Setting up DNS configuration..."

    # Backup original resolv.conf
    if [ ! -f /etc/resolv.conf.original ]; then
        cp -P /etc/resolv.conf /etc/resolv.conf.original &
        wait
    fi

    # Check if systemd-resolved is running
    if ! systemctl is-active systemd-resolved >/dev/null 2>&1; then
        # Configure DNS servers
    cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 2001:4860:4860::8888
nameserver 2001:4860:4860::8844
EOF

    # Set proper permissions
    chmod 644 /etc/resolv.conf

    # # Setup routing table for DNS
    # for dns in 8.8.8.8 8.8.4.4; do
    #     ip route add $dns via $(ip route | grep default | grep -v $TUN_INTERFACE | awk '{print $3}') dev $TUN_BYPASS_INTERFACE proto static
    # done

    else
        # Create resolved.conf drop-in directory if it doesn't exist
        mkdir -p /etc/systemd/resolved.conf.d/

        # Create custom configuration for DNS if it doesn't already exist
        if [ ! -f /etc/systemd/resolved.conf.d/psiphon-tun.conf ]; then
            # Create custom configuration for DNS
            cat > /etc/systemd/resolved.conf.d/psiphon-tun.conf <<EOF
[Resolve]
DNS=8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
DNSOverTLS=no
DNSSEC=no
Domains=~.
EOF
        fi
        # Set DNS routing for the TUN interface
        resolvectl dns "$TUN_INTERFACE" 8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
        resolvectl domain "$TUN_INTERFACE" "~."
        resolvectl default-route "$TUN_INTERFACE" yes

        # Restart systemd-resolved to apply changes
        systemctl restart systemd-resolved
    fi
    success "TUN interface configured with IPv4 and IPv6"

}

# Setup TUN interface
function setup_tun_interface() {
    log "Setting up TUN interface..."

    # # DYNAMIC INTERFACE DETECTION: Re-determine bypass interface if not set or in service mode
    # # In systemd service mode, the network may not have been ready when the script loaded,
    # # so we need to re-detect the bypass interface now
    # if [[ -z "$TUN_BYPASS_INTERFACE" ]] || [[ "$SERVICE_MODE" == "true" ]]; then
    #     log "Re-detecting bypass interface for current network state..."
    #     local detected_interface
    #     detected_interface=$(ip -json route get 8.8.8.8 2>/dev/null | jq -r '.[0].dev // empty' ||
    #                                ip -json link show | jq -r '.[] | select(.link_type!="loopback") | .ifname' | head -n1)
        
    #     if [[ -n "$detected_interface" ]]; then
    #         if [[ "$TUN_BYPASS_INTERFACE" != "$detected_interface" ]]; then
    #             log "Bypass interface changed from '$TUN_BYPASS_INTERFACE' to '$detected_interface'"
    #         fi
    #         TUN_BYPASS_INTERFACE="$detected_interface"
    #     elif [[ -z "$TUN_BYPASS_INTERFACE" ]]; then
    #         error "Could not determine bypass interface - network may not be ready"
    #         error "Initial detection also failed. Check network connectivity."
    #         return 1
    #     else
    #         log "Using previously detected bypass interface: $TUN_BYPASS_INTERFACE"
    #     fi
    # fi

    # log "Using bypass interface: $TUN_BYPASS_INTERFACE"

    # Create TUN interface if it doesn't exist
    if ! ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        if ! ip tuntap add dev "$TUN_INTERFACE" mode tun user "$PSIPHON_USER" group "$PSIPHON_GROUP"; then
            error "Failed to create TUN interface"
            cleanup_routing
            return 1
        fi
    fi

    # Configure IPv4 interface
    if ! ip addr flush dev "$TUN_INTERFACE" 2>&1; then
        warning "Failed to flush TUN interface: $?"
    fi

    # Configure IPv4 point-to-point addresses
    if ! ip addr add "$TUN_IP" peer "$TUN_PEER_IP" dev "$TUN_INTERFACE" 2>&1; then
        error "Failed to add IPv4 point-to-point address to TUN interface"
        cleanup_routing
        return 1
    fi

    # Configure IPv6 interface with unique local address
    if ! ip -6 addr add "$TUN_IP6/64" dev "$TUN_INTERFACE" 2>&1; then
        warning "Failed to add IPv6 address to TUN interface: $?"
    fi

    # Bring up interface and wait for it to be ready
    ip link set "$TUN_INTERFACE" up

    # Wait for interface to be ready (both IPv4 and IPv6)
    local timeout=10
    while [ "$timeout" -gt 1 ]; do
        if ip addr show dev "$TUN_INTERFACE" | grep -q "inet.*$TUN_IP" && \
           ip addr show dev "$TUN_INTERFACE" | grep -q "inet6.*$TUN_IP6"; then
            break
        fi
        sleep 1
        ((timeout--))
    done

    if [ "$timeout" -eq 0 ]; then
        warning "Timeout waiting for TUN interface to be fully ready"
    else
        log "TUN interface ready with both IPv4 and IPv6 addresses"
    fi

    # Verify psiphon-user can access TUN device before proceeding
    # This prevents silent failures when Psiphon later tries to bind to the TUN interface
    log "Verifying psiphon-user access to TUN device..."
    if ! sudo -u "$PSIPHON_USER" test -r "/dev/net/tun" 2>/dev/null || \
       ! sudo -u "$PSIPHON_USER" test -w "/dev/net/tun" 2>/dev/null; then
        error "User $PSIPHON_USER cannot read/write /dev/net/tun device"
        error "Check TUN interface permissions and group membership"
        cleanup_routing
        return 1
    fi
    log "✓ TUN device access verified for psiphon-user"

    # DON'T add default routes here - wait for RA processing
    log "TUN interface configured (routes will be added after RA processing)"

    # Update DNS configuration after routes are established
    change_dns_config

    # Verify DNS system is ready before proceeding
    # systemd-resolved may need time to reload configuration
    log "Waiting for DNS system to stabilize..."
    local dns_wait=0
    local dns_max_wait=10
    while [ $dns_wait -lt $dns_max_wait ]; do
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            log "✓ systemd-resolved is active"
            break
        fi
        sleep 1
        dns_wait=$((dns_wait + 1))
    done

    if [ $dns_wait -eq $dns_max_wait ]; then
        warning "systemd-resolved not confirmed active after ${dns_max_wait}s, but proceeding"
    fi

    success "TUN interface configured with IPv4 and IPv6 addresses"
}

# Network Security and Kill Switch Implementation
# Configures comprehensive traffic isolation and routing enforcement using nftables
# Configure nftables firewall rules for secure VPN operation
configure_nftables() {
    local tun_interface="$TUN_INTERFACE"
    local tun_subnet="$TUN_SUBNET"
    local tun_subnet6="$TUN_SUBNET6"
    local bypass_interface="$TUN_BYPASS_INTERFACE"
    
    # Get the numeric UID for psiphon-user (required for nftables meta skuid)
    local psiphon_uid
    psiphon_uid=$(id -u "$PSIPHON_USER" 2>/dev/null)
    if [ -z "$psiphon_uid" ]; then
        error "Failed to get UID for $PSIPHON_USER"
        return 1
    fi
    
    # Check if nftables is available and working
    if ! command -v nft &>/dev/null; then
        error "nftables (nft command) is not available. Please install the nftables package."
        return 1
    fi
    
    # Verify nftables can be used (test with a simple list command)
    local nft_test
    if ! nft_test=$(nft list tables 2>&1 >/dev/null); then
        error "nftables command failed. This may indicate:"
        error "  1. nftables service is not running (try: systemctl start nftables)"
        error "  2. Missing kernel support for nftables"
        error "  3. Permission issues (this should be run as root)"
        error "  Raw error: $nft_test"
        return 1
    fi
    
    log "Configuring nftables with UID $psiphon_uid for $PSIPHON_USER"
    
    # Create a temporary file to build the nftables ruleset
    # This ensures safe configuration before applying
    local nft_ruleset_file
    nft_ruleset_file=$(mktemp) || {
        error "Failed to create temporary file for nftables configuration"
        return 1
    }

    # shellcheck disable=SC2064
    # Double quotes intentionally used here to capture the local variable value
    # while the function is still executing. Single quotes would cause the
    # variable to be undefined when the trap fires (out of scope).
    trap "rm -f '$nft_ruleset_file'" RETURN
    
    # Generate the nftables ruleset with proper variable expansion
    cat > "$nft_ruleset_file" << EOF
# Define filter table (inet covers both IPv4 and IPv6)
table inet psiphon_filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Allow established/related connections first
        ct state {established, related} accept
        
        # Allow traffic through TUN interface (both directions)
        iifname "$tun_interface" accept
        oifname "$tun_interface" accept
    }
    
    chain output {
        type filter hook output priority 0; policy drop;
        
        # Allow loopback traffic (both directions for local services)
        iifname "lo" accept
        oifname "lo" accept
        
        # Allow established/related connections first
        ct state {established, related} accept
        
        # Allow Psiphon user (UID $psiphon_uid) to use any interface (needed for tunnel establishment)
        # This must come before TUN-only rule to allow tunnel bootstrap
        meta skuid $psiphon_uid accept
        
        # Allow TUN interface traffic for everyone else
        oifname "$tun_interface" accept
        
        # Everyone else can ONLY use TUN interface (default DROP policy handles blocking)
    }
}

# IPv4 NAT table
table ip psiphon_nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        
        # NAT for IPv4 traffic from TUN subnet going out through bypass interface
        ip saddr $tun_subnet oifname "$bypass_interface" masquerade
    }
}

# IPv6 NAT table
table ip6 psiphon_nat6 {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        
        # NAT for IPv6 traffic from TUN subnet going out through bypass interface
        ip6 saddr $tun_subnet6 oifname "$bypass_interface" masquerade
    }
}
EOF
    
    # Validate the ruleset before applying (show errors for debugging)
    local validation_output
    if ! validation_output=$(nft -c -f "$nft_ruleset_file" 2>&1); then
        error "nftables ruleset validation failed. Generated ruleset is invalid."
        error "Validation error details:"
        echo "$validation_output" | while read -r line; do
            error "  $line"
        done
        # Also log the generated ruleset for debugging
        error "Generated ruleset that failed validation:"
        while read -r line; do
            error "  $line"
        done < "$nft_ruleset_file"
        return 1
    fi
    
    log "nftables ruleset validation passed"
    
    # Apply the validated ruleset
    local apply_error
    local apply_status
    apply_error=$(nft -f "$nft_ruleset_file" 2>&1)
    apply_status=$?
    
    if [ $apply_status -ne 0 ]; then
        error "Failed to apply nftables rules (exit code: $apply_status)"
        error "Application error details:"
        echo "$apply_error" | while read -r line; do
            error "  $line"
        done
        error "Generated ruleset that failed application:"
        while read -r line; do
            error "  $line"
        done < "$nft_ruleset_file"
        return 1
    fi
    
    if [ -n "$apply_error" ]; then
        log "nftables applied with warnings/output: $apply_error"
    fi
    
    # Verify the rules were actually applied
    
    log "Verifying nftables rules were applied successfully..."
    
    # First check if nft command exists
    if ! command -v nft >/dev/null 2>&1; then
        error "nft command not found - nftables may not be installed"
        return 1
    fi
    
    # Check if the table exists
    local table_check
    if ! table_check=$(nft list tables inet 2>&1); then
        error "Failed to list nftables tables"
        error "  Error: $table_check"
        return 1
    fi
    
    if ! nft list chain inet psiphon_filter output >/dev/null 2>&1; then
        error "nftables rules were not properly applied - OUTPUT chain not found"
        error "Available tables:"
        nft list tables 2>&1 | while read -r line; do
            error "  $line"
        done
        error "Attempting to list all rules for debugging:"
        nft list ruleset 2>&1 | while read -r line; do
            error "  $line"
        done
        return 1
    fi
    
    log "✓ nftables rules successfully applied and verified"
    
    # Save nftables rules for persistence
    log "Saving nftables configuration for persistence..."
    
    # Create /etc/nftables directory if it doesn't exist
    mkdir -p "/etc/nftables" 2>/dev/null || true
    
    # Save the validated ruleset for persistence
    # Use the temporary file we already validated
    if ! cp "$nft_ruleset_file" "/etc/nftables/psiphon-tun.nft" 2>/dev/null; then
        warning "Failed to save nftables ruleset to /etc/nftables/psiphon-tun.nft (persistence may not work across reboots)"
    else
        log "nftables ruleset saved to /etc/nftables/psiphon-tun.nft"
    fi
    
    # Ensure the main config file includes our ruleset
    if [ -f "/etc/nftables.conf" ]; then
        # Remove any old psiphon includes first to avoid duplicates
        sed -i '/psiphon-tun/d' "/etc/nftables.conf" 2>/dev/null || true
        # Add our include if not present
        if ! grep -q 'psiphon-tun.nft' "/etc/nftables.conf" 2>/dev/null; then
            if echo 'include "/etc/nftables/psiphon-tun.nft"' >> "/etc/nftables.conf" 2>/dev/null; then
                log "Added psiphon-tun.nft include to /etc/nftables.conf"
            fi
        fi
    else
        # If main config doesn't exist, create a new one with our rules
        if cat > "/etc/nftables.conf" << 'NFTCONF' 2>/dev/null
#!/usr/sbin/nft -f

flush ruleset

include "/etc/nftables/psiphon-tun.nft"
NFTCONF
        then
            log "Created /etc/nftables.conf with psiphon-tun.nft include"
        else
            warning "Failed to create /etc/nftables.conf (system may not auto-load rules on reboot)"
        fi
    fi
    
    # Ensure nftables service is enabled and running
    # Ensure nftables service is enabled and running
    if ! systemctl is-enabled nftables &>/dev/null 2>&1; then
        if systemctl enable nftables 2>/dev/null; then
            log "Enabled nftables service"
        else
            warning "Failed to enable nftables service (manual enabling may be required)"
        fi
    fi
    
    # IMPORTANT: Do NOT restart nftables service during Psiphon operation!
    # The nftables service runs 'flush ruleset' which would clear our in-memory rules.
    # Since we've already applied rules via 'nft -f', they're active in-memory.
    # Persistence is configured via /etc/nftables.conf includes, and will reload on system reboot.
    # Restarting the service would clear everything, breaking the kill switch!
    log "✓ nftables rules loaded and verified (NOT restarting service to preserve in-memory rules)"
    
    return 0
}

function setup_routing() {
    log "Setting up routing and firewall rules..."

    # === WARP Integration Check === (WARP is optional)
    if is_warp_connected; then
        log "WARP detected and connected via interface: $WARP_INTERFACE"
        log "Configuring Psiphon → WARP → Internet routing chain"
        log "May not work very well for now"
    fi

    # === Base Security Configuration ===
    # Enable controlled forwarding for tunnel operations
    # Required for proper VPN functionality while maintaining security
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    echo 1 > /proc/sys/net/ipv6/conf/default/forwarding

    # Add to sysctl.conf for persistence
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        {
            echo "net.ipv4.ip_forward=1"
            echo "net.ipv6.conf.all.forwarding=1"
            echo "net.ipv6.conf.default.forwarding=1"
        } >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    fi

    # # === Firewall Manager Compatibility ===
    # # Stop firewalld if running to prevent interference with nftables rules
    # # firewalld manages its own nftables tables and will clear our rules on reload
    # log "Checking for firewall managers that might interfere..."
    # if systemctl is-active --quiet firewalld 2>/dev/null; then
    #     log "firewalld is active - stopping to prevent nftables rule conflicts"
    #     if systemctl stop firewalld 2>/dev/null; then
    #         log "✓ firewalld stopped (we'll manage firewall rules directly via nftables)"
    #     else
    #         warning "Could not stop firewalld (may have permission issues)"
    #     fi
    # fi

    # Create initial nftables ruleset
    log "Setting up nftables ruleset..."

    # Configure nftables rules
    if ! configure_nftables; then
        error "Failed to set up nftables rules"
        cleanup_routing
        return 1
    fi

    success "IPv4 and IPv6 routing configured with nftables"
}

# setting up IPv6 routing
function setup_ipv6_routing() {
    log "Setting up IPv6 system configuration..."

    # Enable IPv6 forwarding (already done in setup_routing, but being explicit here)
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    echo 1 > /proc/sys/net/ipv6/conf/default/forwarding

    # Ensure IPv6 is enabled on the TUN interface
    echo 0 > /proc/sys/net/ipv6/conf/"$TUN_INTERFACE"/disable_ipv6

    # Enable IPv6 privacy extensions
    echo 2 > /proc/sys/net/ipv6/conf/all/use_tempaddr
    echo 2 > /proc/sys/net/ipv6/conf/default/use_tempaddr

    # Disable IPv6 autoconfiguration on TUN interface
    echo 0 > /proc/sys/net/ipv6/conf/"$TUN_INTERFACE"/accept_ra
    echo 0 > /proc/sys/net/ipv6/conf/"$TUN_INTERFACE"/autoconf

    # Add persistent sysctl settings
    cat > /etc/sysctl.d/99-psiphon-ipv6.conf << EOF
# IPv6 forwarding
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1

# Privacy extensions
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2

# Disable autoconfiguration on TUN
net.ipv6.conf.$TUN_INTERFACE.accept_ra=0
net.ipv6.conf.$TUN_INTERFACE.autoconf=0
EOF

    # Apply sysctl settings
    sysctl --system >/dev/null 2>&1 || true

    success "IPv6 system configuration completed"
}

# Waits for IPv4 routing to stabilize
function wait_for_ipv4_routing() {
    log "Waiting for IPv4 routing to stabilize..."
    local timeout=10
    local count=0

    while [ $count -lt $timeout ]; do
        # Check if default route exists through TUN interface with peer gateway
        if ip route show default | grep -q "via $TUN_PEER_IP dev $TUN_INTERFACE"; then
            log "IPv4 routing stabilized"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done

    warning "IPv4 routing didn't stabilize within $timeout seconds"
    log "Current IPv4 routes:"
    ip route show | head -5
    return 1
}

# Comprehensive network readiness check
function check_network_readiness() {
    log "Performing comprehensive network readiness check..."
    local issues=0

    # Check TUN interface exists and is UP
    if ! ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        error "TUN interface $TUN_INTERFACE does not exist"
        issues=$((issues + 1))
    elif ! ip link show "$TUN_INTERFACE" | grep -q "UP"; then
        error "TUN interface $TUN_INTERFACE is not UP"
        issues=$((issues + 1))
    else
        log "✓ TUN interface $TUN_INTERFACE is UP"
    fi

    # Check TUN interface has IPv4 address
    if ! ip addr show "$TUN_INTERFACE" | grep -q "inet.*$TUN_PEER_IP"; then
        error "TUN interface missing IPv4 address $TUN_PEER_IP"
        issues=$((issues + 1))
    else
        log "✓ TUN interface has IPv4 address"
    fi

    # Check TUN interface has IPv6 address
    if ! ip addr show "$TUN_INTERFACE" | grep -q "inet6.*$TUN_IP6"; then
        warning "TUN interface missing IPv6 address $TUN_IP6"
    else
        log "✓ TUN interface has IPv6 address"
    fi

    # Check bypass interface exists and is UP
    if ! ip link show "$TUN_BYPASS_INTERFACE" >/dev/null 2>&1; then
        error "Bypass interface $TUN_BYPASS_INTERFACE does not exist"
        issues=$((issues + 1))
    elif ! ip link show "$TUN_BYPASS_INTERFACE" | grep -q "UP"; then
        error "Bypass interface $TUN_BYPASS_INTERFACE is not UP"
        issues=$((issues + 1))
    else
        log "✓ Bypass interface $TUN_BYPASS_INTERFACE is UP"
    fi

    # Check IPv4 default route through TUN (Only should be used after psiphon connected)
    if ! ip route show default | grep -q "$TUN_INTERFACE"; then
        warning "No IPv4 default route through $TUN_INTERFACE"
    else
        log "✓ IPv4 default route configured"
    fi

    # Check IPv6 default route through TUN (Only should be used after psiphon connected)
    if ! ip -6 route show default | grep -q "$TUN_INTERFACE"; then
        warning "No IPv6 default route through $TUN_INTERFACE"
    else
        log "✓ IPv6 default route configured"
    fi

    # Check nftables kill switch is active
    local nft_output
    if nft_output=$(nft list chain inet psiphon_filter output 2>&1) && echo "$nft_output" | grep -q 'policy drop'; then
        log "✓ nftables kill switch active (OUTPUT DROP policy)"
    else
        error "nftables kill switch (OUTPUT DROP policy) not active"
        # Provide diagnostic info
        if ! command -v nft >/dev/null 2>&1; then
            error "  Diagnostic: nft command not available"
        elif [ -z "$nft_output" ]; then
            error "  Diagnostic: psiphon_filter table or output chain not found"
            log "  Available nftables tables:"
            nft list tables 2>&1 | sed 's/^/    /'
        else
            error "  Diagnostic: OUTPUT chain found but missing DROP policy"
            error "  Chain contents:"
            echo "$nft_output" | awk '{print "    " $0}'
        fi
        issues=$((issues + 1))
    fi

    # Verify nftables rules for psiphon-user (check for meta skuid rule)
    if [ -n "$nft_output" ] && echo "$nft_output" | grep -qE 'meta skuid [0-9]+'; then
        log "✓ nftables psiphon-user rules active"
    else
        warning "nftables psiphon-user rules may not be properly configured"
        # Don't count as fatal since connection might still work
    fi

    # Verify TUN interface rules exist
    if [ -n "$nft_output" ] && echo "$nft_output" | grep -qE "oifname \"$TUN_INTERFACE\""; then
        log "✓ nftables TUN interface rules active"
    else
        error "nftables TUN interface rules not found"
        if [ -n "$nft_output" ]; then
            error "  Diagnostic: OUTPUT chain found but missing TUN interface rules"
            error "  Looking for: oifname \"$TUN_INTERFACE\""
            error "  Actual chain contents:"
            echo "$nft_output" | awk '{print "    " $0}'
        fi
        issues=$((issues + 1))
    fi

    log "✓ Network configuration complete"
    if [ $issues -eq 0 ]; then
        success "Network readiness check passed"
        return 0
    else
        error "Network readiness check failed with $issues critical issues"
        cleanup_routing
        return 1
    fi
}

# Network diagnostic function for troubleshooting
function diagnose_network_issues() {
    log "=== Network Diagnostic Report ==="
    log "Gathering comprehensive network state information..."

    # Basic interface information
    log ""
    log "1. Interface Status:"
    log "TUN Interface ($TUN_INTERFACE):"
    if ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        ip link show "$TUN_INTERFACE" | sed 's/^/   /'
        ip addr show "$TUN_INTERFACE" | grep -E "(inet|inet6)" | sed 's/^/   /'
    else
        log "   ERROR: TUN interface does not exist"
    fi

    log ""
    log "Bypass Interface ($TUN_BYPASS_INTERFACE):"
    if ip link show "$TUN_BYPASS_INTERFACE" >/dev/null 2>&1; then
        ip link show "$TUN_BYPASS_INTERFACE" | head -1 | sed 's/^/   /'
        ip addr show "$TUN_BYPASS_INTERFACE" | grep -E "(inet|inet6)" | head -2 | sed 's/^/   /'
    else
        log "   ERROR: Bypass interface does not exist"
    fi

    # Routing information
    log ""
    log "2. Routing Tables:"
    log "IPv4 Default Routes:"
    ip route show default | head -5 | sed 's/^/   /' || log "   No IPv4 default routes"

    log "IPv6 Default Routes:"
    ip -6 route show default | head -5 | sed 's/^/   /' || log "   No IPv6 default routes"

    log "TUN Interface Routes:"
    ip route show dev "$TUN_INTERFACE" | head -3 | sed 's/^/   /' || log "   No routes via TUN interface"

    # Firewall status
    log ""
    log "3. Firewall Status:"
    log "nftables ruleset:"
    nft list ruleset 2>/dev/null || log "   Error: nftables not available or no rules set"

    # Check specific security rules
    log ""
    log "Key security rules:"
    if nft list chain inet psiphon_filter output 2>/dev/null | grep -q 'policy drop'; then
        log "✓ OUTPUT chain policy: DROP (Kill switch active)"
    else
        log "✗ OUTPUT chain policy not set to DROP"
    fi
    
    if nft list chain inet psiphon_filter output 2>/dev/null | grep -qE 'meta skuid [0-9]+'; then
        log "✓ psiphon-user rules active"
    else
        log "✗ psiphon-user rules missing or not properly configured"
    fi

    if nft list chain inet psiphon_filter output 2>/dev/null | grep -qE "oifname \"$TUN_INTERFACE\""; then
        log "✓ TUN interface rules active (oifname $TUN_INTERFACE)"
    else
        log "✗ TUN interface rules missing"
    fi

    # Process status
    log ""
    log "4. Process Status:"
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        local pids
        pids=$(pgrep -f "psiphon-tunnel-core")
        log "Psiphon processes: $pids"
        for pid in $pids; do
            if ps -p "$pid" -o pid,ppid,user,args --no-headers 2>/dev/null; then
                ps -p "$pid" -o pid,ppid,user,args --no-headers | sed 's/^/   /'
            fi
        done
    else
        log "   No Psiphon processes found"
    fi

    # DNS configuration
    log ""
    log "5. DNS Configuration:"
    if [[ -f /etc/resolv.conf ]]; then
        log "Current resolv.conf:"
        head -5 /etc/resolv.conf | sed 's/^/   /'
    fi

    # DNS leak detection (passive and active checks)
    log ""
    log "5.a DNS Leak Detection Tests:"
    
    # Only perform DNS leak detection if Psiphon is connected
    if ! pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        log "   - Psiphon not running, skipping DNS leak tests (results invalid without tunnel)"
    else
        # Passive check: verify routes to configured DNS servers go via TUN interface
        IFS=',' read -ra _dns4 <<< "$TUN_DNS_SERVERS"
        local _dns_leak_found=0
        
        log "   Checking IPv4 DNS server routes:"
        for _dns in "${_dns4[@]}"; do
            _dns=$(echo "$_dns" | xargs)
            if [ -z "$_dns" ]; then
                continue
            fi
            _route=$(ip route get "$_dns" 2>/dev/null || true)
            if echo "$_route" | grep -q "dev $TUN_INTERFACE"; then
                log "      ✓ $_dns via $TUN_INTERFACE (no leak)"
            else
                log "      ✗ $_dns NOT via $TUN_INTERFACE (LEAK DETECTED). Route: ${_route:-N/A}"
                _dns_leak_found=1
            fi
        done

        IFS=',' read -ra _dns6 <<< "$TUN_DNS_SERVERS6"
        log "   Checking IPv6 DNS server routes:"
        for _dns in "${_dns6[@]}"; do
            _dns=$(echo "$_dns" | xargs)
            if [ -z "$_dns" ]; then
                continue
            fi
            _route6=$(ip -6 route get "$_dns" 2>/dev/null || true)
            if echo "$_route6" | grep -q "dev $TUN_INTERFACE"; then
                log "      ✓ $_dns via $TUN_INTERFACE (no leak)"
            else
                log "      ✗ $_dns NOT via $TUN_INTERFACE (LEAK DETECTED). Route: ${_route6:-N/A}"
                _dns_leak_found=1
            fi
        done

        # Active check: attempt DNS resolution via configured servers if `dig` is available
        if command -v dig >/dev/null 2>&1; then
            log ""
            log "   Active DNS resolution tests (via dig, timeout 5s):"
            for _dns in "${_dns4[@]}"; do
                _dns=$(echo "$_dns" | xargs)
                if [ -z "$_dns" ]; then
                    continue
                fi
                if timeout 5 dig +time=2 +tries=1 @"$_dns" +short example.com >/dev/null 2>&1; then
                    log "      ✓ Resolution via $_dns succeeded"
                else
                    log "      ✗ Resolution via $_dns failed (timeout or unreachable)"
                fi
            done
        else
            log "   - dig not installed, skipping active resolution tests"
        fi

        if [ $_dns_leak_found -eq 0 ]; then
            log ""
            log "   ✓ DNS LEAK TEST PASSED: All DNS servers routed through tunnel"
        else
            log ""
            log "   ✗ DNS LEAK TEST FAILED: Some DNS servers are NOT routed through tunnel"
        fi
    fi


    # Connectivity tests
    log ""
    log "6. Connectivity Tests:"

    # Test IPv4 connectivity through TUN (only if Psiphon is running)
    log "IPv4 connectivity test through TUN (HTTP):"
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        if timeout 8 curl -4 -s --interface "$TUN_INTERFACE" --connect-timeout 5 -o /dev/null http://www.google.com/generate_204 2>/dev/null; then
            log "   ✓ IPv4 HTTP through TUN successful"
        else
            log "   ✗ IPv4 HTTP through TUN failed"
        fi
    else
        log "   - Psiphon not running, skipping connectivity test"
    fi

    # Test IPv6 connectivity through TUN (only if Psiphon is running)
    log "IPv6 connectivity test through TUN (HTTP):"
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        if timeout 8 curl -6 -s --interface "$TUN_INTERFACE" --connect-timeout 5 -o /dev/null http://www.google.com/generate_204 2>/dev/null; then
            log "   ✓ IPv6 HTTP through TUN successful"
        else
            log "   ✗ IPv6 HTTP through TUN failed"
        fi
    else
        log "   - Psiphon not running, skipping connectivity test"
    fi

    # System information
    log ""
    log "7. System Information:"
    log "Kernel version: $(uname -r)"
    log "Available network namespaces: $(ip netns list 2>/dev/null | wc -l)"

    # Check for conflicting services
    log ""
    log "8. Potential Conflicts:"
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        log "   WARNING: NetworkManager is active (may interfere)"
    fi

    if systemctl is-active systemd-networkd >/dev/null 2>&1; then
        log "   INFO: systemd-networkd is active"
    fi

    if pgrep -f "warp-svc" >/dev/null 2>&1; then
        log "   INFO: WARP service detected"
    fi

    log ""
    log "=== End Diagnostic Report ==="
    success "Network diagnostic complete - review output above for issues"
}

# This waits for the kernel to fully process the manual IPv6 configuration,
# not for any actual Router Advertisements
function wait_for_ra_processing() {
    log "Waiting for TUN interface to reach stable IPv6 state..."

    local timeout=15
    local elapsed=0
    local stable_count=0
    local required_stable_cycles=3
    local prev_addr_state=""

    # Wait for TUN interface IPv6 addresses and routes to stabilize
    # This is more robust than monitoring all routes - we only care about TUN
    while [ $elapsed -lt $timeout ]; do
        # Check TUN interface actual state (addresses and routes together)
        local current_state
        current_state=$(ip -6 addr show "$TUN_INTERFACE" 2>/dev/null | md5sum || echo "")
        current_state+=$(ip -6 route show dev "$TUN_INTERFACE" 2>/dev/null | md5sum || echo "")

        if [ -z "$prev_addr_state" ]; then
            # First iteration - just record the snapshot
            prev_addr_state="$current_state"
            log "TUN interface IPv6 state monitoring started... ($elapsed/$timeout)"
        elif [ "$current_state" = "$prev_addr_state" ]; then
            # State unchanged from last check
            stable_count=$((stable_count + 1))
            log "TUN IPv6 state stable ($stable_count/$required_stable_cycles)... ($elapsed/$timeout)"

            # If we've seen stable state for required_stable_cycles, we're done
            if [ $stable_count -ge $required_stable_cycles ]; then
                log "TUN interface IPv6 configuration stabilized after $elapsed seconds"
                break
            fi
        else
            # State changed - reset stability counter
            stable_count=0
            log "TUN IPv6 state changed, reset counter... ($elapsed/$timeout)"
            prev_addr_state="$current_state"
        fi

        # Wait before next check
        sleep 1
        elapsed=$((elapsed + 1))
    done

    if [ $elapsed -ge $timeout ]; then
        warning "TUN IPv6 state didn't stabilize within $timeout seconds, proceeding anyway"
    fi

    # Log final TUN IPv6 state
    log "Final TUN IPv6 state:"
    ip -6 addr show "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route show dev "$TUN_INTERFACE" 2>/dev/null || true

    success "IPv6 TUN is stable now (waited $elapsed seconds)"
}

function setup_tun_routes_after_ra() {
    log "Setting up TUN default routes after Psiphon connection established..."
    log "This prevents self-routing by adding routes only after Psiphon binds to bypass interface"

    # Explicit connection verification
    # setup_tun_routes_after_ra() is called after start_services() returns, but
    # Psiphon may not yet be fully connected. The wait_for_psiphon_connection() function
    # called inside start_psiphon() ensures connection before we add default routes.
    # However, we verify again here to be explicit about the dependency and catch any edge cases.
    log "Verifying Psiphon connection before route setup..."

    # Verify Psiphon is actually connected before setting up routes
    local connection_verified="false"
    if [[ "$SERVICE_MODE" == "true" ]]; then
        # Service mode: check journalctl logs
        if journalctl -u $SERVICE_BINARY_NAME.service -n 10 --no-pager 2>/dev/null | grep -q "ConnectedServerRegion"; then
            connection_verified="true"
        fi
    else
        # Script mode: check log file
        if [[ -f "$PSIPHON_LOG_FILE" ]] && tail -n 10 "$PSIPHON_LOG_FILE" 2>/dev/null | grep -q "ConnectedServerRegion"; then
            connection_verified="true"
        fi
    fi

    if [[ "$connection_verified" != "true" ]]; then
        error "Psiphon connection not verified - refusing to set up default routes"
        error "This prevents potential self-routing issues"
        error "Psiphon process may still be connecting. Check logs:"
        if [[ "$SERVICE_MODE" == "true" ]]; then
            error "  journalctl -u $SERVICE_BINARY_NAME.service -f"
        else
            error "  tail -f $PSIPHON_LOG_FILE"
        fi
        return 1
    fi

    log "Psiphon connection verified - proceeding with route setup"

    # Delete any existing default routes for TUN interface first
    ip route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true

    # Add explicit route for TUN subnet if needed
    if ! ip route show | grep -q "$TUN_SUBNET.*$TUN_INTERFACE"; then
        log "Adding TUN subnet route..."
        ip route add "$TUN_SUBNET" dev "$TUN_INTERFACE" 2>/dev/null || true
    fi

    # Set up IPv4 routing with retry logic
    log "Setting up IPv4 default route..."
    local retry_count=0
    local ipv4_success=false

    while [ $retry_count -lt 3 ]; do
        if ip route add default via "$TUN_PEER_IP" dev "$TUN_INTERFACE" metric 50 2>/dev/null; then
            log "IPv4 default route added successfully via $TUN_PEER_IP"
            ipv4_success=true
            break
        else
            warning "Failed to add IPv4 default route, attempt $((retry_count + 1))/3"
            # Clean up any partial routes
            ip route del default via "$TUN_PEER_IP" dev "$TUN_INTERFACE" 2>/dev/null || true
            sleep 2
            retry_count=$((retry_count + 1))
        fi
    done

    if [ "$ipv4_success" = false ]; then
        error "Failed to establish IPv4 default route after 3 attempts"
        log "Current IPv4 routes:"
        ip route show
        cleanup_routing
        return 1
    fi

    # Wait for IPv4 routing to stabilize
    if ! wait_for_ipv4_routing; then
        warning "IPv4 routing stabilization check failed, but continuing"
    fi

    # Set up IPv6 routing with retry logic
    log "Setting up IPv6 default route..."
    retry_count=0
    local ipv6_success=false

    while [ $retry_count -lt 3 ]; do
        if ip -6 route add default dev "$TUN_INTERFACE" metric 50 pref high 2>/dev/null; then
            log "IPv6 default route added successfully"
            ipv6_success=true
            break
        else
            warning "Failed to add IPv6 default route, attempt $((retry_count + 1))/3"
            # Clean up any partial routes
            ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true
            sleep 2
            retry_count=$((retry_count + 1))
        fi
    done

    if [ "$ipv6_success" = false ]; then
        warning "Failed to establish IPv6 default route after 3 attempts"
        log "Current IPv6 routes:"
        ip -6 route show | head -10
    fi

    # Verify both routing tables are working
    local final_check_count=0
    while [ $final_check_count -lt 5 ]; do
        local ipv4_route_ok=false
        local ipv6_route_ok=false

        if ip route show default | grep -q "via $TUN_PEER_IP dev $TUN_INTERFACE"; then
            ipv4_route_ok=true
        fi

        if ip -6 route show default | grep -q "$TUN_INTERFACE"; then
            ipv6_route_ok=true
        fi

        if [ "$ipv4_route_ok" = true ] || [ "$ipv6_route_ok" = true ]; then
            if [ "$ipv4_route_ok" = true ]; then
                log "IPv4 routing verified"
            fi
            if [ "$ipv6_route_ok" = true ]; then
                log "IPv6 routing verified"
            fi
            break
        fi

        sleep 1
        final_check_count=$((final_check_count + 1))
    done

    # Show routing table for debugging
    log "Final IPv4 routes:"
    ip route show | head -5
    log "Final IPv6 routes:"
    ip -6 route show | head -5

    success "TUN default routes configured after Psiphon connection established - no self-routing"
}

# systemd service psiphon binary restart helper
function systemd_psiphon_reload() {
    log "Reloading Psiphon binary service..."
    systemctl --no-block restart "$SERVICE_BINARY_NAME.service"
    success "Psiphon binary service reload command issued."
}


# Wait for Psiphon to establish connection
# Returns 0 on success, 1 on timeout/failure
function wait_for_psiphon_connection() {
    local timeout=$1
    local initial_timeout=$timeout
    
    log "Waiting for Psiphon to connect (timeout: ${timeout}s)..."
    sleep 2  # Initial wait before checking logs
    while [ "$timeout" -gt 1 ]; do
        if [[ "$SERVICE_MODE" == "true" ]]; then
            # Service mode: check systemctl status and journalctl logs
            if ! systemctl is-active --quiet $SERVICE_BINARY_NAME.service; then
                error "Psiphon service is not running"
                return 1
            fi

            # Check for connection in service logs - only recent entries
            # Use since to ensure we only check logs from after we started waiting
            if journalctl -u $SERVICE_BINARY_NAME.service --since "7 seconds ago" --no-pager 2>/dev/null | grep -q "ConnectedServerRegion"; then
                echo ""
                success "Psiphon connected successfully"
                return 0
            fi
        else
            # Script mode: check log file for NEW entries
            if [[ -f "$PSIPHON_LOG_FILE" ]]; then
                # Get only new lines from the log file
                local current_content
                current_content=$(tail -n 5 "$PSIPHON_LOG_FILE" 2>/dev/null)
                
                # Check if we found the connection marker in recent logs
                if echo "$current_content" | grep -q "ConnectedServerRegion"; then
                    echo ""
                    success "Psiphon connected successfully"
                    return 0
                fi
                
                # Also check if the log file is growing (process is active)
                if ! echo "$current_content" | grep -q "Error\|error\|FATAL\|fatal"; then
                    # No errors detected yet, keep waiting
                    :
                fi
            fi
        fi

        echo -n "."
        sleep 1
        ((timeout--))
    done

    echo ""
    error "Timeout waiting for Psiphon connection after $((initial_timeout - timeout)) seconds"
    return 1
}

# Secure Service Initialization
# Starts Psiphon with security-first approach:
# 1. Validates binary integrity
# 2. Ensures proper permissions
# 3. Implements process isolation
# 4. Establishes secure tunnel configuration
function start_psiphon() {
    log "Initializing secure Psiphon service with TUN support..."

    # Verify binary exists and is executable
    if [[ ! -f "$PSIPHON_BINARY" ]]; then
        error "Psiphon binary not found at $PSIPHON_BINARY"
        return 1
    fi

    # if [[ ! -x "$PSIPHON_BINARY" ]]; then
    #     error "Psiphon binary is not executable"
    #     return 1
    # fi

    # Verify config exists
    if [[ ! -f "$PSIPHON_CONFIG_FILE" ]]; then
        error "Psiphon config not found at $PSIPHON_CONFIG_FILE"
        return 1
    fi

    # Kill any existing Psiphon processes
    pkill -f "psiphon-tunnel-core.*$TUN_INTERFACE" 2>/dev/null || true
    # Wait for processes to actually terminate
    local wait_count=0
    while pgrep -f "psiphon-tunnel-core.*$TUN_INTERFACE" >/dev/null 2>&1 && [ $wait_count -lt 10 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    # In service mode, run as a systemd service
    if [[ "$SERVICE_MODE" == "true" ]]; then
        log "start the homepage monitor service..."
        systemctl start $SERVICE_HOMEPAGE_MONITOR.path
        # Wait for service to be active
        local wait_count=0
        while [ "$(systemctl is-active $SERVICE_HOMEPAGE_MONITOR.path 2>/dev/null)" != "active" ] && [ $wait_count -lt 10 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done
        log "start the psiphon binary service..."
        systemctl start $SERVICE_BINARY_NAME.service

        # Wait for Psiphon to connect using the helper function
        if ! wait_for_psiphon_connection 700; then
            error "Failed to establish Psiphon connection in service mode"
            log "Check service status with: systemctl status $SERVICE_BINARY_NAME.service"
            return 1
        fi

        log "Run: systemctl status $SERVICE_BINARY_NAME.service"
        log "   to check the status of the Psiphon binary service."
    else
        # For manual mode, keep the background process

        # Start Psiphon with native TUN support
        sudo -u "$PSIPHON_USER" "$PSIPHON_BINARY" \
            -config "$PSIPHON_CONFIG_FILE" \
            -dataRootDirectory "$INSTALL_DIR/data" \
            -tunDevice "$TUN_INTERFACE" \
            -tunBindInterface "$TUN_BYPASS_INTERFACE" \
            -tunDNSServers "$TUN_DNS_SERVERS,$TUN_DNS_SERVERS6" \
            -formatNotices \
            -useNoticeFiles 2>&1 | sudo -u "$PSIPHON_USER" tee -a "$PSIPHON_LOG_FILE" &

        local psiphon_pid=$!

        # Wait for process to initialize
        local wait_count=0
        while ! kill -0 "$psiphon_pid" 2>/dev/null && [ $wait_count -lt 10 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done

        # Wait for connection using the helper function
        if ! wait_for_psiphon_connection 700; then
            error "Failed to establish Psiphon connection in script mode"
            return 1
        fi

        # Open sponsor URL securely
        # We ignore errors here to avoid blocking startup
        if open_sponsor_url; then
            log "Sponsor URL opened successfully"
        else
            warning "Failed to open sponsor URL"
        fi

        # Verify process started successfully
        if [[ -z "$psiphon_pid" ]] || ! kill -0 "$psiphon_pid" 2>/dev/null; then
            error "Failed to start Psiphon or process died immediately"
            return 1
        fi

        # Write PID file atomically to prevent race conditions
        # Use temp file with restrictive permissions, then atomic rename
        local pid_temp_file="${PID_FILE}.tmp.$$"
        {
            echo "$psiphon_pid"
        } > "$pid_temp_file" || {
            error "Failed to write temporary PID file"
            kill -TERM "$psiphon_pid" 2>/dev/null || true
            return 1
        }
        # Set restrictive permissions before moving to final location
        chmod 600 "$pid_temp_file"
        chown root:root "$pid_temp_file"
        # Atomic rename prevents reading partial/corrupted PID file
        mv -f "$pid_temp_file" "$PID_FILE" || {
            error "Failed to move PID file to final location"
            rm -f "$pid_temp_file"
            kill -TERM "$psiphon_pid" 2>/dev/null || true
            return 1
        }
        # After successful atomic write, verify readability
        if [[ ! -r "$PID_FILE" ]]; then
            error "PID file not readable after creation"
            return 1
        fi
        chmod 644 $PID_FILE  # Relax permissions only after atomic write succeeds

        # Test if connection is actually working
        log "Verifying tunnel connectivity..."
        sleep 2
        local is_connected=0
        if timeout 10 curl -4s --interface "$TUN_INTERFACE" -m 7 https://youtube.com/generate_204 >/dev/null 2>&1; then
            log "IPv4 Connection verified through tunnel"
            ((is_connected++))
        else
            warning "Could not verify tunnel IPv4 connectivity, but proceeding"
        fi
        sleep 1
        if timeout 10 curl -6s --interface "$TUN_INTERFACE" -m 7 https://youtube.com/generate_204 >/dev/null 2>&1; then
            log "IPv6 Connection verified through tunnel"
            ((is_connected++))
        else
            warning "Could not verify tunnel IPv6 connectivity, but proceeding"
        fi

        if [[ $is_connected -lt 2 ]]; then
            warning "Consider the script manually!"
        fi

        # Final verification
        if ! kill -0 "$psiphon_pid" 2>/dev/null; then
            error "Psiphon process died after startup"
            return 1
        fi

        success "Psiphon started successfully with native TUN support (PID: $psiphon_pid)"
    fi
}

function open_sponsor_url() {
    # Open sponsor URL with enhanced security
    if [[ -z "$PSIPHON_SPONSOR_HOMEPAGE_PATH" || ! -f "$PSIPHON_SPONSOR_HOMEPAGE_PATH" ]]; then
        warning "Invalid or missing homepage file"
        return 1
    fi

    # Verify file permissions and ownership
    local file_perms
    file_perms=$(stat -c "%a" "$PSIPHON_SPONSOR_HOMEPAGE_PATH" 2>/dev/null)
    if [[ "$file_perms" != "600" && "$file_perms" != "644" ]]; then
        warning "Invalid homepage file permissions: $file_perms (expected 600 or 644)"
        return 1
    fi

    # Extract and validate URL using jq with explicit error checking
    local SPONSOR_URL
    if ! SPONSOR_URL=$(jq -r '.data.url // empty' "$PSIPHON_SPONSOR_HOMEPAGE_PATH" 2>/dev/null); then
        warning "Failed to parse homepage JSON file"
        return 1
    fi

    # Enhanced URL validation
    if [[ -z "$SPONSOR_URL" || "$SPONSOR_URL" == "null" ]]; then
        warning "Empty or null sponsor URL"
        return 1
    fi

    # Primary security check: URL pattern validation
    local url_regex='^https://ipfounder\.net/\?sponsor_id=[A-Za-z0-9]+[^[:space:]]*$'
    if [[ ! "$SPONSOR_URL" =~ $url_regex ]]; then
        warning "Invalid sponsor URL format detected"
        log "Security: Blocked attempt to open non-conforming URL"
        return 1
    fi

    # Secondary security check: Additional URL validation
    if [[ ${#SPONSOR_URL} -gt 500 ]]; then
        warning "URL exceeds maximum allowed length"
        return 1
    fi

    # Additional security: Check for suspicious characters
    if echo "$SPONSOR_URL" | grep -q '[;<>`|]'; then
        warning "URL contains suspicious characters"
        log "Security: Blocked URL with potentially dangerous characters"
        return 1
    fi

    # Get the active logged-in user with validation
    local ACTIVE_USER
    ACTIVE_USER="$(logname)"
    if [[ -z "$ACTIVE_USER" || "$ACTIVE_USER" == "root" ]]; then
        warning "No suitable non-root user found to open URL"
        return 1
    fi

    # Verify the user exists and is valid
    if ! id "$ACTIVE_USER" >/dev/null 2>&1; then
        warning "Invalid user account"
        return 1
    fi

    if ! command -v gio >/dev/null 2>&1; then
        warning "gio command not found"
        return 1
    fi

    log "Opening verified sponsor URL for user: $ACTIVE_USER"
    log "Sponsor URL: $SPONSOR_URL"

    # Execute with restricted environment
    (
        exec runuser -u "$ACTIVE_USER" \
        --whitelist-environment=DISPLAY,XAUTHORITY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR \
        -- gio open "$SPONSOR_URL" >/dev/null 2>&1 &
    )

    log "URL_OPEN: user=$ACTIVE_USER url_hash=$(echo -n "$SPONSOR_URL" | sha256sum | cut -d' ' -f1)"
    return 0
}

# Start all services
function start_services() {
    log "Starting services..."

    if start_psiphon; then
        success "Psiphon TUN service started successfully"
    else
        error "Failed to start services"
        stop_services
        return 1
    fi
}

function cleanup_routing() {
    log "Cleaning up routing and firewall rules..."

    # Reset nftables by only removing Psiphon-specific tables, preserving any unrelated nftables
    log "Removing Psiphon-specific nftables rules..."
    
    # Create a temporary cleanup script that only removes our tables
    local cleanup_script_file
    cleanup_script_file=$(mktemp) || {
        error "Failed to create temporary file for nftables cleanup script"
        return 1
    }

    # shellcheck disable=SC2064
    # Double quotes intentionally used here to capture the local variable value
    # while the function is still executing. Single quotes would cause the
    # variable to be undefined when the trap fires (out of scope).
    trap "rm -f '$cleanup_script_file'" RETURN
    
    # Only remove Psiphon-specific tables, leaving all other nftables intact
    cat > "$cleanup_script_file" << 'EOF'
# Remove only Psiphon-specific tables, preserve all other rules
delete table inet psiphon_filter
delete table ip psiphon_nat
delete table ip6 psiphon_nat6
EOF
    
    # Apply the cleanup script to remove only our tables
    if ! nft -f "$cleanup_script_file" 2>/dev/null; then
        # If nftables is not available or fails, log warning but continue with cleanup
        warning "Failed to remove Psiphon nftables rules (nftables may not be available or rules not loaded)"
    fi

    # The default routes are removed when the TUN interface is deleted, but we can be explicit
    ip route del default via "$TUN_PEER_IP" dev "$TUN_INTERFACE" 2>/dev/null || true
    ip route del default dev "$TUN_INTERFACE" 2>/dev/null || true
    ip -6 route del default dev "$TUN_INTERFACE" 2>/dev/null || true

    # Remove our custom nftables configuration if it exists
    # Do this AFTER resetting rules to ensure we can safely remove files
    if [ -f "/etc/nftables/psiphon-tun.nft" ]; then
        if rm -f "/etc/nftables/psiphon-tun.nft" 2>/dev/null; then
            log "Removed /etc/nftables/psiphon-tun.nft"
        else
            warning "Failed to remove /etc/nftables/psiphon-tun.nft (may require manual cleanup)"
        fi
    fi
    
    # Clean up include line from main nftables config
    if [ -f "/etc/nftables.conf" ]; then
        if sed -i '/psiphon-tun\.nft/d' "/etc/nftables.conf" 2>/dev/null; then
            log "Removed psiphon-tun.nft include from /etc/nftables.conf"
        else
            warning "Failed to remove include from /etc/nftables.conf (manual editing may be required)"
        fi
    fi

    # Reload nftables service to apply changes if it's running
    if systemctl is-active nftables &>/dev/null 2>&1; then
        if systemctl restart nftables 2>/dev/null; then
            log "Restarted nftables service with cleaned configuration"
        else
            warning "Failed to restart nftables service (changes may not apply until manual restart)"
        fi
    fi

    # # Restart firewalld if it was stopped by us (restores system firewall management)
    # if systemctl is-enabled firewalld &>/dev/null 2>&1; then
    #     log "Restarting firewalld to restore system firewall management..."
    #     if systemctl start firewalld 2>/dev/null; then
    #         log "✓ firewalld restarted successfully"
    #     else
    #         warning "Could not restart firewalld (manual restart may be needed)"
    #     fi
    # fi

    success "Routing and firewall rules cleaned up."
}

# Stop all services
function stop_services() {
    log "Stopping services..."

    local stopped_something=false

    if [[ "$SERVICE_MODE" == "true" ]]; then
        systemctl stop $SERVICE_HOMEPAGE_MONITOR.path
        if systemctl is-active --quiet $SERVICE_HOMEPAGE_MONITOR.path 2>/dev/null; then
            warning "Psiphon homepage monitor service did not stop cleanly, attempting to kill process..."
        else
            log "Psiphon homepage monitor service stopped."
            stopped_something=true
        fi

        systemctl stop $SERVICE_BINARY_NAME.service
        # Check if still running
        if systemctl is-active --quiet $SERVICE_BINARY_NAME.service 2>/dev/null; then
            warning "Psiphon binary service did not stop cleanly, attempting to kill process..."
        else
            log "Psiphon binary service stopped."
            stopped_something=true
        fi

        systemctl stop $SERVICE_HOMEPAGE_TRIGGER.service
        if systemctl is-active --quiet $SERVICE_HOMEPAGE_TRIGGER.service 2>/dev/null; then
            warning "Psiphon homepage trigger service did not stop cleanly."
        else
            log "Psiphon homepage trigger service stopped."
            stopped_something=true
        fi
    fi

    # Stop Psiphon
    if [[ -f $PID_FILE ]]; then
        local psiphon_pid
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            # Try graceful shutdown first
            kill -TERM "$psiphon_pid" 2>/dev/null || true
            # Wait for graceful termination
            local wait_count=0
            while kill -0 "$psiphon_pid" 2>/dev/null && [ $wait_count -lt 7 ]; do
                sleep 1
                wait_count=$((wait_count + 1))
            done
            # Force kill if still running
            if kill -0 "$psiphon_pid" 2>/dev/null; then
                kill -KILL "$psiphon_pid" 2>/dev/null || true
                sleep 1
            fi
            stopped_something=true
        fi
        rm -f $PID_FILE
    fi

    # Kill any remaining Psiphon processes
    if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        pkill -f "psiphon-tunnel-core" 2>/dev/null || true
        stopped_something=true
    fi

    # Clean up routing and firewall rules before taking down the interface
    cleanup_routing

    # Reset systemd-resolved configuration
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        log "Resetting systemd-resolved configuration..."
        rm -f /etc/systemd/resolved.conf.d/psiphon-tun.conf
        systemctl restart systemd-resolved
    else
        # Restore original DNS configuration
        if [ -f /etc/resolv.conf.original ]; then
            cp -fP /etc/resolv.conf.original /etc/resolv.conf
        fi
    fi

    # Bring down TUN interface
    if ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        ip link set "$TUN_INTERFACE" down 2>/dev/null || true
        ip link delete "$TUN_INTERFACE" 2>/dev/null || true
        stopped_something=true
    fi

    # Wait for services to actually stop
    local wait_count=0
    while (systemctl is-active $SERVICE_BINARY_NAME.service >/dev/null 2>&1 || systemctl is-active $SERVICE_HOMEPAGE_MONITOR.path >/dev/null 2>&1) && [ $wait_count -lt 7 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done

    if $stopped_something; then
        success "Services stopped successfully"
    else
        log "No running services found"
    fi
}

# Install everything
function install_shell() {
    log "Installing Psiphon TUN setup..."

    check_dependencies
    create_user
    create_directories
    check_and_update_psiphon
    create_psiphon_config

    create_systemd_services

    success "Psiphon TUN setup installed successfully"
    log "Use '$0 start' to start the service"
    log "Use 'sudo systemctl enable $SERVICE_CONFIGURE_NAME' to start automatically at boot"
    log "Use 'sudo systemctl start $SERVICE_CONFIGURE_NAME' to start via systemd"
}

# Uninstall everything
function uninstall() {
    log "Uninstalling Psiphon TUN setup..."

    # Stop services first
    stop_services
    # Disable and remove systemd configuration services
    if systemctl is-enabled --quiet "$SERVICE_CONFIGURE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_CONFIGURE_NAME" 2>/dev/null || true
    fi
    # Disable and remove systemd binary services
    if systemctl is-enabled --quiet "$SERVICE_BINARY_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_BINARY_NAME" 2>/dev/null || true
    fi
    # Disable and remove homepage monitor service
    if systemctl is-enabled --quiet "$SERVICE_HOMEPAGE_MONITOR" 2>/dev/null; then
        systemctl disable "$SERVICE_HOMEPAGE_MONITOR" 2>/dev/null || true
    fi
    # Disable and remove homepage trigger service
    if systemctl is-enabled --quiet "$SERVICE_HOMEPAGE_TRIGGER" 2>/dev/null; then
        systemctl disable "$SERVICE_HOMEPAGE_TRIGGER" 2>/dev/null || true
    fi

    systemctl stop $SERVICE_CONFIGURE_NAME.service
    if systemctl is-active --quiet $SERVICE_CONFIGURE_NAME.service 2>/dev/null; then
        warning "Psiphon configuration service did not stop cleanly."
    else
        log "Psiphon configuration service stopped."
        stopped_something=true
    fi

    rm -f /etc/systemd/system/$SERVICE_CONFIGURE_NAME.service
    rm -f /etc/systemd/system/$SERVICE_BINARY_NAME.service
    rm -f /etc/systemd/system/$SERVICE_HOMEPAGE_MONITOR.path
    rm -f /etc/systemd/system/$SERVICE_HOMEPAGE_TRIGGER.service

    systemctl daemon-reload 2>/dev/null || true


    # Remove installation directory
    if [[ -d "$INSTALL_DIR" ]]; then
        read -p "Remove installation directory $INSTALL_DIR? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            log "Installation directory removed"
        fi
    fi

    # Remove user and group
    read -p "Remove user and group ($PSIPHON_USER, $PSIPHON_GROUP)? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$PSIPHON_USER" 2>/dev/null || true
        groupdel "$PSIPHON_GROUP" 2>/dev/null || true
        log "User and group removed"
    fi

    success "Psiphon TUN setup uninstalled"
}

# Get WARP status
function get_warp_status() {
    ACTIVE_USER=$(logname)
    local status_output
    if [[ -x "$WARP_CLI_PATH" ]]; then
        status_output=$(exec runuser -u "$ACTIVE_USER" -- "$WARP_CLI_PATH" status 2>/dev/null || echo "ERROR")
        echo "$status_output"
    else
        echo "ERROR"
    fi
}

# Check if WARP is available and connected
function is_warp_connected() {
    [[ "$(get_warp_status)" == *"$WARP_STATUS_CONNECTED"* ]]
}

function get_warp_svc_pid() {
    # Get the PID of the warp-svc process - try multiple methods for reliability
    local warp_pid

    # Method 1: pgrep exact match
    warp_pid=$(pgrep -x "$WARP_SVC_PROCESS" 2>/dev/null | head -n1)

    # Method 2: fallback to pgrep with partial match
    if [[ -z "$warp_pid" ]]; then
        warp_pid=$(pgrep -f "$WARP_SVC_PROCESS" 2>/dev/null | head -n1)
    fi

    if [[ -n "$warp_pid" ]]; then
        echo "$warp_pid"
        return 0
    else
        return 1
    fi
}

function warp_status() {
    echo "=== WARP Integration Status ==="

    local psiphontunv4
    # Check WARP CLI availability
    if [[ -x "$WARP_CLI_PATH" ]]; then
        echo -e "WARP CLI: ${GREEN}Available${NC} ($WARP_CLI_PATH)"

        # Get WARP status
        local warp_status_output
        warp_status_output=$(get_warp_status)
        echo "WARP CLI Output: $warp_status_output"

        # Check connection status
        if is_warp_connected; then
            echo -e "WARP Status: ${GREEN}Connected${NC}"
            echo -e "WARP Interface: $WARP_INTERFACE"
            # Check WARP service process
            local warp_pid
            if warp_pid=$(get_warp_svc_pid); then
                echo -e "WARP Service: ${GREEN}Running${NC} (PID: $warp_pid)"
                echo -e "WARP Process: $WARP_SVC_PROCESS"
                echo -e "WARP User: root (warp-svc always runs as root)"

                # Check firewall rules for WARP
                echo ""
                echo "=== Firewall Configuration ==="
                echo "Firewall rules for WARP process (PID: $warp_pid):"
                nft list ruleset | grep -i "meta skpid $warp_pid" || echo "No PID-specific rules found"

            else
                echo -e "WARP Service: ${RED}Process Not Found${NC}"
            fi

            # Test WARP connectivity
            echo ""
            echo "=== WARP Connectivity Test ==="
            # Try to detect if traffic is going through WARP
            local cdncgitracev4
            if cdncgitracev4=$(timeout 10 curl -4sSm 7 --interface $WARP_INTERFACE https://cloudflare.com/cdn-cgi/trace 2>/dev/null); then
                echo -e "WARP IPv4 Result: $(echo "$cdncgitracev4" | grep 'warp=')"
            else
                echo -e "WARP IPv4 Test: ${RED}FAILED${NC}"
            fi
            local cdncgitracev6
            if cdncgitracev6=$(timeout 10 curl -6sSm 7 --interface $WARP_INTERFACE https://cloudflare.com/cdn-cgi/trace 2>/dev/null); then
                echo -e "WARP IPv6 Result: $(echo "$cdncgitracev6" | grep 'warp=')"
            else
                echo -e "WARP IPv6 Test: ${RED}FAILED${NC}"
            fi

            # Check if psiphon process is active and has a connection to the internet
            local psiphonipv4
            psiphonipv4=$(timeout 10 curl -4sSm 7 -x socks5://127.0.0.1:$SOCKS_PORT https://cloudflare.com/cdn-cgi/trace)

            # Check for active psiphon TUN interface
            if psiphontunv4=$(ip addr show dev $TUN_INTERFACE | grep -o 'inet [0-9.]*' | cut -d' ' -f2); then
                echo -e "Psiphon TUN IPv4: ${GREEN}$psiphontunv4${NC}"
                echo -e "• Traffic Flow: ${GREEN}All applications → PsiphonTUN → Psiphon Process → WARP → Internet${NC}"
                echo "• Kill Switch: All traffic blocked by default (OUTPUT DROP)"
                echo -e "• Whitelisted: $PSIPHON_USER (for tunnel establishment)"
                # echo "• Whitelisted: $WARP_SVC_PROCESS PID (for WARP connectivity)"
            else
                if [[ $(echo "$cdncgitracev4" | grep 'warp=') == "warp=on" && $(echo "$psiphonipv4" | grep 'warp=') == "warp=off" ]]; then
                    echo -e "Psiphon running only as a proxy over WARP: ${GREEN}OK${NC}"
                    echo -e "• Traffic Flow 1: ${GREEN}Applications with proxy → Psiphon Process → WARP → Internet${NC}"
                    echo -e "• Traffic Flow 2: ${YELLOW}All other applications without proxy → WARP → Internet${NC}"
                elif  [[ $(echo "$cdncgitracev4" | grep 'warp=') == "warp=on" ]]; then
                    echo -e "• Traffic Flow: ${GREEN}Applications → WARP → Internet${NC}"
                fi
            fi
        else
            echo ""
            echo -e "=== WARP Status: ${RED}Not Connected${NC} ==="
        fi

    else
        echo -e "WARP CLI: ${RED}Not Available${NC} ($WARP_CLI_PATH)"
    fi
}

function status() {
    echo "=== Psiphon TUN Status ==="

    # Check if Psiphon process is running
    local psiphon_pid

    if [[ -f $PID_FILE ]]; then
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            echo -e "Psiphon: ${GREEN}RUNNING${NC} (PID: $psiphon_pid)"
        else
            echo -e "Psiphon: ${RED}STOPPED${NC} (stale PID file)"
        fi
    elif pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        psiphon_pid=$(pgrep -f "psiphon-tunnel-core")
        echo -e "Psiphon: ${YELLOW}RUNNING${NC} (PID: $psiphon_pid, no PID file)"
    else
        echo -e "Psiphon: ${RED}STOPPED${NC}"
    fi

    # Check TUN interface
    echo ""
    echo "=== Network Interface Status ==="
    if ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        local tun_ip
        tun_ip=$(ip addr show "$TUN_INTERFACE" | grep -o 'inet [0-9.]*' | cut -d' ' -f2 || echo "No IP")
        echo -e "TUN Interface: ${GREEN}UP${NC} ($TUN_INTERFACE, IP: $tun_ip)"
    else
        echo -e "TUN Interface: ${RED}DOWN${NC} ($TUN_INTERFACE)"
    fi

    # Check Routing
    echo ""
    echo "=== Routing Status ==="
    if ip route | grep -q "$TUN_INTERFACE"; then
        echo -e "TUN Routing: ${GREEN}CONFIGURED${NC}"
    else
        echo -e "TUN Routing: ${RED}NOT CONFIGURED${NC}"
    fi

    # Test connection if everything is running
    if [[ -n "${psiphon_pid:-}" ]] && kill -0 "$psiphon_pid" 2>/dev/null && ip link show "$TUN_INTERFACE" >/dev/null 2>&1; then
        echo ""
        echo "=== Connection Test ==="
        local test_ip
        if test_ip=$(timeout 10 curl -s --interface "$TUN_INTERFACE" --connect-timeout 5 ifconfig.me 2>/dev/null); then
            # check for both IPv4 and IPv6 format
            if [[ -n "$test_ip" && ( "$test_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$test_ip" =~ ^[0-9a-f:]+$ ) ]]; then
                echo -e "External IP via TUN: ${GREEN}$test_ip${NC}"
            else
                echo -e "Connection Test: ${YELLOW}UNEXPECTED RESULT${NC} ($test_ip)"
            fi
        else
            echo -e "Connection Test: ${RED}FAILED${NC}"
            echo ""
            echo -e "${YELLOW}Connection test failed. Run 'sudo $0 diagnose' for detailed network diagnostics.${NC}"
        fi
    fi

    # IPv6 status test
    echo ""
    echo "=== IPv6 Status ==="
    if ip -6 addr show dev "$TUN_INTERFACE" >/dev/null 2>&1; then
        local ipv6_addr
        ipv6_addr=$(ip -6 addr show dev "$TUN_INTERFACE" | grep -o 'inet6 [0-9a-f:]*' | cut -d' ' -f2 || echo "No IPv6")
        echo -e "IPv6 Support: ${GREEN}ENABLED${NC}"
        echo -e "TUN IPv6: ${GREEN}$ipv6_addr${NC}"

        # # Test IPv6 connectivity
        # if timeout 10 ping6 -c 1 2606:4700:4700::1001 >/dev/null 2>&1; then
        #     echo -e "IPv6 Connectivity: ${GREEN}OK${NC}"
        # else
        #     echo -e "IPv6 Connectivity: ${RED}FAILED${NC}"
        # fi
    else
        echo -e "IPv6 Support: ${RED}NOT CONFIGURED${NC}"
        echo -e "${YELLOW}IPv6 not configured. Run 'sudo $0 diagnose' for detailed analysis.${NC}"
    fi

    echo ""
    echo "=== DNS Resolution Test ==="
    echo -e "DNS v4 Query Result: $(dig -4 +timeout=2 +retry=0 +short youtube.com @8.8.8.8 | head -n1)"
    echo -e "DNS v6 Query Result: $(dig -6 +timeout=2 +retry=0 +short youtube.com @2001:4860:4860::8888 | head -n1)"

    # WARP Status
    echo ""
    echo "=== WARP Integration Status ==="
    if [[ -x "$WARP_CLI_PATH" ]]; then
        if is_warp_connected; then
            echo -e "WARP Status: ${GREEN}Connected${NC}"
            if warp_pid=$(get_warp_svc_pid); then
                echo -e "WARP Service: ${GREEN}Running${NC} (PID: $warp_pid)"
            fi
        else
            echo -e "WARP Status: Not Connected"
            echo -e "VPN Mode: Psiphon Only"
        fi
    else
        echo -e "WARP CLI: ${RED}Not Installed${NC} ($WARP_CLI_PATH)"
        echo -e "VPN Mode: Psiphon Only"
    fi

    echo ""
    echo "=== curl test ==="
    echo -e "External IPv4 direct:\n$(timeout 10 curl -4sSm 7 https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv6 direct:\n$(timeout 10 curl -6sSm 7 https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv4 SOCKS port:\n$(timeout 10 curl -4sSm 7 -x socks5://127.0.0.1:$SOCKS_PORT https://cloudflare.com/cdn-cgi/trace)"
    echo ""
    sleep 1
    echo -e "External IPv6 SOCKS port:\n$(timeout 10 curl -6sSm 7 -x "socks5://[::ffff:127.0.0.1]:$SOCKS_PORT" https://cloudflare.com/cdn-cgi/trace)"
    echo ""
}

# Update Psiphon
function update() {
    log "Checking for Psiphon updates..."

    local was_running=false
    if [[ -f $PID_FILE ]]; then
        local psiphon_pid
        psiphon_pid=$(cat $PID_FILE 2>/dev/null || echo "")
        if [[ -n "$psiphon_pid" ]] && kill -0 "$psiphon_pid" 2>/dev/null; then
            was_running=true
        fi
    fi

    if $was_running; then
        log "Stopping services for update..."
        stop_services
    fi

    check_and_update_psiphon

    if $was_running; then
        log "Restarting services..."
        setup_tun_interface
        setup_routing
        start_services
    fi
}

# Show usage
function usage() {
    cat << EOF
      Freedom is the freedom to say that
          __o            o           __o                o     o
        o/  v\\          <|>        o/  v\\              <|>   <|>
       /|    <\\         < >       /|    <\\             / >   < \\
       //    o/         / \\       //    o/    _\\__o__  \\o__ __o/
            /v     _\\__o   o__/_       /v          \\   \\|__ __|
           />           \\ /           />      _\\__o__         |
         o/             <o>         o/             \\         <o>
        /v               |         /v                         |
       /> __o__/_       < >       /> __o__/_                 / \\
                            if that is granted, all else follows...
                                              ― George Orwell, 1984


Psiphon TUN Setup Script - Secure Tunneling Solution v$INSTALLER_VERSION

Usage: $0 [COMMAND]

COMMANDS:
    install     Install and configure Psiphon TUN setup
    uninstall   Remove Psiphon TUN setup completely
    start       Start Psiphon service with native TUN support
    stop        Stop Psiphon service and cleanup
    restart     Stop and restart Psiphon service
    status      Show status of all components
    diagnose    Run comprehensive network diagnostics for troubleshooting
    warp-status Check WARP integration status and configuration
    update      Check for and install Psiphon updates
    help        Show this help message

FEATURES:
    - Uses Psiphon's native TUN support (no external dependencies)
    - Automatic updates
    - Robust error handling and logging
    - Full traffic routing through Psiphon network
    - Support for both HTTP and SOCKS proxies

SECURITY FEATURES:
    • Runs Psiphon as dedicated non-root user ($PSIPHON_USER)
    • Binary integrity verification during download
    • Secure file permissions and ownership
    • Process isolation and capability restrictions
    • Input validation and error handling

NETWORK CONFIGURATION:
    • TUN Interface: $TUN_INTERFACE ($TUN_IP)
    • SOCKS Proxy: 127.0.0.1:$SOCKS_PORT
    • HTTP Proxy: 127.0.0.1:$HTTP_PORT
    • Traffic routing excludes Psiphon user to prevent loops

WARP INTEGRATION:
    • Auto-detects if WARP is connected (warp-cli status = Connected)
    • Creates VPN chain: Psiphon → WARP → Internet (may not work very well for now)
    • Use 'warp-status' command for detailed WARP integration info

FILES:
    • Install Directory: $INSTALL_DIR
    • Binary: $PSIPHON_BINARY
    • Psiphon Config: $PSIPHON_CONFIG_FILE
    • Logs: $LOG_FILE $(du -h "$LOG_FILE" | cut -f1)
    • Service: /etc/systemd/system/$SERVICE_CONFIGURE_NAME.service
    • Psiphon notices: $INSTALL_DIR/data/notices

EXAMPLES:
    $0 install          # Install and configure everything
    $0 start            # Start the TUN service
    $0 status           # Check service status

    # Systemd management:
    sudo systemctl enable $SERVICE_CONFIGURE_NAME    # Auto-start at boot
    sudo systemctl start $SERVICE_CONFIGURE_NAME     # Start via systemd
    sudo systemctl status $SERVICE_CONFIGURE_NAME    # Check systemd status

For more information, visit: https://github.com/boilingoden/psiphon-client-linux-service
And: https://github.com/Psiphon-Labs/psiphon-tunnel-core

EOF
}

# Main script logic
function main() {
    case "${1:-}" in
        install)
            check_root
            acquire_lock
            install_shell
            ;;
        uninstall)
            check_root
            acquire_lock
            uninstall
            ;;
        start)
            check_root
            acquire_lock
            check_and_update_psiphon
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            start_services
            setup_tun_routes_after_ra
            check_network_readiness
            ;;
        systemd_start)
            SERVICE_MODE="true"
            check_root
            acquire_lock
            check_and_update_psiphon
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            start_services
            setup_tun_routes_after_ra
            check_network_readiness
            ;;
        reload)
            check_root
            start_psiphon # it will first kill then start psiphon
            ;;
        systemd_reload)
            SERVICE_MODE="true"
            check_root
            systemd_psiphon_reload
            ;;
        stop)
            check_root
            acquire_lock
            stop_services
            ;;
        systemd_stop)
            SERVICE_MODE="true"
            check_root
            stop_services
            ;;
        restart)
            check_root
            acquire_lock
            stop_services
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            start_services
            setup_tun_routes_after_ra
            check_network_readiness
            ;;
        systemd_restart)
            SERVICE_MODE="true"
            check_root
            stop_services
            setup_tun_interface
            setup_routing
            wait_for_ra_processing
            start_services
            setup_tun_routes_after_ra
            check_network_readiness
            ;;
        status)
            status
            ;;
        diagnose)
            check_root
            diagnose_network_issues
            ;;
        warp-status)
            warp_status
            ;;
        update)
            check_root
            acquire_lock
            update
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            echo "Unknown command: ${1:-}"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
