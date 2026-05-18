#!/bin/bash
# firewall.sh — unified firewall management for the devcontainer.
#
# Subcommands:
#   init     One-time setup: flush rules, build ipset, install iptables policy,
#            verify, and start the background refresh loop. Run as root via
#            sudo from devcontainer.json's postStartCommand.
#   refresh  Re-resolve allowed domains and add any new IPs to the existing
#            ipset. Idempotent and safe to call any time.
#   loop     Run `refresh` forever on a timer (REFRESH_INTERVAL seconds,
#            default 900). Started in the background by `init`.
#
# Domain list lives in /usr/local/etc/allowed-domains.conf.

set -uo pipefail

LOG=/var/log/firewall-refresh.log
IPSET_NAME=allowed-domains

# Domains the firewall allows. Edit this list and rerun
# `sudo firewall.sh init` (or rebuild the container) to apply changes.
ALLOWED_DOMAINS=(
    # --- Core: package registries, Anthropic API, telemetry, VS Code ---
    "registry.npmjs.org"
    "api.anthropic.com"
    "sentry.io"
    "statsig.anthropic.com"
    "statsig.com"
    "marketplace.visualstudio.com"
    "vscode.blob.core.windows.net"
    "update.code.visualstudio.com"
    # Publisher CDNs for extension manifests/assets (Pylance, debugpy, etc.)
    "ms-python.gallerycdn.vsassets.io"
    "ms-python.gallery.vsassets.io"
    "redhat.gallerycdn.vsassets.io"
    "redhat.gallery.vsassets.io"
    "anthropic.gallerycdn.vsassets.io"
    "anthropic.gallery.vsassets.io"
    "esbenp.gallerycdn.vsassets.io"
    "esbenp.gallery.vsassets.io"

    # --- Python packaging (pip, pipx, ansible deps) ---
    "pypi.org"
    "files.pythonhosted.org"
    "pythonhosted.org"

    # --- GitHub raw content (collections often install from Git) ---
    "raw.githubusercontent.com"
    "objects.githubusercontent.com"
    "codeload.github.com"

    # --- SonarQube and documentation
    "sonarqube.io"
    "docs.sonarsource.com"
)

log() {
    echo "[firewall $(date -u +%H:%M:%S)] $*"
}

die() {
    log "ERROR: $*"
    exit 1
}

# Resolve a domain and add each A record to the ipset. Returns 0 on success
# (at least one IP added), 1 if nothing resolved. Safe to call repeatedly.
add_domain_ips() {
    local domain="$1" ips
    ips=$(dig +short +tries=2 +time=3 A "$domain" 2>/dev/null \
          | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    [ -z "$ips" ] && return 1
    while IFS= read -r ip; do
        ipset add "$IPSET_NAME" "$ip" -exist 2>/dev/null || true
    done <<< "$ips"
    return 0
}

# ---------------------------------------------------------------------------
# Subcommand: refresh
# ---------------------------------------------------------------------------
cmd_refresh() {
    ipset list -n "$IPSET_NAME" >/dev/null 2>&1 \
        || die "ipset $IPSET_NAME does not exist; run '$0 init' first"
    local failed=0
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        add_domain_ips "$domain" || { log "WARN: failed to resolve $domain"; failed=$((failed+1)); }
    done
    log "refresh complete (${#ALLOWED_DOMAINS[@]} domains, $failed failures)"
}

# ---------------------------------------------------------------------------
# Subcommand: loop
# ---------------------------------------------------------------------------
cmd_loop() {
    local interval="${REFRESH_INTERVAL:-900}"
    log "starting refresh loop (interval=${interval}s)"
    while true; do
        cmd_refresh || true
        sleep "$interval"
    done
}

# ---------------------------------------------------------------------------
# Subcommand: init
# ---------------------------------------------------------------------------
cmd_init() {
    # Strict mode for setup (refresh/loop tolerate transient errors)
    set -e
    IFS=$'\n\t'

    # Preserve Docker's embedded DNS NAT rules (127.0.0.11) before flushing
    local docker_dns_rules
    docker_dns_rules=$(iptables-save -t nat 2>/dev/null | grep "127.0.0.11" || true)

    # Reset default policies to ACCEPT first — otherwise on container restart
    # the previous run's DROP policies block our own curl below.
    iptables -P INPUT   ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT  ACCEPT

    # Kill any prior refresh loop so re-runs don't pile up
    pkill -f "firewall.sh loop" 2>/dev/null || true

    # Flush existing rules and any prior ipset
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    ipset destroy "$IPSET_NAME" 2>/dev/null || true

    # Restore Docker DNS NAT rules so internal name resolution keeps working
    if [ -n "$docker_dns_rules" ]; then
        while IFS= read -r rule; do
            if [[ "$rule" =~ ^[*] ]] || [[ "$rule" == "COMMIT" ]] || [[ "$rule" =~ ^: ]]; then
                continue
            fi
            local rule_args="${rule#-A }"
            # shellcheck disable=SC2086
            iptables -t nat -A $rule_args 2>/dev/null || true
        done <<< "$docker_dns_rules"
    fi

    # Allow DNS, SSH, loopback before flipping policy to DROP
    iptables -A INPUT  -p udp --sport 53 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT  -p tcp --sport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT  -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # ipset for allowed destination IPs
    ipset create "$IPSET_NAME" hash:net

    # --- GitHub IP ranges (web, api, git) — separate mechanism (CIDR) ---
    log "fetching GitHub IP ranges..."
    local gh_ranges
    gh_ranges=$(curl --connect-timeout 5 --max-time 15 -s https://api.github.com/meta || true)
    [ -n "$gh_ranges" ] || die "failed to fetch GitHub IP ranges"
    echo "$gh_ranges" | jq -e '.web and .api and .git' >/dev/null \
        || die "GitHub API response missing required fields"
    log "aggregating GitHub IP ranges..."
    while read -r cidr; do
        [ -z "$cidr" ] && continue
        ipset add "$IPSET_NAME" "$cidr"
    done < <(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | aggregate -q)

    # --- AWS S3 us-east-1 IP ranges (for Galaxy's S3 backend) ---
    log "fetching AWS IP ranges..."
    local aws_ranges
    aws_ranges=$(curl --connect-timeout 5 --max-time 15 -s https://ip-ranges.amazonaws.com/ip-ranges.json || true)
    [ -n "$aws_ranges" ] || die "failed to fetch AWS IP ranges"
    echo "$aws_ranges" | jq -e '.prefixes' >/dev/null \
        || die "AWS IP ranges response missing .prefixes"
    log "aggregating S3 us-east-1 ranges..."
    while read -r cidr; do
        [ -z "$cidr" ] && continue
        ipset add "$IPSET_NAME" "$cidr"
    done < <(echo "$aws_ranges" \
        | jq -r '.prefixes[] | select(.service=="S3" and .region=="us-east-1") | .ip_prefix' \
        | aggregate -q)

    # --- Resolve allowlisted domains ---
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        log "resolving $domain..."
        add_domain_ips "$domain" || die "failed to resolve $domain"
    done

    # Allow traffic to the host network (port forwarding, host gateway)
    local host_ip host_network
    host_ip=$(ip route | grep default | cut -d" " -f3)
    [ -n "$host_ip" ] || die "could not detect host gateway"
    host_network=$(echo "$host_ip" | sed "s/\.[0-9]*$/.0\/24/")
    log "host network: $host_network"
    iptables -A INPUT  -s "$host_network" -j ACCEPT
    iptables -A OUTPUT -d "$host_network" -j ACCEPT

    # On Docker Desktop (Mac/Windows) host.docker.internal resolves to a
    # separate host gateway IP (e.g. 192.168.65.254) that is outside the
    # default-route subnet above.  Allow it explicitly so MCP servers and
    # other host-side services are reachable.
    local hdi_ip
    hdi_ip=$(grep -m1 'host\.docker\.internal' /etc/hosts | grep -v ':' | awk '{print $1}' || true)
    if [ -n "$hdi_ip" ] && [ "$hdi_ip" != "$host_ip" ]; then
        log "host.docker.internal (Docker Desktop): $hdi_ip"
        iptables -A INPUT  -s "$hdi_ip" -j ACCEPT
        iptables -A OUTPUT -d "$hdi_ip" -j ACCEPT
    fi

    # Default-deny
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  DROP

    # Allow established/related return traffic
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow new outbound connections only to allowlisted IPs
    iptables -A OUTPUT -m set --match-set "$IPSET_NAME" dst -j ACCEPT

    # Reject the rest with an explicit ICMP message
    iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

    log "firewall configured. verifying..."
    if curl --connect-timeout 5 -s https://example.com >/dev/null 2>&1; then
        die "verification failed — unlisted host reachable"
    fi
    if ! curl --connect-timeout 5 -s https://api.github.com/zen >/dev/null 2>&1; then
        die "verification failed — GitHub API unreachable"
    fi
    log "firewall verification OK."

    # Background refresh loop so rotating IPs (Galaxy, PyPI, npm) keep working
    nohup "$0" loop >> "$LOG" 2>&1 &
    disown
    log "refresh loop started (PID $!, log $LOG)"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "${1:-}" in
    init)    cmd_init ;;
    refresh) cmd_refresh ;;
    loop)    cmd_loop ;;
    *)
        cat >&2 <<EOF
Usage: $0 {init|refresh|loop}

  init     Set up firewall (run once at container start, as root)
  refresh  Re-resolve domains and add new IPs to the ipset
  loop     Run refresh forever on REFRESH_INTERVAL (default 900s)
EOF
        exit 2
        ;;
esac
