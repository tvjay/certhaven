#!/bin/bash
# Host firewall for the certmgr server, using ufw. Run as root:
#   sudo bash /usr/share/certmgr/firewall-ufw.sh "192.168.10.0/24 10.20.0.0/16"
# The argument lists the management networks allowed to reach SSH (22) and the admin UI (443).
# Port 80 stays open to everyone so clients can download CRLs and CA certificates.
# Safe to re-run: it rebuilds the rules from scratch each time.
set -euo pipefail

MGMT_NETS="${1:?usage: $0 \"<management CIDR> [<CIDR> ...]\"}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root." >&2
    exit 1
fi

apt-get install -y -q ufw >/dev/null

# Retire the earlier nftables setup: its boot-time "flush ruleset" would wipe ufw's rules.
if systemctl is-enabled --quiet nftables 2>/dev/null; then
    systemctl disable --now nftables
fi

if [ ! -e /proc/net/if_inet6 ]; then
    sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw   # IPv6 is disabled on this host
fi

ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw allow 80/tcp comment 'CRL and CA certificate downloads'
for net in $MGMT_NETS; do
    ufw allow from "$net" to any port 22 proto tcp comment 'SSH from management network'
    ufw allow from "$net" to any port 443 proto tcp comment 'certmgr admin UI'
done
ufw --force enable
ufw status verbose
