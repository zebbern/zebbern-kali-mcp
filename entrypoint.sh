#!/bin/bash
set -eo pipefail

echo "[entrypoint] Kali MCP Server initializing..."

# --- Network Routes (Issue #1) ---
# HTB_ROUTES: comma-separated CIDR ranges to route via the default gateway
# Example: HTB_ROUTES=10.129.0.0/16,10.10.0.0/16
if [ -n "$HTB_ROUTES" ]; then
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    IFACE=$(ip route | grep default | awk '{print $5}')
    if [ -n "$GATEWAY" ] && [ -n "$IFACE" ]; then
        IFS=',' read -ra ROUTES <<< "$HTB_ROUTES"
        for route in "${ROUTES[@]}"; do
            route=$(echo "$route" | xargs)
            if [ -n "$route" ]; then
                ip route add "$route" via "$GATEWAY" dev "$IFACE" 2>/dev/null && \
                    echo "[entrypoint] Route added: $route via $GATEWAY ($IFACE)" || \
                    echo "[entrypoint] Route exists or failed: $route"
            fi
        done
    else
        echo "[entrypoint] WARN: No default gateway found, skipping HTB_ROUTES"
    fi
fi

# --- Custom /etc/hosts entries (Issue #2) ---
# EXTRA_HOSTS: comma-separated hostname:ip pairs
# Example: EXTRA_HOSTS=dc01.pirate.htb:10.129.244.95,web01.pirate.htb:192.168.100.2
if [ -n "$EXTRA_HOSTS" ]; then
    IFS=',' read -ra HOSTS <<< "$EXTRA_HOSTS"
    for entry in "${HOSTS[@]}"; do
        entry=$(echo "$entry" | xargs)
        if [ -n "$entry" ]; then
            host=$(echo "$entry" | cut -d: -f1)
            ip=$(echo "$entry" | cut -d: -f2)
            if [ -n "$host" ] && [ -n "$ip" ]; then
                echo "$ip $host" >> /etc/hosts
                echo "[entrypoint] Host added: $host -> $ip"
            fi
        fi
    done
fi

# Append from mounted hosts file if present
if [ -f /etc/hosts.extra ]; then
    cat /etc/hosts.extra >> /etc/hosts 2>/dev/null || true
    echo "[entrypoint] Appended entries from /etc/hosts.extra"
fi

# --- Ligolo TUN Interface (Issue #8) ---
if [ -e /dev/net/tun ]; then
    ip tuntap add user root mode tun ligolo 2>/dev/null && \
        echo "[entrypoint] Created ligolo TUN interface" || \
        echo "[entrypoint] Ligolo TUN already exists or creation skipped"
    ip link set ligolo up 2>/dev/null || true
fi

# --- IP Forwarding ---
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

echo "[entrypoint] Initialization complete, launching server..."
exec python3 zebbern-kali/kali_server.py "$@"
