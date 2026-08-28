#!/bin/sh
set -eu

: "${AD_REALM:=MCP.TEST}"
: "${AD_DOMAIN:=MCP}"
: "${AD_ADMIN_PASSWORD:=LabAdmin-2026!}"
: "${AD_USER:=fixture-user}"
: "${AD_USER_PASSWORD:=FixtureUser-2026!}"
: "${AD_DC_IP:=172.30.250.10}"

rm -f /etc/samba/smb.conf
samba-tool domain provision \
  --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL \
  --option="acl_xattr:security_acl_name=user.NTACL" \
  --realm="$AD_REALM" --domain="$AD_DOMAIN" \
  --adminpass="$AD_ADMIN_PASSWORD" --host-ip="$AD_DC_IP"
samba-tool user create "$AD_USER" "$AD_USER_PASSWORD"
exec samba --foreground --no-process-group
