FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      samba samba-dsdb-modules samba-vfs-modules winbind smbclient \
      krb5-user dnsutils ldap-utils ca-certificates samba-ad-provision && \
    rm -rf /var/lib/apt/lists/*

COPY provision.sh /usr/local/bin/provision-ad
RUN chmod +x /usr/local/bin/provision-ad

HEALTHCHECK --interval=5s --timeout=5s --start-period=20s --retries=30 \
  CMD smbclient -L //127.0.0.1 -U "Administrator%${AD_ADMIN_PASSWORD}" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/provision-ad"]
