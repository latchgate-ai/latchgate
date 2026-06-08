# LatchGate egress proxy — minimal Alpine-based Squid.
#
# Runs entirely as non-root. Port 3128 is unprivileged, no setuid needed.
# Logs to stdout/stderr for Docker log collection.
# No cache directories — this is a security proxy, not a performance proxy.

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

RUN apk add --no-cache squid && \
    rm -rf /var/cache/apk/*

# Squid only needs /run/squid for the UDS control socket (not used here,
# but Squid may create ancillary files) and /tmp for the PID file.
# /var/log/squid and /var/spool/squid are NOT needed — logs go to
# stdout/stderr and caching is disabled.
RUN mkdir -p /run/squid /var/run/latchgate/egress && \
    chown squid:squid /run/squid /var/run/latchgate/egress

# Configuration.
COPY squid.conf /etc/squid/squid.conf

# Deny-all allowlist seed. No domain entries → allowed_domains ACL
# matches nothing → Squid blocks ALL outbound traffic. Fail-closed.
# The gate overwrites this at runtime via live-sync.
RUN printf '# deny-all seed — no domains permitted until gate runtime sync\n' \
    > /var/run/latchgate/egress/allowlist.txt && \
    chown squid:squid /var/run/latchgate/egress/allowlist.txt

USER squid

EXPOSE 3128

ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]
