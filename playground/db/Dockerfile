# A thin bespoke db tier for the SQLi playground (#47, ADR-0008): stock postgres
# with a baked dev credential and a seed schema, so the environment model needs
# no volume mount or env field to stand it up. The credential is a lab-only
# constant and this is a deliberately vulnerable target: it must never leave the
# egress-less lab.
FROM postgres:16

ENV POSTGRES_USER=redstep
ENV POSTGRES_PASSWORD=redstep
ENV POSTGRES_DB=redstep

# The official entrypoint runs the init scripts on first boot before it opens the
# TCP listener, so a TCP `pg_isready` passing implies this seed has loaded.
COPY seed.sql /docker-entrypoint-initdb.d/10-seed.sql

# A TCP healthcheck (via -h 127.0.0.1, not the init-time unix socket), so the
# readiness gate (bring_up, #47) sees `healthy` only once the server accepts TCP.
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=30 \
  CMD pg_isready -U redstep -d redstep -h 127.0.0.1 || exit 1
