# Multi-stage build: compile the tiny Rust fixture inside a pinned rust image,
# then run it on a SHELL-BEARING base. Unlike the other playground fixtures,
# whose runtime is distroless with no shell, command injection needs a real shell
# at runtime to be demonstrable, so this one fixture runs on debian:bookworm-slim
# (which ships /bin/sh and echo/cat). It is a deliberately vulnerable target that
# runs only inside the egress-less lab and must never be pushed or deployed.
FROM rust:1.90-slim-bookworm AS build
# FEATURES selects the build variant: empty for the vulnerable mvp image, `fixed`
# for the patched redstep/cmdi:fixed. The `fixed` feature adds no dependency, so
# Cargo.lock is unchanged and `--locked` holds either way.
ARG FEATURES=
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked ${FEATURES:+--features "$FEATURES"}

FROM debian:bookworm-slim
COPY --from=build /src/target/release/app /app
# The sentinel the injected `;cat /srv/cmdi_secret.txt` reads: its body is the
# command-injection witness, pinned offline against this file by the orchestrator
# (RK-014). The injection path is the contract between this COPY and the probe.
COPY secret.txt /srv/cmdi_secret.txt
EXPOSE 8083
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=30 \
  CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
