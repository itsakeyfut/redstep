# Multi-stage build: compile the thin Rust api inside a pinned rust image, then
# run the binary on a minimal, pinned distroless runtime. No shell in the
# runtime, so the HEALTHCHECK runs the binary's own `healthcheck` subcommand.
FROM rust:1.90-slim-bookworm AS build
# FEATURES selects the build variant: empty for the vulnerable mvp image,
# `fixed` for the patched `redstep/api:fixed` (#54). The `fixed` feature adds no
# dependency, so Cargo.lock is unchanged and `--locked` holds either way.
ARG FEATURES=
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked ${FEATURES:+--features "$FEATURES"}

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/app /app
EXPOSE 8081
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=30 \
  CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
