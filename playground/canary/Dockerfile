# Multi-stage build: compile the tiny Rust canary inside a pinned rust image, then
# run it on a minimal, pinned distroless runtime. No shell in the runtime, so the
# HEALTHCHECK runs the binary's own `healthcheck` subcommand.
FROM rust:1.90-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/app /app
EXPOSE 8082
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=30 \
  CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
