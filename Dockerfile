# syntax=docker/dockerfile:1

FROM rust:1.83-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY config ./config

RUN cargo build --release -p nx_proxy

FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --create-home nxproxy

WORKDIR /opt/rocketleagueserverfix
COPY --from=builder /app/target/release/nx_proxy /usr/local/bin/nx_proxy
COPY config/example.toml /etc/nx_proxy/example.toml

USER nxproxy
EXPOSE 7000/udp
EXPOSE 9100/tcp

ENTRYPOINT ["/usr/local/bin/nx_proxy"]
CMD ["--config", "/etc/nx_proxy/example.toml"]
