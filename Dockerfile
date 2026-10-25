FROM rust:1.85-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/magnitude-relay /usr/local/bin/
RUN useradd -r -s /usr/sbin/nologin relay
USER relay
WORKDIR /data
EXPOSE 7777
ENTRYPOINT ["magnitude-relay"]   
