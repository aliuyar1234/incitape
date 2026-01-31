FROM rust:1.76-slim AS builder
WORKDIR /src
COPY . /src/incitape
WORKDIR /src/incitape
RUN cargo build --release -p incitape-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/incitape/target/release/incitape /usr/local/bin/incitape
ENTRYPOINT ["incitape"]
