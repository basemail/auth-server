FROM rust:1.79-bookworm as build
# initialize the cargo workspace
# we initialize vanilla crates for caching reasons
RUN USER=root cargo new --bin auth-server
RUN USER=root cargo new --bin auth-server/crates/admin
RUN USER=root cargo new --bin auth-server/crates/api
RUN USER=root cargo new --bin auth-server/crates/database
WORKDIR /auth-server

# 1. copy over manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./crates/admin/Cargo.toml ./crates/admin/Cargo.toml
COPY ./crates/api/Cargo.toml ./crates/api/Cargo.toml
COPY ./crates/database/Cargo.toml ./crates/database/Cargo.toml

# 2. cache build dependencies and delete the templated development code
RUN cargo build --release
RUN rm crates/**/src/*.rs

# 3. copy over the crates we want to build and build the binaries
COPY ./crates ./crates

# delete the original deps so we ensure clean builds
RUN rm ./target/release/deps/api*
RUN rm ./target/release/deps/admin*
RUN rm ./target/release/deps/database*
RUN cargo build --release

# running in a vanilla debian image saves us GBs of space
FROM debian:bookworm-slim
LABEL org.opencontainers.image.source=https://github.com/basemail/auth-server

RUN apt-get update
RUN apt-get install -y openssl

COPY --from=build /auth-server/target/release/admin .
COPY --from=build /auth-server/target/release/api .
COPY ./crates/admin/config.toml ./crates/admin/config.toml
# local | test | prod
ENV ENVIRONMENT=test
ENV DATABASE_NAME=siwe-auth
ENV DATABASE_URI=mongodb://localhost:27017
ENV RUST_LOG=info
# Run the initialize DB script: cargo run -p admin init-db
# ENV JWT_SECRET=<include as a secret>
# CMD ["./admin", "init-db"]

# Change the .env file so that ENVIRONMENT=local so we bind to the localhost and have permissive CORS policy.
# Run the api: cargo run -p api
#ENV ENVIRONMENT=local
#CMD ["./api"]
