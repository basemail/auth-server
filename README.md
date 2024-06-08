# SIWE Authentication Server

Basic authentication server that provides JWT access tokens for signed in users. Integrating systems need to reference the same database to validate tokens.

## Stack

The server is written in Rust using the Actix Web Framework for the HTTP server and MongoDB for the database.

## Getting Started

Assuming you have Rust and MongoDB installed, you can pull the server down and run it locally right away.

```bash
git clone https://github.com/basemail/auth-server
cd auth-server
cargo run
```