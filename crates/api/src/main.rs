// main.rs - entry point to run the API server

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use clap::Parser;
use dotenvy::dotenv;
use mongodb::Collection;
use tracing::subscriber::set_global_default;
use tracing_actix_web::TracingLogger;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, Registry};

mod auth;
mod config;
mod routes;
mod utils;

use config::Config;
use database::{
    auth::model::{NonceModel, RefreshTokenModel},
    auth::set_ttl_index,
};
use routes::{nonce, refresh, sign_in, validate};

#[derive(Parser, Debug)]
struct Args {
    /// Database URI and Name
    #[arg(
        long,
        env = "DATABASE_URI",
        default_value = "mongodb://localhost:27017"
    )]
    database_uri: String,
    #[arg(long, env = "DATABASE_NAME", default_value = "siwe-auth")]
    database_name: String,
    /// Environment
    #[arg(long, env = "ENVIRONMENT", default_value = "local")]
    pub environment: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file if local
    dotenv().ok();

    // Parse CLI args, using ENV vars if not provided
    let args = Args::parse();

    // Setup tracing for our API
    // Adds log tracer as the default tracer for the log crate
    LogTracer::init().expect("Failed to set log tracer");
    // Set log level based on env variable
    let env_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    let fmt_layer = fmt::layer().with_target(false);
    let subscriber = Registry::default().with(env_layer).with(fmt_layer);
    set_global_default(subscriber).expect("Failed to set global default subscriber");

    // Create database client
    let client = mongodb::Client::with_uri_str(args.database_uri)
        .await
        .expect("Failed to connect to database.");

    // Set TTL indexes
    let nonces_collection: Collection<NonceModel> =
        client.database(&args.database_name).collection("nonces");

    set_ttl_index(nonces_collection, 10).await;

    let invalid_refresh_tokens_collection: Collection<RefreshTokenModel> = client
        .database(&args.database_name)
        .collection("invalid-refresh-tokens");

    set_ttl_index(invalid_refresh_tokens_collection, 86400).await;

    // Set api config
    let config = Config {
        client: client.clone(),
        database: args.database_name.clone(),
    };

    // Set default JSON config
    let json_cfg = web::JsonConfig::default();

    // Create and run http server
    let binding = if args.environment.as_str() == "local" {
        ("127.0.0.1", 8081)
    } else {
        ("0.0.0.0", 10000)
    };
    HttpServer::new(move || {
        let cors = match args.environment.as_str() {
            "local" => Cors::permissive(),
            "testnet" => Cors::default()
                .allowed_origin("https://testnet.basechain.email")
                .allowed_methods(vec!["GET", "POST"])
                .allow_any_header()
                .supports_credentials()
                .max_age(3600),
            "production" => Cors::default()
                .allowed_origin("https://basechain.email")
                .allowed_methods(vec!["GET", "POST"])
                .allow_any_header()
                .supports_credentials()
                .max_age(3600),
            _ => panic!("Invalid environment"),
        };
        App::new()
            .app_data(web::Data::new(config.clone()))
            .app_data(json_cfg.clone())
            .wrap(TracingLogger::default())
            .wrap(cors)
            .service(nonce)
            .service(sign_in)
            .service(refresh)
            .service(validate)
    })
    .bind(binding)?
    .run()
    .await
}
