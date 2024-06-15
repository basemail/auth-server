// admin/main.rs - scripts for initializing the database and updating data

use clap::{Parser, Subcommand};
use database::{
    chains::{
        model::create_chain_index,
        query::{does_chain_exist, insert_chain},
    },
    domains::query::insert_domain,
};
use dotenvy::dotenv;
use http::uri::Authority;
use mongodb::Client;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[clap(name = "admin")]
struct Args {
    #[clap(subcommand)]
    subcommand: Subcommands,
    #[arg(short, long, env = "ENVIRONMENT", default_value = "local")]
    environment: String,
    #[arg(
        long,
        env = "DATABASE_URI",
        default_value = "mongodb://localhost:27017"
    )]
    database_uri: String,
    #[arg(long, env = "DATABASE_NAME", default_value = "siwe-auth")]
    database_name: String,
}

#[derive(Debug, Subcommand)]
enum Subcommands {
    #[clap(name = "init-db")]
    InitDatabase,
    #[clap(name = "add-chain")]
    AddChain {
        // Chain name should match one under the provided environment in the config file
        #[arg(short, long)]
        chain: String,
    },
    #[clap(name = "add-domain")]
    AddDomain { domain: String },
}

#[derive(Debug, Deserialize)]
struct Chain {
    chain_id: u64,
    http_rpc_url: String,
    ws_rpc_url: String,
}

// Allows nesting chains under a specific environment
// local -> anvil -> AnvilChain data
// test -> sepolia -> SepoliaChain data
#[derive(Debug, Deserialize)]
struct Config {
    chains: HashMap<String, HashMap<String, Chain>>,
    domains: HashMap<String, HashMap<String, String>>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    // Load environment variables from .env file
    dotenv().ok();

    // Parse CLI args, using ENV vars if not provided
    let args = Args::parse();

    // Set up tracing and parse args.
    let env_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::fmt()
        .with_env_filter(env_layer)
        .with_target(true)
        .init();

    // Load the config file
    let config: Config = match std::fs::read_to_string("./crates/admin/config.toml") {
        Ok(config) => toml::from_str(&config).unwrap(),
        Err(_) => panic!("Failed to read config.toml file."),
    };

    // Create database client
    let db_client = Client::with_uri_str(args.database_uri)
        .await
        .expect("Failed to connect to database.");

    // Perform subcommand logic
    match args.subcommand {
        Subcommands::InitDatabase => {
            // 1. Drop the database on the provided client
            db_client
                .database(&args.database_name)
                .drop(None)
                .await
                .unwrap();

            // 2. Create the database indexes defined in the database models
            info!("Creating database indexes.");
            create_chain_index(&db_client, &args.database_name).await;

            // Get the chains to add to the database from the environment config
            let chains = match config.chains.get(&args.environment) {
                Some(chains) => chains,
                None => panic!("No chains found for the environment."),
            };

            // Iterate through the chains and insert them into the database
            for (name, chain) in chains {
                info!("Inserting chain into database: {}", name);

                // Insert RPC urls for the chain into the database
                insert_chain(
                    &db_client,
                    &args.database_name,
                    &chain.chain_id,
                    &chain.http_rpc_url,
                    &chain.ws_rpc_url,
                )
                .await
                .expect("Failed to insert chains into database.");
            }

            // Get the domains to add to the database from the environment config
            let domains = match config.domains.get(&args.environment) {
                Some(domains) => domains,
                None => panic!("No domains found for the environment."),
            };

            // Iterate through the domains and insert them into the database
            for (name, domain) in domains {
                info!("Inserting domain into database: {}", name);

                // Parse domain string into Authority
                let domain =
                    Authority::try_from(domain.clone()).expect("Failed to parse domain string.");

                // Insert domain into the database
                insert_domain(&db_client, &args.database_name, &domain)
                    .await
                    .expect("Failed to insert domain into database.");
            }

            info!("Database initialized for {} environment.", args.environment);
        }
        Subcommands::AddChain { chain } => {
            // 1. Get the chain information from the config file that is to be added
            let chain_name = chain;
            let chain = match config.chains.get(&args.environment) {
                Some(chains) => match chains.get(&chain_name) {
                    Some(chain) => chain,
                    None => panic!("Chain not found in the environment."),
                },
                None => panic!("No chains found for the environment."),
            };

            // 2. Check if a chain already exists with the same chain_id
            let chain_exists = does_chain_exist(&db_client, &args.database_name, &chain.chain_id)
                .await
                .is_ok();
            debug!("Chain exists: {}", chain_exists);

            // 3. Insert chain rpc urls into the database if they are not already present
            if !chain_exists {
                info!("Adding chain to database.");
                insert_chain(
                    &db_client,
                    &args.database_name,
                    &chain.chain_id,
                    &chain.http_rpc_url,
                    &chain.ws_rpc_url,
                )
                .await
                .expect("Failed to insert chain into database.");
            }

            info!("Finished adding chain to the database.");
        }
        Subcommands::AddDomain { domain } => {
            // 1. Parse domain string into Authority
            let domain = Authority::try_from(domain).expect("Failed to parse domain string.");

            // 2. Insert domain into the database
            insert_domain(&db_client, &args.database_name, &domain)
                .await
                .expect("Failed to insert domain into database.");

            info!("Finished adding domain to the database.");
        }
    }

    Ok(())
}
