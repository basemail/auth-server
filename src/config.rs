// config.rs - Configuration type for the API

use mongodb::Client;

#[derive(Clone, Debug)]
pub struct Config {
    pub client: Client,
    pub database: String,
}
