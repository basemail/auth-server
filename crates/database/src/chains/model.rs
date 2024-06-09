// database/chains/model.rs - model for the chains collection
use mongodb::{bson::doc, options::IndexOptions, Client, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainModel {
    pub chain_id: u64,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
}

pub async fn create_chain_index(client: &Client, database: &str) {
    let options = IndexOptions::builder().unique(true).build();

    let model = IndexModel::builder()
        .keys(doc! { "chain_id": 1 })
        .options(options)
        .build();

    client
        .database(database)
        .collection::<ChainModel>("chains")
        .create_index(model, None)
        .await
        .expect("Failed to create index on chain_id for chains.");
}
