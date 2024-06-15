// database/domains/model.rs - model for the domains collection
use mongodb::{bson::doc, options::IndexOptions, Client, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainModel {
    pub domain: String,
}

pub async fn create_domain_index(client: &Client, database: &str) {
    let options = IndexOptions::builder().unique(true).build();

    let model = IndexModel::builder()
        .keys(doc! { "domain": 1 })
        .options(options)
        .build();

    client
        .database(database)
        .collection::<DomainModel>("domains")
        .create_index(model, None)
        .await
        .expect("Failed to create domain index.");
}
