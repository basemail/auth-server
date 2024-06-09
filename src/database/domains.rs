// database/domains.rs - query abstractions for the domains collection

use http::uri::Authority;
use mongodb::{
    bson::{doc, to_bson},
    Client, Collection,
};

pub async fn is_domain_supported(
    client: &Client,
    database: &str,
    domain: &Authority,
) -> Result<bool, &'static str> {
    let collection: Collection<String> = client.database(database).collection("domains");

    match collection
        .find_one(
            doc! { "domain": to_bson(&(*domain.to_string())).unwrap() },
            None,
        )
        .await
    {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Err("Failed to check if domain is supported in database"),
    }
}
