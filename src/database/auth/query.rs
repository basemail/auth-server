// database/auth/query.rs - Database queries for the defined auth models

use super::model::{NonceModel, RefreshTokenModel};
use mongodb::bson::{doc, DateTime};
use mongodb::{Client, Collection};

pub async fn insert_nonce(client: &Client, database: &str, nonce: &str) -> Result<(), String> {
    let collection: Collection<NonceModel> = client.database(database).collection("nonces");

    let nonce_model = NonceModel {
        nonce: nonce.to_string(),
        created_at: DateTime::now(),
    };

    let result = collection.insert_one(nonce_model, None).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn get_nonce(
    client: &Client,
    database: &str,
    nonce: &str,
) -> Result<Option<String>, String> {
    let collection: Collection<NonceModel> = client.database(database).collection("nonces");

    let result = collection.find_one(doc! { "nonce": nonce }, None).await;

    match result {
        Ok(Some(result)) => Ok(Option::from(result.nonce)),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn insert_refresh_token(
    client: &Client,
    database: &str,
    token: &str,
) -> Result<(), String> {
    let collection: Collection<RefreshTokenModel> = client
        .database(database)
        .collection("invalid-refresh-tokens");

    let token_model = RefreshTokenModel {
        token: token.to_string(),
        created_at: DateTime::now(),
    };

    let result = collection.insert_one(token_model, None).await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn get_refresh_token(
    client: &Client,
    database: &str,
    refresh_token: &str,
) -> Result<Option<String>, String> {
    let collection: Collection<RefreshTokenModel> = client
        .database(database)
        .collection("invalid-refresh-tokens");

    let result = collection
        .find_one(doc! { "token": refresh_token }, None)
        .await;

    match result {
        Ok(Some(result)) => Ok(Option::from(result.token)),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
