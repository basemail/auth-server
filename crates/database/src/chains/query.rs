// database/chains/query.rs - query functions for the chains collection
use super::model::ChainModel;
// use futures::TryStreamExt;
use mongodb::{
    bson::{doc, to_bson},
    Client, Collection,
};

// Insert new chain info
pub async fn insert_chain(
    client: &Client,
    database: &str,
    chain_id: &u64,
    http_rpc_url: &str,
    ws_rpc_url: &str,
) -> Result<(), &'static str> {
    let collection: Collection<ChainModel> = client.database(database).collection("chains");

    let chain_model = ChainModel {
        chain_id: *chain_id,
        http_rpc_url: http_rpc_url.to_string(),
        ws_rpc_url: ws_rpc_url.to_string(),
    };

    // Check if chain already exists
    match collection
        .find_one(doc! { "chain_id": to_bson(chain_id).unwrap() }, None)
        .await
    {
        Ok(Some(_)) => return Err("Chain already exists in database."),
        Ok(None) => (),
        Err(_) => return Err("Failed to check if chain exists in database"),
    }

    // Insert new chain
    let result = collection.insert_one(chain_model, None).await;

    match result {
        Ok(_) => Ok(()),
        Err(_) => Err("Failed to insert chain into database"),
    }
}

// // Remove chain
// pub async fn delete_chain(
//     client: &Client,
//     database: &str,
//     chain_id: &u64,
// ) -> Result<(), &'static str> {
//     let collection: Collection<ChainModel> = client.database(database).collection("chains");

//     // Check if rpcs already exist for chain, if not, return error
//     match collection
//         .find_one(doc! { "chain_id": to_bson(chain_id).unwrap() }, None)
//         .await
//     {
//         Ok(Some(_)) => (),
//         Ok(None) => return Err("Chain does not exist in database"),
//         Err(_) => return Err("Failed check if chain exists in database"),
//     }

//     let result = collection
//         .delete_one(doc! { "chain_id": to_bson(chain_id).unwrap() }, None)
//         .await;

//     match result {
//         Ok(_) => Ok(()),
//         Err(_) => Err("Failed to remove chain from database"),
//     }
// }

// // Change rpcs for a chain
// pub async fn update_chain(
//     client: &Client,
//     database: &str,
//     chain_id: &u64,
//     http_rpc_url: &str,
//     ws_rpc_url: &str,
// ) -> Result<(), &'static str> {
//     let collection: Collection<ChainModel> = client.database(database).collection("chains");

//     // Check if chain exists in database, if not, return error
//     match collection
//         .find_one(doc! { "chain_id": to_bson(chain_id).unwrap() }, None)
//         .await
//     {
//         Ok(Some(_)) => (),
//         Ok(None) => return Err("Chain does not exist in database"),
//         Err(_) => return Err("Failed to check if chain exists in database"),
//     }

//     let result = collection
//         .update_one(
//             doc! { "chain_id": to_bson(chain_id).unwrap() },
//             doc! { "$set": { "http_rpc_url": http_rpc_url, "ws_rpc_url": ws_rpc_url } },
//             None,
//         )
//         .await;

//     match result {
//         Ok(_) => Ok(()),
//         Err(_) => Err("Failed to update chain in database"),
//     }
// }

// Check if chain exists
pub async fn does_chain_exist(
    client: &Client,
    database: &str,
    chain_id: &u64,
) -> Result<bool, &'static str> {
    let collection: Collection<ChainModel> = client.database(database).collection("chains");

    let result = collection
        .find_one(doc! { "chain_id": to_bson(chain_id).unwrap() }, None)
        .await;

    match result {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Err("Failed to get chain from database"),
    }
}

pub async fn get_chain(
    client: &Client,
    database: &str,
    chain_id: &u64,
) -> Result<ChainModel, &'static str> {
    let collection: Collection<ChainModel> = client.database(database).collection("chains");

    let result = collection
        .find_one(doc! { "chain_id": to_bson(chain_id).unwrap() }, None)
        .await;

    match result {
        Ok(Some(chain_model)) => Ok(chain_model),
        Ok(None) => Err("Chain does not exist in database"),
        Err(_) => Err("Failed to get chain from database"),
    }
}

// pub async fn get_all_chain_ids(client: &Client, database: &str) -> Result<Vec<u64>, &'static str> {
//     let collection: Collection<ChainModel> = client.database(database).collection("chains");

//     let mut cursor = collection.find(None, None).await.unwrap();

//     let mut chain_ids: Vec<u64> = vec![];

//     loop {
//         match cursor.try_next().await {
//             Ok(Some(chain_model)) => chain_ids.push(chain_model.chain_id),
//             Ok(None) => break,
//             Err(_) => return Err("Error iterating through chains"),
//         }
//     }

//     Ok(chain_ids)
// }
