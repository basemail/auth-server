use mongodb::bson::doc;
use mongodb::options::IndexOptions;
use mongodb::{Collection, IndexModel};
use std::time::Duration;

pub mod model;
pub mod query;

pub async fn set_ttl_index<T>(collection: Collection<T>, duration_in_secs: u64) {
    // Expire invalid refresh tokens by removing them from the DB
    let options = IndexOptions::builder()
        .expire_after(Duration::from_secs(duration_in_secs))
        .build();

    // Apply options above to created_at key
    let model = IndexModel::builder()
        .keys(doc! {"created_at": 1})
        .options(options)
        .build();

    let _result = collection.create_index(model, None).await;
}
