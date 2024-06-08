// database/model.rs - Models for the sign in request nonce and refresh token

use mongodb::bson::DateTime;
use serde::{Deserialize, Serialize};

// Model for a sign in request nonce
#[derive(Serialize, Deserialize)]
pub struct NonceModel {
    pub nonce: String,
    pub created_at: DateTime,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenModel {
    pub token: String,
    pub created_at: DateTime,
}
