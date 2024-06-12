// routes.rs - API routes for authentication requests

use super::auth::*;
use super::config::Config;
use super::utils::get_environment_variable;
use actix_web::{
    error, get,
    http::header::ContentType,
    post,
    web::{Data, Json},
    Error, HttpResponse,
};
use database::{
    auth::query::{get_nonce, get_refresh_token, insert_nonce, insert_refresh_token},
    chains::query::get_chain,
    domains::is_domain_supported,
};
use ethers::{
    providers::{Http, Provider},
    types::Signature,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Serialize;
use siwe::{eip55, generate_nonce, Message, VerificationOpts};
use std::str::FromStr;
use tracing::{debug, error, info, warn};

#[tracing::instrument(
    name = "/nonce - Returns a nonce for the sign in request",
    skip(config)
)]
#[get("/nonce")]
pub async fn nonce(config: Data<Config>) -> Result<HttpResponse, Error> {
    info!("Generating auth nonce");
    // Use siwe to generate a nonce for the message signature request
    let nonce = generate_nonce();

    debug!("Inserting nonce into database");
    let result = insert_nonce(&config.client, &config.database, &nonce).await;

    // Return nonce if successful
    match result {
        Ok(_) => {
            debug!("Nonce successfully inserted");
            Ok(HttpResponse::Ok()
                .content_type(ContentType::json())
                .body(nonce))
        }
        Err(e) => {
            error!("{}", e);
            Err(error::ErrorInternalServerError("Error inserting nonce"))
        }
    }
}

#[derive(Serialize)]
struct JWTPair {
    pub access_token: String,
    pub refresh_token: String,
}

//
#[tracing::instrument(
    name = "/sign_in - Signs the user in, creating and returning a JWT",
    skip(config)
)]
#[post("/sign_in")]
pub async fn sign_in(
    config: Data<Config>,
    req_data: Json<SigninData>,
) -> Result<HttpResponse, Error> {
    let message: Message = match req_data.message.as_str().parse() {
        Ok(message) => message,
        Err(e) => {
            error!("Error parsing message: {}", e);
            return Err(error::ErrorBadRequest("Invalid message"));
        }
    };
    let address = eip55(&message.address);
    let signature: Signature = match Signature::from_str(&req_data.signature) {
        Ok(signature) => signature,
        Err(e) => {
            error!("Error parsing signature: {}", e);
            return Err(error::ErrorBadRequest("Invalid signature"));
        }
    };
    info!(
        "Received user sign-in request. Address: {}. Message: {}",
        address, message
    );

    // Check the nonce is valid
    debug!("Checking that nonce is valid");
    let _ok: Result<(), Error> =
        match get_nonce(&config.client, &config.database, &message.nonce).await {
            Ok(Some(_result)) => {
                debug!("Nonce is valid");
                Ok(())
            }
            Ok(None) => return Err(error::ErrorBadRequest("Invalid nonce")),
            Err(e) => {
                error!("Error getting nonce from DB: {}", e);
                return Err(error::ErrorInternalServerError("Internal Server Error"));
            }
        };

    // Check that the domain of the message is supported
    match is_domain_supported(&config.client, &config.database, &message.domain).await {
        Ok(true) => {}
        Ok(false) => {
            warn!("Domain is not supported: {}", message.domain);
            return Err(error::ErrorBadRequest("Unsupported domain"));
        }
        Err(e) => {
            error!("Error checking domain: {}", e);
            return Err(error::ErrorInternalServerError("Internal Server Error"));
        }
    }

    // Check that the chain_id is supported and load the chain data
    let chain = match get_chain(&config.client, &config.database, &message.chain_id).await {
        Ok(chain) => chain,
        Err(e) => {
            error!("Error getting chain from DB: {}", e);
            return Err(error::ErrorInternalServerError("Internal Server Error"));
        }
    };

    // Create a provider for the chain to be able to verify contract (eip 1271) signatures
    let provider = match Provider::<Http>::try_from(chain.http_rpc_url.as_str()) {
        Ok(provider) => provider,
        Err(e) => {
            error!("Error creating provider: {}", e);
            return Err(error::ErrorInternalServerError("Internal Server Error"));
        }
    };

    // Create verification options for the siwe verify transaction, confirming the correct nonce
    debug!("Verifying user signature.");
    let verification_opts = VerificationOpts {
        domain: Some(message.domain.clone()),
        nonce: Some(message.nonce.clone()),
        rpc_provider: Some(provider),
        timestamp: None,
    };

    // Return error if nonce does not match
    if let Err(_e) = message
        .verify(signature.to_vec().as_slice(), &verification_opts)
        .await
    {
        warn!("Could not verify signature.");
        return Err(error::ErrorBadRequest("Could not verify signature"));
    }
    debug!("Signature verified.");

    // Create and return a JWT for the user's address
    let access_token = match create_jwt(&address, 60) {
        Ok(access_token) => access_token,
        Err(e) => {
            error!("Error creating access token: {}", e.to_string());
            return Err(error::ErrorInternalServerError(
                "Failed to create access token",
            ));
        }
    };

    let refresh_token = match create_jwt(&address, 86400) {
        Ok(refresh_token) => refresh_token,
        Err(e) => {
            error!("Error creating refresh token: {}", e.to_string());
            return Err(error::ErrorInternalServerError(
                "Failed to create refresh token",
            ));
        }
    };

    let jwt_pair = JWTPair {
        access_token,
        refresh_token,
    };

    info!("User signed in: {}", address);
    let body = match serde_json::to_string(&jwt_pair) {
        Ok(body) => body,
        Err(_) => {
            return Err(error::ErrorInternalServerError(
                "Failed to serialize response.",
            ))
        }
    };

    Ok(HttpResponse::Ok().body(body))
}

#[tracing::instrument(
    name = "/refresh - Checks a provided refresh token, returns a new access token and refresh token.",
    skip(config)
)]
#[post("/refresh")]
pub async fn refresh(config: Data<Config>, req_data: Json<String>) -> Result<HttpResponse, Error> {
    let token_string: String = req_data.to_string();

    let jwt_secret = get_environment_variable("JWT_SECRET".to_string());

    if jwt_secret.is_err() {
        error!("Error getting JWT_SECRET: {}", jwt_secret.err().unwrap());
        return Err(error::ErrorInternalServerError("Internal Server Error"));
    }
    let jwt_secret = jwt_secret.unwrap();

    debug!("Received user refresh request. Checking if refresh token has been used before...");
    // A refresh token should only be used once, check this one hasn't been used before
    let _ok: Result<(), Error> =
        match get_refresh_token(&config.client, &config.database, &token_string).await {
            Ok(Some(_result)) => {
                warn!("Refresh Token has previously been used: {}", token_string);
                return Err(error::ErrorBadRequest("Expired Refresh Token"));
            }
            Ok(None) => {
                debug!("Refresh token is valid.");
                Ok(())
            }
            Err(e) => {
                error!("Error checking DB for refresh token: {}", e);
                return Err(error::ErrorInternalServerError(
                    "Failed to check refresh token",
                ));
            }
        };

    debug!("Setting validation requirements...");
    let validation = Validation::new(Algorithm::HS512);

    debug!("Decoding refresh token...");
    let claims = match decode::<Claims>(
        &token_string,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &validation,
    ) {
        Ok(claims) => {
            debug!("Refresh token successfully decoded");
            claims
        }
        Err(e) => {
            error!(
                "Validation failed for refresh token {} Error: {}",
                &token_string,
                e.to_string()
            );
            return Err(error::ErrorBadRequest("Invalid Refresh Token"));
        }
    };

    debug!("Inserting refresh token into DB.");
    // If it has not been used before, insert into the DB so it cannot be re-used
    match insert_refresh_token(&config.client, &config.database, &token_string).await {
        Ok(_) => {
            debug!("Refresh token inserted successfully.");
        }
        Err(e) => {
            error!("Error inserting refresh token in DB: {}", e);
            return Err(error::ErrorInternalServerError(
                "Failed to insert refresh token",
            ));
        }
    };

    // Create and return a JWT for the user's address
    debug!("Creating new JWT pair.");
    let new_access_token = match create_jwt(&claims.claims.sub, 60) {
        Ok(access_token) => access_token,
        Err(e) => {
            error!("Error creating access token: {}", e.to_string());
            return Err(error::ErrorInternalServerError(
                "Failed to create access token",
            ));
        }
    };

    let new_refresh_token = match create_jwt(&claims.claims.sub, 86400) {
        Ok(refresh_token) => refresh_token,
        Err(e) => {
            error!("Error creating refresh token: {}", e.to_string());
            return Err(error::ErrorInternalServerError(
                "Failed to create refresh token",
            ));
        }
    };

    let jwt_pair = JWTPair {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
    };

    let body = match serde_json::to_string(&jwt_pair) {
        Ok(body) => body,
        Err(_) => {
            return Err(error::ErrorInternalServerError(
                "Failed to serialize response.",
            ))
        }
    };

    info!("User refresh succeeded.");
    Ok(HttpResponse::Ok().body(body))
}

#[tracing::instrument(
    name = "/validate - Verifies an access token was issued by this service and returns the address",
    skip(_config)
)]
#[get("/validate/")]
pub async fn validate(
    _config: Data<Config>,
    access_token: Json<String>,
) -> Result<HttpResponse, Error> {
    let token_string: String = access_token.to_string();

    let jwt_secret = get_environment_variable("JWT_SECRET".to_string());

    if jwt_secret.is_err() {
        error!("Error getting JWT_SECRET: {}", jwt_secret.err().unwrap());
        return Err(error::ErrorInternalServerError("Internal Server Error"));
    }
    let jwt_secret = jwt_secret.unwrap();

    debug!("Setting validation requirements...");
    let validation = Validation::new(Algorithm::HS512);
    // TODO add issuer claim to the tokens and validate this for extra security?

    // TODO check that the nonce for the token is in the database

    // TODO check that the chain is supported and matches the one sent by the caller

    debug!("Decoding access token...");
    let claims = match decode::<Claims>(
        &token_string,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &validation,
    ) {
        Ok(token_data) => {
            debug!("Access token successfully decoded");
            token_data.claims
        }
        Err(e) => {
            error!(
                "Validation failed for access token {} Error: {}",
                &token_string,
                e.to_string()
            );
            return Err(error::ErrorBadRequest("Invalid Access Token"));
        }
    };

    // Validate the token has not expired
    let now = chrono::Utc::now().timestamp() as usize;
    if now > claims.exp {
        warn!("Access token has expired.");
        return Err(error::ErrorBadRequest("Expired Access Token"));
    }

    let address = claims.sub;

    let body = match serde_json::to_string(&address) {
        Ok(body) => body,
        Err(_) => {
            return Err(error::ErrorInternalServerError(
                "Failed to serialize response.",
            ))
        }
    };

    info!("User validated: {}", address);
    Ok(HttpResponse::Ok().body(body))
}
