// auth.rs - Data structures and utility functions used to authenticate users to the API

use super::utils::get_environment_variable;
use actix_web::{
    dev::Payload,
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorUnauthorized},
    http::header::{HeaderMap, AUTHORIZATION},
    Error, FromRequest, HttpRequest,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use tracing::{debug, error};

// Message and signature from siwe for signin request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigninData {
    pub message: String,
    pub signature: String,
}

// Claims to be added to JWT
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub sub: String, // Optional. Subject (whom token refers to)
}

#[derive(Debug)]
pub struct SiweUser {
    pub address: String,
}

impl FromRequest for SiweUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<SiweUser, Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let addr = req.match_info().query("address").parse::<String>().unwrap();
        debug!("FromRequest for SiweUser - parsed address: {}", &addr);

        let res: Result<String, Error> = 
        if addr.is_empty() {
            Err(ErrorBadRequest("Address not found"))
        } else {
            debug!("Checking authorization...");
            authorize(addr, req.headers())
        };

        Box::pin(async move {
            match res {
                Ok(_) => {
                    debug!("Success!");
                    Ok(SiweUser {
                        address: res.unwrap(),
                    })
                }
                Err(e) => Err(e),
            }
        })
    }
}

// Creates a JWT for the address provided
pub fn create_jwt(address: &String, validity_in_seconds: i64) -> Result<String, Error> {
    let jwt_secret = match get_environment_variable("JWT_SECRET".to_string()) {
        Ok(secret) => secret,
        Err(e) => {
            error!("Error getting JWT secret: {}", e);
            return Err(ErrorInternalServerError(
                "Failed to load environment variable",
            ));
        }
    };

    debug!("Setting expiration for JWT.");
    let expiration = (match chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(validity_in_seconds))
    {
        Some(expiration) => expiration,
        None => {
            error!("Error setting expiration for JWT.");
            return Err(ErrorInternalServerError("Failed to set expiration for JWT"));
        }
    })
    .timestamp();

    debug!("Setting claims for JWT.");
    let claims = Claims {
        sub: address.to_owned(),
        exp: expiration as usize,
    };

    debug!("Encoding JWT.");
    let header = Header::new(Algorithm::HS512);
    return match encode(
        &header,
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    ) {
        Ok(res) => Ok(res),
        Err(e) => {
            error!("Error encoding {} JWT", e);
            Err(ErrorInternalServerError("Internal Server Error"))
        }
    };
}

// Gets a JWT from the request headers
pub fn jwt_from_header(headers: &HeaderMap) -> Result<String, Error> {
    debug!("Extracting authorization header...");
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => {
            debug!("Success!");
            v
        }
        None => return Err(ErrorBadRequest("Auth header not found")),
    };

    debug!("Extracting header value...");
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => {
            debug!("Success!");
            v
        }
        Err(_) => return Err(ErrorBadRequest("Auth header not found")),
    };

    debug!("Checking header format...");
    if !auth_header.starts_with("Bearer") {
        return Err(ErrorBadRequest("Invalid Auth Header"));
    }
    debug!("Success!");

    debug!("Trimming header...");
    Ok(auth_header.trim_start_matches("Bearer ").to_owned())
}

// Checks whether the address provided matches the address in the subject field of the JWT claims
pub fn authorize(address: String, headers: &HeaderMap) -> Result<String, Error> {
    let jwt_secret = match get_environment_variable("JWT_SECRET".to_string()) {
        Ok(secret) => secret,
        Err(e) => {
            error!("Error getting JWT secret: {}", e);
            return Err(ErrorInternalServerError(
                "Failed to load environment variable",
            ));
        }
    };

    match jwt_from_header(headers) {
        Ok(jwt) => {
            debug!("Authorization header successfully extracted");

            debug!("Setting validation requirements...");
            let mut validation = Validation::new(Algorithm::HS512);
            validation.sub = Some(address.clone());

            debug!("Decoding JWT...");
            let res = match decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(jwt_secret.as_ref()),
                &validation,
            ) {
                Ok(_claims) => {
                    debug!("JWT for {} successfully decoded", { &address });
                    Ok(address)
                }
                Err(e) => {
                    error!(
                        "Validation failed for token {} with address {}. Error: {}",
                        &jwt,
                        &address,
                        e.to_string()
                    );
                    Err(ErrorUnauthorized("Invalid Authorization"))
                }
            };
            res
        }
        Err(e) => {
            error!(
                "Extraction failed for headers {:#?} Error: {}",
                &headers,
                e.to_string()
            );
            Err(e)
        }
    }
}
