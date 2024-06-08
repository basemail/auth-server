// utils.rs - utility functions used across modules

use actix_web::error::ErrorInternalServerError;
use actix_web::Error;
use std::env;
use tracing::{debug, error};

pub fn get_environment_variable(key: String) -> Result<String, Error> {
    debug!("Loading {} from environment...", &key);
    match env::var(&key) {
        Ok(var) => Ok(var),
        Err(_e) => {
            error!("Error loading {} from environment", key);
            Err(ErrorInternalServerError("Internal Server Error"))
        }
    }
}
