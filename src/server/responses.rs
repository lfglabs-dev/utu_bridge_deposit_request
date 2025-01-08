// server/responses.rs
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub struct ApiResponse {
    pub status: Status,
    pub data: Value,
}

impl ApiResponse {
    pub fn new<T: Serialize>(status: Status, data: T) -> Self {
        ApiResponse {
            status,
            data: serde_json::to_value(data).expect("Failed to convert to Value"),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum Status {
    Success,
    Error,
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest,
    InternalServerError,
}
