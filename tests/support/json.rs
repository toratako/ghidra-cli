//! Decode the public CLI result envelope without accepting alternative shapes.
#![allow(dead_code)]
use serde::de::DeserializeOwned;

#[derive(serde::Deserialize)]
struct ResultData<T> {
    data: T,
}

pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    serde_json::from_slice::<ResultData<T>>(bytes).map(|result| result.data)
}

pub fn from_str<T: DeserializeOwned>(text: &str) -> serde_json::Result<T> {
    serde_json::from_str::<ResultData<T>>(text).map(|result| result.data)
}
