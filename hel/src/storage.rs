//! Key -> value persistence with a per-target backend.
//!
//! - Native: the key is a filesystem path; backed by `std::fs`.
//! - WASM: the key is a localStorage key; backed by JS imports
//!   `hel_storage_get` / `hel_storage_set` (provided by the host page).
//!
//! This lets the same command code (`init`, `source`, `dump`/`save`, `correct`)
//! persist to files on the CLI and to the browser's localStorage on the web,
//! with no per-call-site branching.

use std::io;

#[cfg(not(target_arch = "wasm32"))]
pub fn read(key: &str) -> io::Result<String> {
    std::fs::read_to_string(key)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn write(key: &str, data: &str) -> io::Result<()> {
    std::fs::write(key, data)
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = hel_storage_get)]
        pub fn get(key: &str) -> Option<String>;
        #[wasm_bindgen(js_name = hel_storage_set)]
        pub fn set(key: &str, val: &str);
    }
}

#[cfg(target_arch = "wasm32")]
pub fn read(key: &str) -> io::Result<String> {
    match imp::get(key) {
        Some(v) => Ok(v),
        None => Err(io::Error::new(io::ErrorKind::NotFound, "key not found in localStorage")),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn write(key: &str, data: &str) -> io::Result<()> {
    imp::set(key, data);
    Ok(())
}
