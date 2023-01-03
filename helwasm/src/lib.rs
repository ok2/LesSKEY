extern crate hel;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn ok_add(a: i32, b: i32) -> i32 {
    a + b + 1
}
