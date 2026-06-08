#[macro_use]
extern crate lazy_static;
extern crate hel;

use wasm_bindgen::prelude::*;

mod hel_state;

/// Call once at page load: routes Rust panics to the browser console with a
/// readable message + stack instead of an opaque "unreachable" trap.
#[wasm_bindgen]
pub fn hel_init() {
    console_error_panic_hook::set_once();
}
