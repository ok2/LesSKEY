use hel::lk::LK;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref STATE: Arc<Mutex<LK>> = Arc::new(Mutex::new(LK::new()));
}
