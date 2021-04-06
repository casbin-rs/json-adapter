use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Policies(pub(crate) HashMap<String, Vec<Vec<String>>>);

impl Policies {
    pub fn new() -> Policies {
        Policies(HashMap::new())
    }
}

