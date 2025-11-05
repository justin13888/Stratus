use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::ShareConfig;

#[derive(Clone)]
pub struct ShareState {
    pub shares: Arc<HashMap<String, ShareConfig>>,
    pub cache_dir: PathBuf,
}

impl ShareState {
    pub fn new(shares: HashMap<String, ShareConfig>, cache_dir: PathBuf) -> Self {
        Self {
            shares: Arc::new(shares),
            cache_dir,
        }
    }
}
