use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::ShareConfig;
use crate::vfs::Vfs;

#[derive(Clone)]
pub struct ShareState<V: Vfs> {
    pub shares: Arc<HashMap<String, ShareConfig>>,
    pub cache_dir: PathBuf,
    pub vfs: V,
}

impl<V: Vfs> ShareState<V> {
    pub fn new(shares: HashMap<String, ShareConfig>, cache_dir: PathBuf, vfs: V) -> Self {
        Self {
            shares: Arc::new(shares),
            cache_dir,
            vfs,
        }
    }
}
