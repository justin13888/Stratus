use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::config::ShareConfig;
use crate::vfs::Vfs;

#[derive(Clone)]
pub struct ShareState<V: Vfs> {
    pub shares: Arc<HashMap<String, ShareConfig>>,
    pub cache_dir: PathBuf,
    pub vfs: V,
    /// Per-share connection semaphores, present only when max_connections is configured.
    pub semaphores: Arc<HashMap<String, Arc<Semaphore>>>,
}

impl<V: Vfs> ShareState<V> {
    pub fn new(shares: HashMap<String, ShareConfig>, cache_dir: PathBuf, vfs: V) -> Self {
        let semaphores = shares
            .iter()
            .filter_map(|(name, cfg)| {
                cfg.max_connections
                    .map(|n| (name.clone(), Arc::new(Semaphore::new(n))))
            })
            .collect::<HashMap<_, _>>();
        Self {
            shares: Arc::new(shares),
            cache_dir,
            vfs,
            semaphores: Arc::new(semaphores),
        }
    }
}
