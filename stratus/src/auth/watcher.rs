use crate::auth::user::ReloadableUserStore;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Start watching a user database file for changes and reload it automatically.
///
/// Delegates to the shared `watcher::start_file_watcher` utility.
/// On reload failure the previous in-memory user store is kept (fail-safe).
pub fn start_user_db_watcher(
    user_store: Arc<ReloadableUserStore>,
    db_path: PathBuf,
) -> Result<(), notify::Error> {
    info!("Starting file watcher for user database: {:?}", db_path);

    let watch_path = db_path.canonicalize().unwrap_or_else(|_| db_path.clone());
    let parent_dir = watch_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    info!("File watcher started for {:?}", db_path);

    crate::watcher::start_file_watcher(vec![watch_path.clone()], vec![parent_dir], move || {
        info!("User database file changed, reloading...");
        match user_store.reload(&watch_path) {
            Ok(()) => {
                info!(
                    "Successfully reloaded user database: {} user(s)",
                    user_store.len()
                );
                if user_store.is_empty() {
                    warn!(
                        "User database is now empty — no users will be able to authenticate!"
                    );
                }
            }
            Err(e) => {
                error!("Failed to reload user database: {}", e);
                error!("Keeping previous user database in memory");
            }
        }
    })
}
