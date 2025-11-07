use crate::auth::user::ReloadableUserStore;
use notify::{Event, EventKind, RecursiveMode, Watcher as NotifyWatcher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Start watching a user database file for changes and reload it automatically
pub fn start_user_db_watcher(
    user_store: Arc<ReloadableUserStore>,
    db_path: PathBuf,
) -> Result<(), notify::Error> {
    info!("Starting file watcher for user database: {:?}", db_path);

    // Clone the path for use in the watcher thread
    // Canonicalize the path to ensure consistent comparison with file system events
    let watch_path = db_path.canonicalize().unwrap_or_else(|_| db_path.clone());
    let parent_dir = watch_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // Create a channel for receiving file system events
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);

    // Create the file watcher - this must succeed before we spawn the task
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                // Send the event to the async task
                if let Err(e) = tx.blocking_send(event) {
                    error!("Failed to send file watcher event: {}", e);
                }
            }
            Err(e) => {
                error!("File watcher error: {}", e);
            }
        }
    })?;

    // Watch the parent directory (watching individual files can be unreliable)
    // This must succeed before we spawn the background task
    watcher.watch(&parent_dir, RecursiveMode::NonRecursive)?;

    info!("File watcher started for {:?}", db_path);

    // Spawn a background task to handle file system events
    tokio::spawn(async move {
        // Keep watcher alive for the duration of the task
        let _watcher = watcher;

        // Debounce timer to avoid multiple rapid reloads
        let mut debounce_timer: Option<tokio::time::Instant> = None;
        let debounce_duration = Duration::from_millis(500);

        loop {
            tokio::select! {
                // Wait for file system events
                Some(event) = rx.recv() => {
                    // Check if this event is for our watched file
                    // Canonicalize event paths for comparison (handles symlinks and relative paths)
                    let relevant = event.paths.iter().any(|p| {
                        // Try to canonicalize the event path, fall back to original if it fails
                        // (file might not exist yet during atomic writes)
                        let canonical_p = p.canonicalize().unwrap_or_else(|_| p.clone());

                        // Compare canonical paths OR check if the filename matches
                        canonical_p == watch_path ||
                            p.file_name() == watch_path.file_name()
                    });

                    if !relevant {
                        continue;
                    }

                    // Check event kind - we care about modifications and creations
                    let should_reload = matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_)
                    );

                    if should_reload {
                        // Set debounce timer
                        debounce_timer = Some(tokio::time::Instant::now() + debounce_duration);
                    }
                }
                // Wait for debounce timer to expire
                _ = async {
                    if let Some(deadline) = debounce_timer {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        // Sleep forever if no timer is set
                        std::future::pending::<()>().await;
                    }
                }, if debounce_timer.is_some() => {
                    debounce_timer = None;

                    info!("User database file changed, reloading...");

                    // Attempt to reload the user store
                    match user_store.reload(&watch_path) {
                        Ok(()) => {
                            info!(
                                "Successfully reloaded user database: {} user(s)",
                                user_store.len()
                            );
                            if user_store.is_empty() {
                                warn!(
                                    "User database is now empty - no users will be able to authenticate!"
                                );
                            }
                        }
                        Err(e) => {
                            error!("Failed to reload user database: {}", e);
                            error!("Keeping previous user database in memory");
                        }
                    }
                }
            }
        }
    });

    Ok(())
}
