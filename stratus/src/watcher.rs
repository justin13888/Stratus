//! Debounced filesystem watcher utility
//!
//! Provides a single, reusable watcher loop used by both the TLS certificate
//! hot-reloader and the user database hot-reloader. Centralising the logic here
//! ensures both subsystems behave identically and that any fix applies to both.

use notify::{Event, EventKind, RecursiveMode, Watcher as NotifyWatcher};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

/// Number of filesystem events to buffer before the consumer processes them.
/// Sized to absorb burst writes (e.g. during atomic file replacement) without
/// blocking the notify callback thread.
pub const WATCHER_CHANNEL_CAPACITY: usize = 100;

/// Milliseconds to wait after the last relevant event before calling `on_change`.
/// Prevents redundant reloads during atomic file replacement sequences where the
/// OS may emit several events (unlink, create, rename) for a single logical write.
pub const WATCHER_DEBOUNCE_MS: u64 = 500;

/// Start a debounced file watcher that calls `on_change` whenever any of the
/// `watched_paths` is created or modified.
///
/// # Parameters
/// - `watched_paths`: Canonical paths to match events against.
/// - `watch_dirs`: Parent directories to register with the OS watcher (duplicates
///   are deduplicated automatically).
/// - `on_change`: Callback invoked once per debounce window after a relevant change.
///   Called from a spawned tokio task; must be `Send + 'static`.
///
/// Returns immediately; the watcher loop runs in a background tokio task that
/// keeps the underlying `notify::Watcher` alive for the process lifetime.
///
/// # Errors
/// Returns an error if the watcher backend cannot be initialised or a directory
/// cannot be registered.
pub fn start_file_watcher(
    watched_paths: Vec<PathBuf>,
    watch_dirs: Vec<PathBuf>,
    on_change: impl Fn() + Send + 'static,
) -> Result<(), notify::Error> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(WATCHER_CHANNEL_CAPACITY);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            // Ignore send errors: they only occur if the receiver was dropped,
            // which means the server is shutting down.
            let _ = tx.blocking_send(event);
        }
    })?;

    // Deduplicate watch directories so we don't register the same directory twice
    // (e.g. when cert and key files share a parent directory).
    let unique_dirs: HashSet<PathBuf> = watch_dirs.into_iter().collect();
    for dir in &unique_dirs {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
    }

    tokio::spawn(async move {
        // Move watcher into the task to keep it alive for the task's lifetime.
        let _watcher = watcher;
        let debounce_duration = Duration::from_millis(WATCHER_DEBOUNCE_MS);
        let mut debounce_timer: Option<tokio::time::Instant> = None;

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    // An event is relevant if it touches one of our watched paths.
                    // We compare both canonical paths and filenames to handle atomic
                    // writes that temporarily change the inode (e.g. rename-over).
                    let relevant = event.paths.iter().any(|p| {
                        let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
                        watched_paths.iter().any(|watched| {
                            canonical == *watched || p.file_name() == watched.file_name()
                        })
                    });

                    if relevant && matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        debounce_timer = Some(tokio::time::Instant::now() + debounce_duration);
                    }
                }
                _ = async {
                    if let Some(deadline) = debounce_timer {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if debounce_timer.is_some() => {
                    debounce_timer = None;
                    on_change();
                }
            }
        }
    });

    Ok(())
}
