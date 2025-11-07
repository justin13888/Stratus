# User Database Hot-Reloading

## Overview

Stratus supports hot-reloading of the user database file (`users.toml`) without requiring a server restart. This feature allows you to add, remove, or modify user accounts on-the-fly while the server is running.

This page is relevant only when using the `Basic` authentication method with a specified user database file.

## How It Works

When authentication is enabled with the `Basic` authentication method, Stratus automatically starts a file watcher that monitors the configured `user_db_file` for changes. When the file is modified, the server will:

1. Detect the file system change event
2. Apply a debounce delay (500ms) to avoid multiple rapid reloads
3. Attempt to reload and parse the user database
4. If successful, atomically replace the old user database with the new one
5. If parsing fails, keep the old database and log an error

## Configuration

No additional configuration is needed. Hot-reloading is automatically enabled when:

- Authentication is required (`auth_required = true`)
- Authentication method is set to `Basic` (`auth_method = "basic"`)
- A user database file is specified (`user_db_file = "users.toml"`)

Example configuration in `config.toml`:

```toml
[security]
auth_required = true
auth_method = "basic"
user_db_file = "users.toml"
```

## Usage

### Adding a New User

1. Generate a password hash using `stratus-hashgen`:

   ```bash
   stratus-hashgen
   # Enter password when prompted
   ```

2. Edit `users.toml` and add the new user:

   ```toml
   [users.newuser]
   password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
   groups = ["users"]
   ```

3. Save the file. The server will automatically reload within 500ms.

### Modifying User Groups/Metadata

Simply edit the `users.toml` file and save. Changes will be applied immediately:

```toml
[users.alice]
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
groups = ["admin", "users"]  # Added admin group

[users.alice.metadata]
department = "Engineering"
```

### Removing a User

Delete the user's entry from `users.toml` and save. The user will be immediately unable to authenticate.

## Logging

The server logs all reload events:

```
INFO  stratus::auth] Hot-reloading enabled for user database
INFO  stratus::auth::watcher] Starting file watcher for user database: "users.toml"
INFO  stratus::auth::watcher] File watcher started for "users.toml"
INFO  stratus::auth::watcher] User database file changed, reloading...
INFO  stratus::auth::watcher] Successfully reloaded user database: 5 user(s)
```

If a reload fails (e.g., invalid TOML syntax), the error is logged and the previous database is retained:

```
ERROR stratus::auth::watcher] Failed to reload user database: Failed to parse...
ERROR stratus::auth::watcher] Keeping previous user database in memory
```

## Error Handling

The hot-reload mechanism is designed to be safe and non-disruptive:

- **Parse Errors**: If the new file has syntax errors, the old database is kept and an error is logged
- **File Not Found**: If the file is temporarily unavailable (e.g., during an atomic write), the reload is skipped
- **Empty Database**: A warning is logged if the database becomes empty (no users can authenticate)
- **Concurrent Access**: The database uses read-write locks to ensure thread-safe access during reloads

## Technical Details

- **File Watching**: Uses the `notify` crate with platform-specific backends:
  - **Linux**: inotify (native kernel support)
  - **macOS**: FSEvents or kqueue (depending on availability)
  - **Windows**: ReadDirectoryChangesW
  - **BSD**: kqueue
- **Debouncing**: 500ms delay prevents multiple reloads from text editor autosaves or multiple rapid edits
- **Thread Safety**: `ReloadableUserStore` wraps the user database in an `Arc<RwLock<>>` for safe concurrent access
- **Atomic Updates**: Read operations block only during the brief write lock acquisition for the swap

## Platform Support

The hot-reloading feature is fully supported on all major platforms:

- ✅ **Linux** (inotify)
- ✅ **macOS** (FSEvents/kqueue)  
- ✅ **Windows** (ReadDirectoryChangesW)
- ✅ **BSD** (kqueue)

The `notify` crate automatically selects the most efficient file watching backend for your platform.

## Limitations

- Currently only supported for `Basic` authentication method
- File must be on a local filesystem (network filesystems may have delayed notifications)
- Very large user databases may cause brief authentication delays during reload

## Troubleshooting

### File watcher not starting

If you see:

```
WARN Failed to start user database file watcher: ...
WARN User database will not be hot-reloaded on changes
```

The server will still work but requires restart for user changes. This can happen if:

- The parent directory doesn't exist
- Insufficient permissions to watch the directory
- Platform-specific file watching is unavailable
