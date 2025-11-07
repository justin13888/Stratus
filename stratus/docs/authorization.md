# Share Authorization

This document explains how the share authorization system works in Stratus.

## Overview

Stratus implements a flexible authorization system for controlling access to shares, similar to Samba's access control lists. The system supports:

- User-based access control
- Group-based access control
- Guest/anonymous access
- Multiple permission levels (read, write, admin)
- Explicit deny lists

## Permission Levels

There are four permission levels in ascending order:

1. **None** - No access to the share
2. **Read** - Can browse directories and download files
3. **Write** - Can read, upload, modify, and delete files
4. **Admin** - Full control over the share (reserved for future use)

## Access Control Lists

Each share can define the following access control lists in `config.toml`:

### `deny_list`

Users or groups explicitly denied access. **This takes precedence over all other lists.**

```toml
[shares.my_share]
deny_list = ["baduser", "@banned_group"]
```

### `admin_list`

Users or groups with administrative access. Admins have full permissions.

```toml
[shares.my_share]
admin_list = ["admin", "@admins"]
```

### `write_list`

Users or groups with read and write access.

```toml
[shares.my_share]
write_list = ["alice", "bob", "@developers"]
```

### `read_list`

Users or groups with read-only access.

```toml
[shares.my_share]
read_list = ["readonly_user", "@viewers"]
```

## Authorization Logic

The authorization check follows this order:

1. **Check deny_list** - If user/group is in deny list, access is denied immediately
2. **Check admin_list** - If user/group is in admin list, full access is granted
3. **Check write_list** - If user/group is in write list, read/write access is granted
4. **Check read_list** - If user/group is in read list, read access is granted
5. **Empty lists fallback** - If all lists are empty and user is authenticated:
   - If `read_only = false`: read/write access is granted
   - If `read_only = true`: read access is granted
6. **Otherwise** - Access is denied

## Group Syntax

Groups can be specified in access lists using any of these formats:

- `groupname` - Plain group name
- `@groupname` - Unix-style group prefix
- `+groupname` - Alternative group prefix

All three formats are equivalent. For example, these are the same:

```toml
read_list = ["developers", "@developers", "+developers"]
```

## Guest Access

Guest/anonymous access (for unauthenticated users) can be enabled with:

```toml
[shares.public_share]
guest_ok = true
```

When `guest_ok = true`:

- Unauthenticated users get read access only
- Write operations still require authentication

## Read-Only Shares

The `read_only` flag affects the default behavior when access lists are empty:

```toml
[shares.my_share]
read_only = true
```

- When `true`: authenticated users get read access by default
- When `false`: authenticated users get read/write access by default

**Note:** This flag does NOT override explicit write_list or admin_list entries.

## Examples

### Public Read-Only Share

```toml
[shares.public_docs]
path = "/srv/docs"
guest_ok = true
read_only = true
```

Anyone can read, no one can write.

### Private Share with Multiple Permission Levels

```toml
[shares.project]
path = "/srv/projects/alpha"
admin_list = ["alice"]
write_list = ["@developers"]
read_list = ["@stakeholders"]
deny_list = ["contractor_bob"]
```

- `alice` has admin access
- Members of `developers` group can read/write
- Members of `stakeholders` group can read
- `contractor_bob` is denied even if in other groups

### Restricted Share (Explicit Users Only)

```toml
[shares.confidential]
path = "/srv/confidential"
read_list = ["alice", "bob"]
```

Only `alice` and `bob` can access (read-only). All other authenticated users are denied.

### Open Authenticated Share

```toml
[shares.team]
path = "/srv/team"
# All lists empty - any authenticated user can read/write
```

Any authenticated user has read/write access.

## Implementation

The authorization logic is implemented in `src/shares/authz.rs` with the following key functions:

- `check_permission(user, share_config, required_permission)` - Main authorization check
- `is_in_list(username, groups, list)` - Helper to check if user/group is in an ACL

Authorization checks are performed in `src/shares/mod.rs` at the `serve_share` handler level, before any file operations are performed.

## Security Considerations

1. **Deny list has highest priority** - Use it to quickly revoke access
2. **Authentication vs Authorization** - `auth_required` in `[security]` enables authentication; share ACLs control authorization
3. **Path traversal protection** - Authorization happens after path validation to prevent bypasses
4. **Guest access is read-only** - Guest users can never write, regardless of ACLs
5. **Empty lists = authenticated access** - Be careful with empty ACLs on sensitive shares

## Testing

The authorization system includes comprehensive unit tests covering:

- Guest access scenarios
- Deny list precedence
- Each permission level
- Group-based access
- Empty list fallback behavior
- Read-only flag behavior

Run tests with:

```bash
cargo test authz
```
