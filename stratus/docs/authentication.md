# Authentication

Stratus supports authentication to protect your files and shares.

## Quick Start

Enable HTTP Basic Authentication in your `config.toml`:

```toml
[security]
auth_required = true
auth_method = "basic"
user_db_file = "users.toml"
```

Create a `users.toml` file with your users:

```toml
[users.alice]
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$y9c+7XpPGYoJGuM16nI6zg$pTHHElkqLvOKUDy/J4Wgi1PK9epFsl75xvOqmutcWu8"  # admin123
groups = ["admin", "users"]

[users.bob]
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$Iza/p8tK6LXKQSl+2or0LQ$8zrLUnmV2Ul5W2w5ISa/rCrYRpuN3gRdgziVzHone5w"  # demo123
groups = ["users"]
```

## Authentication Methods

### HTTP Basic Authentication

Basic Authentication requires username and password with each request.

**Configuration:**

```toml
[security]
auth_required = true
auth_method = "basic"
user_db_file = "users.toml"
```

**User Database Format:**

The `users.toml` file defines your users:

```toml
[users.username]
password_hash = "$argon2id$..."  # argon2id hash of password
groups = ["group1", "group2"]  # optional user groups
```

**Generating Password Hashes:**

Use the `stratus-hashgen` CLI tool to generate password hashes:

```bash
# Generate hash interactively (password hidden)
cargo run -p stratus-hashgen

# Generate hash with verification
cargo run -p stratus-hashgen --verify

# Generate hash from command line argument (less secure, for testing only)
cargo run -p stratus-hashgen mypassword123
```

The tool will output an Argon2id hash that you can copy into your `users.toml` file.

**⚠️ Security Note:** Never store plain text passwords. Always use argon2id hashes.

**Using Basic Auth:**

With curl:
```bash
curl -u username:password https://localhost:8443/shares/test/
```

In browsers, you'll be prompted for username and password automatically.

### Bearer Token (JWT) - Coming Soon

Support for JWT-based authentication with OpenID Connect is planned for a future release.

### Mutual TLS - Coming Soon

Client certificate authentication support is planned for a future release.

## User Groups

Users can belong to groups for easier access control:

```toml
[users.alice]
password_hash = "$argon2id$..."
groups = ["admin", "developers"]

[users.bob]
password_hash = "$argon2id$..."
groups = ["developers"]
```

Groups can be used in share access lists (see Authorization below).

## Authorization (Share Access Control)

Control which users can access specific shares:

```toml
[shares.public]
path = "/srv/public"
guest_ok = true  # Allow access without authentication

[shares.private]
path = "/srv/private"
read_list = ["alice", "@admin"]   # User 'alice' or anyone in 'admin' group
write_list = ["@admin"]            # Only 'admin' group members
admin_list = ["alice"]             # Share administrators
deny_list = ["bob"]                # Explicitly denied users
```

**Access List Syntax:**
- `"username"` - Specific user
- `"@groupname"` - All users in group
- `[]` - Empty list means all authenticated users

**⚠️ Note:** Per-share authorization is currently in development.

## Disabling Authentication

For development or trusted networks, you can disable authentication:

```toml
[security]
auth_required = false
```

**⚠️ Warning:** Only disable authentication if your server is not exposed to the internet.

## Testing

Test that authentication is working:

```bash
# Should return 401 Unauthorized
curl -k https://localhost:8443/shares/test/

# Should succeed with valid credentials
curl -k -u alice:admin123 https://localhost:8443/shares/test/

# Should return 401 with invalid credentials
curl -k -u alice:wrongpass https://localhost:8443/shares/test/
```

## Troubleshooting

### "User database file not found"

Create the `users.toml` file in your server directory. See `users.example.toml` for a template.

### "Authentication failed"

- Verify username and password are correct
- Check that the password hash was generated correctly
- Ensure the user exists in `users.toml`

### "User database is empty"

Your `users.toml` file has no users defined. Add at least one user or disable authentication.

### Server won't start with auth enabled

Make sure:
- `user_db_file` is specified in config
- The user database file exists
- The TOML syntax is valid

## Security Best Practices

1. **Use HTTPS Only** - Never use Basic Auth over unencrypted HTTP
2. **Strong Passwords** - Require strong passwords for all users
3. **Regular Updates** - Rotate passwords periodically
4. **Principle of Least Privilege** - Grant minimum necessary permissions
5. **Monitor Access** - Check logs for unauthorized access attempts
6. **Secure Storage** - Protect your `users.toml` file with appropriate file permissions:
   ```bash
   chmod 600 users.toml
   ```

## Example Configuration

Complete authentication setup:

```toml
[security]
auth_required = true
auth_method = "basic"
user_db_file = "users.toml"

[shares.docs]
path = "/srv/documents"
browseable = true
read_list = ["@users"]     # All users can read
write_list = ["@admin"]     # Only admins can write
deny_list = ["guest"]       # Guest user denied

[shares.public]
path = "/srv/public"
browseable = true
guest_ok = true             # No authentication required
```

For more configuration options, see `config.example.toml`.

