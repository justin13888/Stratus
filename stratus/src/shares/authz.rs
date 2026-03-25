use crate::auth::User;
use crate::config::ShareConfig;
use tracing::debug;

/// Permission level for a share
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum Permission {
    None,
    Read,
    Write,
    Admin,
}

/// Check if a user has the required permission for a share.
///
/// Check order (highest priority first):
/// 1. `deny_list` — always blocks, overrides everything including `admin_list`.
/// 2. `admin_list` — full access (Read + Write + Admin), overrides `read_only`.
/// 3. `write_list` — read + write access; overrides the `read_only` flag because
///    explicit list membership is an intentional grant that supersedes the default.
/// 4. `read_list` — read-only access.
/// 5. Empty-lists fallback — if ALL four lists are empty, the share is open to every
///    authenticated user (Samba-compatible "unconfigured share" default). The `read_only`
///    flag IS respected here. To restrict a share, populate at least one list.
///
/// Unauthenticated (guest) users are only allowed read access when `guest_ok = true`.
pub fn check_permission(
    user: Option<&User>,
    share_config: &ShareConfig,
    required_permission: Permission,
) -> bool {
    // If guest_ok is true and no authentication is required, allow guest read access
    if user.is_none() {
        if share_config.guest_ok && required_permission == Permission::Read {
            debug!("Guest access allowed for share (guest_ok=true)");
            return true;
        } else {
            debug!("Guest access not allowed for share (guest_ok=false)");
            return false;
        }
    }

    let user = user.unwrap();
    let username = &user.username;

    // Check deny list first - this takes precedence
    if user.matches_any(&share_config.deny_list) {
        debug!("User '{}' is in deny_list", username);
        return false;
    }

    // Check admin list
    if user.matches_any(&share_config.admin_list) {
        debug!("User '{}' has admin access", username);
        return true; // Admin can do anything
    }

    // Check write list
    if user.matches_any(&share_config.write_list) {
        debug!("User '{}' has write access", username);
        return required_permission <= Permission::Write;
    }

    // Check read list
    if user.matches_any(&share_config.read_list) {
        debug!("User '{}' has read access", username);
        return required_permission <= Permission::Read;
    }

    // If lists are empty, grant access to all authenticated users
    // (unless read_only flag affects this)
    let all_lists_empty = share_config.read_list.is_empty()
        && share_config.write_list.is_empty()
        && share_config.admin_list.is_empty();

    if all_lists_empty {
        debug!(
            "All access lists empty - granting access to authenticated user '{}'",
            username
        );

        // If share is read-only, only allow read access
        if share_config.read_only {
            return required_permission <= Permission::Read;
        }

        // Otherwise allow read/write (but not admin)
        return required_permission <= Permission::Write;
    }

    // User is authenticated but not in any access list
    debug!("User '{}' not in any access list for share", username);
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_share_config(
        read_list: Vec<String>,
        write_list: Vec<String>,
        admin_list: Vec<String>,
        deny_list: Vec<String>,
        read_only: bool,
        guest_ok: bool,
    ) -> ShareConfig {
        ShareConfig {
            description: None,
            path: "/tmp/share".into(),
            enabled: true,
            browseable: true,
            read_only,
            read_list,
            write_list,
            admin_list,
            deny_list,
            guest_ok,
            max_connections: None,
            hide_dot_files: false,
            follow_symlinks: false,
            exclude_patterns: vec![],
            include_patterns: vec![],
            versioning: false,
            max_file_size: 0,
            file_locking: true,
            mount_point: None,
        }
    }

    fn create_user(username: &str, groups: Vec<&str>) -> User {
        User {
            username: username.to_string(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_guest_access_allowed() {
        let config = create_share_config(vec![], vec![], vec![], vec![], false, true);
        assert!(check_permission(None, &config, Permission::Read));
        assert!(!check_permission(None, &config, Permission::Write));
    }

    #[test]
    fn test_guest_access_denied() {
        let config = create_share_config(vec![], vec![], vec![], vec![], false, false);
        assert!(!check_permission(None, &config, Permission::Read));
    }

    #[test]
    fn test_deny_list_precedence() {
        let config = create_share_config(
            vec![],
            vec![],
            vec!["alice".to_string()],
            vec!["alice".to_string()],
            false,
            false,
        );
        let user = create_user("alice", vec![]);
        assert!(!check_permission(Some(&user), &config, Permission::Read));
    }

    #[test]
    fn test_admin_access() {
        let config = create_share_config(
            vec![],
            vec![],
            vec!["alice".to_string()],
            vec![],
            false,
            false,
        );
        let user = create_user("alice", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Read));
        assert!(check_permission(Some(&user), &config, Permission::Write));
        assert!(check_permission(Some(&user), &config, Permission::Admin));
    }

    #[test]
    fn test_write_access() {
        let config = create_share_config(
            vec![],
            vec!["alice".to_string()],
            vec![],
            vec![],
            false,
            false,
        );
        let user = create_user("alice", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Read));
        assert!(check_permission(Some(&user), &config, Permission::Write));
        assert!(!check_permission(Some(&user), &config, Permission::Admin));
    }

    #[test]
    fn test_read_access() {
        let config = create_share_config(
            vec!["alice".to_string()],
            vec![],
            vec![],
            vec![],
            false,
            false,
        );
        let user = create_user("alice", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Read));
        assert!(!check_permission(Some(&user), &config, Permission::Write));
    }

    #[test]
    fn test_group_access() {
        let config = create_share_config(
            vec!["@developers".to_string()],
            vec![],
            vec![],
            vec![],
            false,
            false,
        );
        let user = create_user("alice", vec!["developers"]);
        assert!(check_permission(Some(&user), &config, Permission::Read));
    }

    #[test]
    fn test_empty_lists_authenticated() {
        let config = create_share_config(vec![], vec![], vec![], vec![], false, false);
        let user = create_user("alice", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Read));
        assert!(check_permission(Some(&user), &config, Permission::Write));
        assert!(!check_permission(Some(&user), &config, Permission::Admin));
    }

    #[test]
    fn test_empty_lists_readonly() {
        let config = create_share_config(vec![], vec![], vec![], vec![], true, false);
        let user = create_user("alice", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Read));
        assert!(!check_permission(Some(&user), &config, Permission::Write));
    }

    #[test]
    fn test_no_access() {
        let config = create_share_config(
            vec!["bob".to_string()],
            vec![],
            vec![],
            vec![],
            false,
            false,
        );
        let user = create_user("alice", vec![]);
        assert!(!check_permission(Some(&user), &config, Permission::Read));
    }

    // ============================================================================
    // Edge case tests verifying documented policy decisions
    // ============================================================================

    #[test]
    fn test_write_list_overrides_read_only() {
        // Documented: explicit write_list membership supersedes the read_only default.
        // read_only only applies to the empty-list fallback path.
        let config = create_share_config(
            vec![],
            vec!["bob".to_string()],
            vec![],
            vec![],
            true, // read_only = true
            false,
        );
        let user = create_user("bob", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Write));
    }

    #[test]
    fn test_admin_overrides_read_only() {
        // Documented: admin_list membership grants full access regardless of read_only.
        let config = create_share_config(
            vec![],
            vec![],
            vec!["alice".to_string()],
            vec![],
            true, // read_only = true
            false,
        );
        let user = create_user("alice", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Write));
    }

    #[test]
    fn test_empty_lists_allow_all_authenticated() {
        // Documented: empty ACL lists = Samba-compatible open-share default.
        // Every authenticated user gets write access. Populate a list to restrict.
        let config = create_share_config(vec![], vec![], vec![], vec![], false, false);
        let user = create_user("any_user", vec![]);
        assert!(check_permission(Some(&user), &config, Permission::Write));
    }

    #[test]
    fn test_deny_list_only_allows_others_via_empty_fallback() {
        // Documented: deny_list is a blocklist; users not in it reach the empty-list
        // fallback and get default write access (since no other lists are populated).
        let config = create_share_config(
            vec![],
            vec![],
            vec![],
            vec!["bob".to_string()],
            false,
            false,
        );
        let alice = create_user("alice", vec![]);
        let bob = create_user("bob", vec![]);

        assert!(!check_permission(Some(&bob), &config, Permission::Read));
        assert!(check_permission(Some(&alice), &config, Permission::Write));
    }
}
