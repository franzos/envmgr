use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::types::GitContext;

/// Detect git context for the given directory.
///
/// Returns `Ok(Some(context))` when inside a git repo, `Ok(None)` when not,
/// and `Err` only on unexpected failures.
pub fn detect(dir: &Path) -> Result<Option<GitContext>> {
    let repo_root = match git_toplevel(dir) {
        Ok(root) => root,
        Err(_) => return Ok(None),
    };

    let branch = git_branch(dir)?;
    let commit = git_commit(dir)?;

    Ok(Some(GitContext {
        repo_root,
        branch,
        commit,
    }))
}

/// Get the absolute path of the repository root.
fn git_toplevel(dir: &Path) -> Result<PathBuf> {
    let output = run_git(dir, &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(output))
}

/// Get the current branch name.
fn git_branch(dir: &Path) -> Result<String> {
    run_git(dir, &["rev-parse", "--abbrev-ref", "HEAD"])
}

/// Get the current commit hash (full SHA).
fn git_commit(dir: &Path) -> Result<String> {
    run_git(dir, &["rev-parse", "HEAD"])
}

/// Compute the relative path of `dir` from the repo root.
pub fn relative_path(dir: &Path, repo_root: &Path) -> Result<PathBuf> {
    dir.strip_prefix(repo_root)
        .map(|p| p.to_path_buf())
        .map_err(|e| Error::Other(format!("failed to compute relative path: {e}")))
}

/// Read `user.signingkey` from git config (local + global).
pub fn signing_key(dir: &Path) -> Result<Option<String>> {
    match run_git(dir, &["config", "user.signingkey"]) {
        Ok(key) if key.is_empty() => Ok(None),
        Ok(key) => Ok(Some(key)),
        Err(_) => Ok(None),
    }
}

/// Run a git command in the given directory, returning trimmed stdout.
fn run_git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| Error::GitCommand(format!("failed to execute git: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::GitCommand(stderr.trim().to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Run a git command with isolated config (no global/system config leakage).
    fn run_git_isolated(dir: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .map_err(|e| Error::GitCommand(format!("failed to execute git: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::GitCommand(stderr.trim().to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim().to_string())
    }

    /// Read signing key using isolated config.
    fn signing_key_isolated(dir: &Path) -> Result<Option<String>> {
        match run_git_isolated(dir, &["config", "user.signingkey"]) {
            Ok(key) if key.is_empty() => Ok(None),
            Ok(key) => Ok(Some(key)),
            Err(_) => Ok(None),
        }
    }

    /// Create a temporary git repo with isolated config.
    fn make_temp_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        run_git_isolated(dir.path(), &["init"]).unwrap();
        run_git_isolated(dir.path(), &["config", "user.email", "test@test.com"]).unwrap();
        run_git_isolated(dir.path(), &["config", "user.name", "Test"]).unwrap();

        // Need at least one commit for HEAD to exist.
        let file = dir.path().join("README");
        fs::write(&file, "hello").unwrap();
        run_git_isolated(dir.path(), &["add", "README"]).unwrap();
        run_git_isolated(dir.path(), &["commit", "-m", "init"]).unwrap();

        dir
    }

    #[test]
    fn detect_git_repo() {
        let repo = make_temp_repo();
        let ctx = detect(repo.path()).unwrap().expect("should detect repo");
        assert_eq!(ctx.repo_root, repo.path().canonicalize().unwrap());
        assert!(!ctx.branch.is_empty());
        assert!(!ctx.commit.is_empty());
        assert_eq!(ctx.commit.len(), 40); // full SHA
    }

    #[test]
    fn detect_non_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = detect(dir.path()).unwrap();
        assert!(ctx.is_none());
    }

    #[test]
    fn detect_subdirectory() {
        let repo = make_temp_repo();
        let sub = repo.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let ctx = detect(&sub).unwrap().expect("should detect repo from subdir");
        assert_eq!(ctx.repo_root, repo.path().canonicalize().unwrap());
    }

    #[test]
    fn relative_path_within_repo() {
        let repo = make_temp_repo();
        let sub = repo.path().join("apps").join("frontend");
        fs::create_dir_all(&sub).unwrap();
        let root = repo.path().canonicalize().unwrap();
        let rel = relative_path(&root.join("apps").join("frontend"), &root).unwrap();
        assert_eq!(rel, PathBuf::from("apps/frontend"));
    }

    #[test]
    fn relative_path_root_is_empty() {
        let repo = make_temp_repo();
        let root = repo.path().canonicalize().unwrap();
        let rel = relative_path(&root, &root).unwrap();
        assert_eq!(rel, PathBuf::from(""));
    }

    #[test]
    fn signing_key_not_set() {
        let repo = make_temp_repo();
        let key = signing_key_isolated(repo.path()).unwrap();
        assert!(key.is_none());
    }

    #[test]
    fn signing_key_set() {
        let repo = make_temp_repo();
        run_git_isolated(repo.path(), &["config", "user.signingkey", "ABCD1234"]).unwrap();
        let key = signing_key_isolated(repo.path()).unwrap();
        assert_eq!(key, Some("ABCD1234".to_string()));
    }

    #[test]
    fn branch_name_correct() {
        let repo = make_temp_repo();
        let ctx = detect(repo.path()).unwrap().unwrap();
        // Default branch on git init is typically "master" or "main".
        assert!(
            ctx.branch == "master" || ctx.branch == "main",
            "unexpected branch: {}",
            ctx.branch
        );
    }

    #[test]
    fn branch_after_checkout() {
        let repo = make_temp_repo();
        run_git_isolated(repo.path(), &["checkout", "-b", "feature/test"]).unwrap();
        let ctx = detect(repo.path()).unwrap().unwrap();
        assert_eq!(ctx.branch, "feature/test");
    }
}
