use std::path::Path;

use crate::cli::{self, output};
use crate::error::Result;

/// Run the `diff` command: compare two saved versions.
pub fn run(
    cwd: &Path,
    a: &str,
    b: &str,
    full: bool,
    output_format: &str,
    key_file: Option<&str>,
) -> Result<()> {
    let conn = cli::require_store()?;
    let aes_key = cli::load_encryption_key(&conn, key_file)?;
    let (project_path, git_ctx) = cli::resolve_project(cwd)?;
    let current_branch = git_ctx.as_ref().map(|c| c.branch.as_str());

    let save_a = cli::resolve_version(&conn, &project_path, current_branch, a)?;
    let save_b = cli::resolve_version(&conn, &project_path, current_branch, b)?;

    let entries_a = cli::load_entries(&conn, &save_a, aes_key.as_ref())?;
    let entries_b = cli::load_entries(&conn, &save_b, aes_key.as_ref())?;

    let result = crate::diff::diff(&entries_a, &entries_b);

    if output_format == "json" {
        println!("{}", output::format_diff_json(&result, full)?);
    } else {
        print!("{}", output::format_diff_text(&result, full));
    }

    Ok(())
}
