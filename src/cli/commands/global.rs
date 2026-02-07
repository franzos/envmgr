use crate::cli;
use crate::error::Result;
use crate::store::queries;

/// Run the `global` command: list all projects with save counts.
pub fn run() -> Result<()> {
    let conn = cli::require_store()?;
    let projects = queries::list_projects(&conn)?;

    if projects.is_empty() {
        println!("No projects found.");
        return Ok(());
    }

    for project in &projects {
        let label = if project.save_count == 1 {
            "save,"
        } else {
            "saves,"
        };
        println!(
            "{:<50} {} {:<7} last: {}",
            project.project_path, project.save_count, label, project.last_save
        );
    }

    Ok(())
}
