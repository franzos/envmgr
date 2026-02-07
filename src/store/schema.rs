use rusqlite::Connection;
use rusqlite_migration::{M, Migrations};

use crate::error::{Error, Result};

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(
        "
        CREATE TABLE config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE saves (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            project_path TEXT    NOT NULL,
            file_path    TEXT    NOT NULL,
            branch       TEXT    NOT NULL DEFAULT '',
            commit_hash  TEXT    NOT NULL DEFAULT '',
            timestamp    TEXT    NOT NULL,
            content_hash TEXT    NOT NULL,
            hmac         TEXT    NOT NULL DEFAULT '',
            message      TEXT    NOT NULL DEFAULT ''
        );

        CREATE INDEX idx_saves_project_branch
            ON saves(project_path, branch);

        CREATE INDEX idx_saves_content_hash
            ON saves(content_hash);

        CREATE TABLE entries (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            save_id  INTEGER NOT NULL REFERENCES saves(id) ON DELETE CASCADE,
            key      TEXT    NOT NULL,
            value    BLOB    NOT NULL,
            comment  BLOB    NOT NULL DEFAULT ''
        );

        CREATE INDEX idx_entries_save_id
            ON entries(save_id);
        ",
    )])
}

/// Run all pending migrations on the connection.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    migrations()
        .to_latest(conn)
        .map_err(|e| Error::Migration(e.to_string()))
}
