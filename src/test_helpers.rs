use crate::types::EnvEntry;

/// Standard test entries used across test modules.
pub fn sample_entries() -> Vec<EnvEntry> {
    vec![
        EnvEntry {
            comment: Some("Host config".to_string()),
            key: "DB_HOST".to_string(),
            value: "localhost".to_string(),
        },
        EnvEntry {
            comment: None,
            key: "DB_PORT".to_string(),
            value: "5432".to_string(),
        },
    ]
}

/// Open an in-memory SQLite store for testing.
pub fn test_conn() -> rusqlite::Connection {
    crate::store::open_memory().unwrap()
}
