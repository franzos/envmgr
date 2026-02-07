use std::collections::HashMap;

use crate::types::{DiffResult, EnvEntry};

/// Compare two sets of env entries by variable name (order-independent).
pub fn diff(old: &[EnvEntry], new: &[EnvEntry]) -> DiffResult {
    let old_map: HashMap<&str, &EnvEntry> = old.iter().map(|e| (e.key.as_str(), e)).collect();
    let new_map: HashMap<&str, &EnvEntry> = new.iter().map(|e| (e.key.as_str(), e)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();

    // Find removed and changed/unchanged.
    for entry in old {
        match new_map.get(entry.key.as_str()) {
            None => removed.push(entry.clone()),
            Some(new_entry) => {
                if entry == *new_entry {
                    unchanged.push(entry.clone());
                } else {
                    changed.push((entry.clone(), (*new_entry).clone()));
                }
            }
        }
    }

    // Find added (in new but not in old).
    for entry in new {
        if !old_map.contains_key(entry.key.as_str()) {
            added.push(entry.clone());
        }
    }

    DiffResult {
        added,
        removed,
        changed,
        unchanged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, value: &str, comment: Option<&str>) -> EnvEntry {
        EnvEntry {
            key: key.to_string(),
            value: value.to_string(),
            comment: comment.map(String::from),
        }
    }

    #[test]
    fn identical_sets() {
        let a = vec![entry("A", "1", None), entry("B", "2", None)];
        let b = vec![entry("A", "1", None), entry("B", "2", None)];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
        assert_eq!(result.unchanged.len(), 2);
    }

    #[test]
    fn completely_different() {
        let a = vec![entry("A", "1", None)];
        let b = vec![entry("B", "2", None)];
        let result = diff(&a, &b);
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].key, "B");
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].key, "A");
        assert!(result.changed.is_empty());
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn additions_only() {
        let a = vec![entry("A", "1", None)];
        let b = vec![entry("A", "1", None), entry("B", "2", None)];
        let result = diff(&a, &b);
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].key, "B");
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn removals_only() {
        let a = vec![entry("A", "1", None), entry("B", "2", None)];
        let b = vec![entry("A", "1", None)];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].key, "B");
        assert!(result.changed.is_empty());
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn value_change() {
        let a = vec![entry("A", "old", None)];
        let b = vec![entry("A", "new", None)];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert_eq!(result.changed.len(), 1);
        assert_eq!(result.changed[0].0.value, "old");
        assert_eq!(result.changed[0].1.value, "new");
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn comment_only_change() {
        let a = vec![entry("A", "1", Some("old comment"))];
        let b = vec![entry("A", "1", Some("new comment"))];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert_eq!(result.changed.len(), 1);
        assert_eq!(result.changed[0].0.comment, Some("old comment".to_string()));
        assert_eq!(result.changed[0].1.comment, Some("new comment".to_string()));
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn reordered_but_identical() {
        let a = vec![entry("B", "2", None), entry("A", "1", None)];
        let b = vec![entry("A", "1", None), entry("B", "2", None)];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
        assert_eq!(result.unchanged.len(), 2);
    }

    #[test]
    fn empty_old() {
        let a: Vec<EnvEntry> = vec![];
        let b = vec![entry("A", "1", None)];
        let result = diff(&a, &b);
        assert_eq!(result.added.len(), 1);
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn empty_new() {
        let a = vec![entry("A", "1", None)];
        let b: Vec<EnvEntry> = vec![];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert_eq!(result.removed.len(), 1);
        assert!(result.changed.is_empty());
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn both_empty() {
        let a: Vec<EnvEntry> = vec![];
        let b: Vec<EnvEntry> = vec![];
        let result = diff(&a, &b);
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn mixed_changes() {
        let a = vec![
            entry("KEEP", "same", None),
            entry("REMOVE", "gone", None),
            entry("CHANGE", "old", Some("old comment")),
        ];
        let b = vec![
            entry("KEEP", "same", None),
            entry("ADD", "new", None),
            entry("CHANGE", "new", Some("new comment")),
        ];
        let result = diff(&a, &b);
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].key, "ADD");
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].key, "REMOVE");
        assert_eq!(result.changed.len(), 1);
        assert_eq!(result.changed[0].0.key, "CHANGE");
        assert_eq!(result.unchanged.len(), 1);
        assert_eq!(result.unchanged[0].key, "KEEP");
    }

    #[test]
    fn comment_added_to_existing() {
        let a = vec![entry("A", "1", None)];
        let b = vec![entry("A", "1", Some("now with comment"))];
        let result = diff(&a, &b);
        assert_eq!(result.changed.len(), 1);
        assert!(result.unchanged.is_empty());
    }

    #[test]
    fn comment_removed_from_existing() {
        let a = vec![entry("A", "1", Some("had comment"))];
        let b = vec![entry("A", "1", None)];
        let result = diff(&a, &b);
        assert_eq!(result.changed.len(), 1);
        assert!(result.unchanged.is_empty());
    }
}
