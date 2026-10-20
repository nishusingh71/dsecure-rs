//! `TABLE_CLASSES` ko `crates/db/src/table_classes.rs` ke SOURCE TEXT se padhta hai (db crate ke types par
//! compile-time dependency nahi: db mid-edit ho tab bhi sql/schema gates chalte hain).

use anyhow::{Result, bail};
use regex::Regex;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Tenant,
    Identity,
    Directory,
    Platform,
    Infra,
}

impl Class {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tenant" => Some(Self::Tenant),
            "identity" => Some(Self::Identity),
            "directory" => Some(Self::Directory),
            "platform" => Some(Self::Platform),
            "infra" => Some(Self::Infra),
            _ => None,
        }
    }
}

/// table name -> class. Fails when the const block cannot be found or is empty.
pub fn parse_table_classes(src: &str) -> Result<HashMap<String, Class>> {
    let Some(start) = src.find("pub const TABLE_CLASSES") else {
        bail!("`pub const TABLE_CLASSES` not found in table_classes.rs");
    };
    let rest = &src[start..];
    let end = rest.find("\n];").unwrap_or(rest.len());
    let block = &rest[..end];
    let re = Regex::new(r#"\(\s*"([a-z0-9_]+)"\s*,\s*TableClass::(\w+)\s*\)"#)?;
    let mut map = HashMap::new();
    for cap in re.captures_iter(block) {
        let class = match &cap[2] {
            "Tenant" => Class::Tenant,
            "Identity" => Class::Identity,
            "Directory" => Class::Directory,
            "Platform" => Class::Platform,
            "Infra" => Class::Infra,
            other => bail!("unknown TableClass::{other} in table_classes.rs"),
        };
        map.insert(cap[1].to_owned(), class);
    }
    if map.is_empty() {
        bail!("TABLE_CLASSES block has no entries");
    }
    Ok(map)
}

/// Tooling tables the schema check ignores (`TOOLING_TABLES` in table_classes.rs).
pub fn parse_tooling_tables(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub const TOOLING_TABLES") else {
        return vec!["_sqlx_migrations".into(), "_sqlx_migrations_shadow".into()];
    };
    let rest = &src[start..];
    let end = rest.find("];").unwrap_or(rest.len());
    let Ok(re) = Regex::new(r#""([A-Za-z0-9_]+)""#) else {
        return Vec::new();
    };
    re.captures_iter(&rest[..end])
        .map(|c| c[1].to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"
pub const TABLE_CLASSES: &[(&str, TableClass)] = &[
    ("tenants", TableClass::Platform),
    ("groups", TableClass::Tenant),
];
pub const TOOLING_TABLES: &[&str] = &["_sqlx_migrations", "_migration_lock"];
"#;

    #[test]
    fn parses_registry_and_tooling() {
        let m = parse_table_classes(SRC).unwrap();
        assert_eq!(m.get("groups"), Some(&Class::Tenant));
        assert_eq!(m.get("tenants"), Some(&Class::Platform));
        assert_eq!(
            parse_tooling_tables(SRC),
            vec!["_sqlx_migrations", "_migration_lock"]
        );
    }

    #[test]
    fn missing_block_is_an_error() {
        assert!(parse_table_classes("fn x() {}").is_err());
    }
}
