//! SQL classification for database request policy and enforcement.
//!
//! Moved from `latchgate-core` to `latchgate-providers` as part of the
//! provider decoupling refactor.

use super::types::OperationClass;

/// Classify a SQL string into an `OperationClass`.
///
/// SECURITY: intentionally conservative. Unknown or ambiguous => `Unknown` (DENY).
pub fn classify_sql(sql: &str) -> OperationClass {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return OperationClass::Unknown;
    }

    if contains_multiple_statements(trimmed) {
        return OperationClass::MultiStatement;
    }

    let upper = trimmed.to_ascii_uppercase();
    let first_word = upper.split_whitespace().next().unwrap_or("");

    match first_word {
        "SELECT" | "WITH" | "TABLE" | "VALUES" => OperationClass::Select,
        "INSERT" => OperationClass::Insert,
        "UPDATE" => OperationClass::Update,
        "DELETE" => OperationClass::Delete,
        "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "RENAME" | "COMMENT" => OperationClass::Ddl,
        "GRANT" | "REVOKE" => OperationClass::GrantRevoke,
        "COPY" => OperationClass::CopyIo,
        "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" | "SET" | "RESET" | "LOCK"
        | "UNLOCK" => OperationClass::TransactionControl,
        _ => OperationClass::Unknown,
    }
}

/// Check if SQL contains multiple statements (conservative).
fn contains_multiple_statements(sql: &str) -> bool {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = '\0';
    let mut chars = sql.chars().peekable();
    let mut found_semi = false;

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double_quote => {
                if in_single_quote && prev_char != '\'' {
                    in_single_quote = false;
                } else if !in_single_quote {
                    in_single_quote = true;
                }
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            '-' if !in_single_quote && !in_double_quote => {
                if chars.peek() == Some(&'-') {
                    for c2 in chars.by_ref() {
                        if c2 == '\n' {
                            break;
                        }
                    }
                    continue;
                }
            }
            ';' if !in_single_quote && !in_double_quote => {
                found_semi = true;
            }
            _ if found_semi && !c.is_whitespace() => {
                return true;
            }
            _ => {}
        }
        prev_char = c;
    }
    false
}

/// Extract table names from SQL (best-effort, conservative).
pub fn extract_tables(sql: &str) -> Vec<String> {
    let upper = sql.to_ascii_uppercase();
    let tokens: Vec<&str> = upper.split_whitespace().collect();
    let original_tokens: Vec<&str> = sql.split_whitespace().collect();
    let mut tables = Vec::new();

    let table_keywords = ["FROM", "JOIN", "INTO", "UPDATE", "TABLE"];

    for (i, token) in tokens.iter().enumerate() {
        let clean = token.trim_end_matches(',');
        if table_keywords.contains(&clean) {
            if let Some(next) = original_tokens.get(i + 1) {
                let table = next
                    .trim_end_matches(',')
                    .trim_end_matches('(')
                    .trim_matches('"');
                if !table.starts_with('(') && !table.is_empty() {
                    let clean_table = table.split('.').next_back().unwrap_or(table);
                    if !clean_table.to_ascii_uppercase().starts_with("SELECT")
                        && !clean_table.to_ascii_uppercase().starts_with("(")
                    {
                        tables.push(clean_table.to_lowercase());
                    }
                }
            }
        }
    }

    tables.sort();
    tables.dedup();
    tables
}

/// Count positional parameter placeholders (`$1`, `$2`, …) in SQL.
///
/// Returns the highest `$N` index found, which equals the parameter count
/// for well-formed statements. Not a full SQL parser — sufficient for the
/// conservative statement SQL that passes `DatabaseConfig::validate()`.
pub fn count_sql_params(sql: &str) -> usize {
    let mut max_param: usize = 0;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let mut n: usize = 0;
            let mut found_digit = false;
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    found_digit = true;
                    n = n
                        .saturating_mul(10)
                        .saturating_add((d as u8 - b'0') as usize);
                    chars.next();
                } else {
                    break;
                }
            }
            if found_digit {
                max_param = max_param.max(n);
            }
        }
    }
    max_param
}

/// Check whether a SQL statement contains a WHERE clause.
pub(crate) fn has_where_clause(sql: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    upper.split_whitespace().any(|w| w == "WHERE")
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_select() {
        assert_eq!(
            classify_sql("SELECT * FROM orders WHERE id = $1"),
            OperationClass::Select
        );
    }

    #[test]
    fn classify_select_with_cte() {
        assert_eq!(
            classify_sql("WITH cte AS (SELECT 1) SELECT * FROM cte"),
            OperationClass::Select
        );
    }

    #[test]
    fn classify_insert() {
        assert_eq!(
            classify_sql("INSERT INTO orders (id, status) VALUES ($1, $2)"),
            OperationClass::Insert
        );
    }

    #[test]
    fn classify_update() {
        assert_eq!(
            classify_sql("UPDATE orders SET status = $1 WHERE id = $2"),
            OperationClass::Update
        );
    }

    #[test]
    fn classify_delete() {
        assert_eq!(
            classify_sql("DELETE FROM orders WHERE id = $1"),
            OperationClass::Delete
        );
    }

    #[test]
    fn classify_ddl_create() {
        assert_eq!(
            classify_sql("CREATE TABLE evil (id int)"),
            OperationClass::Ddl
        );
    }

    #[test]
    fn classify_ddl_drop() {
        assert_eq!(classify_sql("DROP TABLE orders"), OperationClass::Ddl);
    }

    #[test]
    fn classify_multi_statement() {
        assert_eq!(
            classify_sql("SELECT 1; DROP TABLE orders"),
            OperationClass::MultiStatement
        );
    }

    #[test]
    fn classify_semicolon_in_string_is_not_multi() {
        assert_eq!(
            classify_sql("SELECT * FROM orders WHERE name = 'foo;bar'"),
            OperationClass::Select
        );
    }

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(classify_sql(""), OperationClass::Unknown);
        assert_eq!(classify_sql("  "), OperationClass::Unknown);
    }

    #[test]
    fn classify_case_insensitive() {
        assert_eq!(classify_sql("select * from orders"), OperationClass::Select);
    }

    #[test]
    fn classify_grant() {
        assert_eq!(
            classify_sql("GRANT SELECT ON orders TO attacker"),
            OperationClass::GrantRevoke
        );
    }

    #[test]
    fn classify_copy() {
        assert_eq!(
            classify_sql("COPY orders TO '/tmp/exfil.csv'"),
            OperationClass::CopyIo
        );
    }

    #[test]
    fn classify_transaction_control() {
        assert_eq!(classify_sql("BEGIN"), OperationClass::TransactionControl);
        assert_eq!(classify_sql("COMMIT"), OperationClass::TransactionControl);
        assert_eq!(
            classify_sql("SET search_path TO public"),
            OperationClass::TransactionControl
        );
    }

    #[test]
    fn classify_unknown_keyword() {
        assert_eq!(classify_sql("EXECUTE something"), OperationClass::Unknown);
    }

    #[test]
    fn line_comment_before_keyword_classified_as_unknown() {
        assert_eq!(
            classify_sql("-- this is a comment\nSELECT * FROM orders"),
            OperationClass::Unknown
        );
    }

    #[test]
    fn semicolon_inside_double_quoted_identifier_is_not_multi() {
        assert_eq!(
            classify_sql("SELECT * FROM \"table;name\" WHERE id = $1"),
            OperationClass::Select
        );
    }

    #[test]
    fn empty_statement_after_semicolon_is_not_multi() {
        assert_eq!(
            classify_sql("SELECT * FROM orders;   "),
            OperationClass::Select
        );
    }

    #[test]
    fn do_block_classified_as_multi_statement() {
        assert_eq!(
            classify_sql("DO $$ BEGIN RAISE NOTICE 'hi'; END $$"),
            OperationClass::MultiStatement
        );
    }

    #[test]
    fn values_keyword_classified_as_select() {
        assert_eq!(
            classify_sql("VALUES (1, 'a'), (2, 'b')"),
            OperationClass::Select
        );
    }

    // -- extract_tables --

    #[test]
    fn extract_tables_from_select() {
        let tables = extract_tables("SELECT * FROM orders WHERE id = $1");
        assert_eq!(tables, vec!["orders"]);
    }

    #[test]
    fn extract_tables_from_join() {
        let tables =
            extract_tables("SELECT o.id FROM orders o JOIN customers c ON o.cust_id = c.id");
        assert!(tables.contains(&"orders".to_string()));
        assert!(tables.contains(&"customers".to_string()));
    }

    #[test]
    fn extract_tables_deduplicates() {
        let tables =
            extract_tables("SELECT * FROM orders o1 JOIN orders o2 ON o1.id = o2.parent_id");
        assert_eq!(tables.iter().filter(|t| *t == "orders").count(), 1);
    }

    #[test]
    fn extract_tables_from_schema_qualified_name() {
        let tables = extract_tables("SELECT * FROM public.orders WHERE id = $1");
        assert!(tables.contains(&"orders".to_string()));
    }

    // -- has_where_clause --

    #[test]
    fn has_where_detects_where() {
        assert!(has_where_clause(
            "UPDATE orders SET status = $1 WHERE id = $2"
        ));
        assert!(!has_where_clause("DELETE FROM orders"));
    }

    // -- count_sql_params --

    #[test]
    fn count_params_simple() {
        assert_eq!(count_sql_params("SELECT * FROM t WHERE id = $1"), 1);
    }

    #[test]
    fn count_params_multiple() {
        assert_eq!(
            count_sql_params("UPDATE t SET a = $1, b = $2 WHERE id = $3"),
            3
        );
    }

    #[test]
    fn count_params_none() {
        assert_eq!(count_sql_params("SELECT 1"), 0);
    }

    #[test]
    fn count_params_non_sequential() {
        assert_eq!(count_sql_params("INSERT INTO t (a, b) VALUES ($1, $5)"), 5);
    }

    #[test]
    fn count_params_dollar_no_digit() {
        assert_eq!(count_sql_params("SELECT $name FROM t"), 0);
    }
}
