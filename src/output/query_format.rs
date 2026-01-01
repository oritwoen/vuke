//! Query result formatters for CLI output.

use std::sync::Arc;

use arrow::datatypes::Schema;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};

use crate::storage::{Row, Value};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!(
                "Unknown format '{}'. Valid formats: table, json, csv",
                s
            )),
        }
    }
}

pub fn format_table(rows: &[Row], schema: Option<Arc<Schema>>) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    let column_names: Vec<String> = if let Some(ref schema) = schema {
        schema.fields().iter().map(|f| f.name().clone()).collect()
    } else {
        rows[0]
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    table.set_header(
        column_names
            .iter()
            .map(|name| Cell::new(name).fg(Color::Cyan)),
    );

    for row in rows {
        let cells: Vec<Cell> = column_names
            .iter()
            .map(|name| {
                let value = row.get(name);
                format_value_cell(value)
            })
            .collect();
        table.add_row(cells);
    }

    table.to_string()
}

fn format_value_cell(value: Option<&Value>) -> Cell {
    match value {
        None | Some(Value::Null) => Cell::new("NULL").fg(Color::DarkGrey),
        Some(Value::String(s)) => {
            let display = if s.chars().count() > 40 {
                format!("{}...", s.chars().take(37).collect::<String>())
            } else {
                s.clone()
            };
            Cell::new(display)
        }
        Some(Value::Int64(n)) => Cell::new(n).fg(Color::Yellow),
        Some(Value::UInt64(n)) => Cell::new(n).fg(Color::Yellow),
        Some(Value::Float64(n)) => Cell::new(format!("{:.6}", n)).fg(Color::Yellow),
        Some(Value::Binary(b)) => {
            let hex = hex::encode(b);
            let display = if hex.len() > 40 {
                format!("{}...", &hex[..37])
            } else {
                hex
            };
            Cell::new(display).fg(Color::Magenta)
        }
        Some(Value::Timestamp(ts)) => {
            let datetime = chrono::DateTime::from_timestamp_millis(*ts)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| ts.to_string());
            Cell::new(datetime).fg(Color::Green)
        }
    }
}

pub fn format_json(rows: &[Row]) -> String {
    if rows.is_empty() {
        return "[]".to_string();
    }

    let mut json_rows: Vec<String> = Vec::with_capacity(rows.len());

    for row in rows {
        let fields: Vec<String> = row
            .columns()
            .iter()
            .map(|(name, value)| {
                let json_value = format_value_json(value);
                format!("\"{}\":{}", escape_json_string(name), json_value)
            })
            .collect();

        json_rows.push(format!("{{{}}}", fields.join(",")));
    }

    format!("[\n  {}\n]", json_rows.join(",\n  "))
}

fn format_value_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::String(s) => format!("\"{}\"", escape_json_string(s)),
        Value::Int64(n) => n.to_string(),
        Value::UInt64(n) => n.to_string(),
        Value::Float64(n) => {
            if n.is_finite() {
                format!("{}", n)
            } else {
                "null".to_string()
            }
        }
        Value::Binary(b) => format!("\"{}\"", hex::encode(b)),
        Value::Timestamp(ts) => chrono::DateTime::from_timestamp_millis(*ts)
            .map(|dt| format!("\"{}\"", dt.to_rfc3339()))
            .unwrap_or_else(|| ts.to_string()),
    }
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// RFC 4180 compliant CSV formatting.
pub fn format_csv(rows: &[Row], schema: Option<Arc<Schema>>) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let mut output = String::new();

    let column_names: Vec<String> = if let Some(ref schema) = schema {
        schema.fields().iter().map(|f| f.name().clone()).collect()
    } else {
        rows[0]
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    let header: Vec<String> = column_names.iter().map(|n| escape_csv_field(n)).collect();
    output.push_str(&header.join(","));
    output.push('\n');

    for row in rows {
        let fields: Vec<String> = column_names
            .iter()
            .map(|name| {
                let value = row.get(name);
                let formatted = format_value_csv(value);
                escape_csv_field(&formatted)
            })
            .collect();
        output.push_str(&fields.join(","));
        output.push('\n');
    }

    output
}

fn format_value_csv(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Int64(n)) => n.to_string(),
        Some(Value::UInt64(n)) => n.to_string(),
        Some(Value::Float64(n)) => format!("{}", n),
        Some(Value::Binary(b)) => hex::encode(b),
        Some(Value::Timestamp(ts)) => chrono::DateTime::from_timestamp_millis(*ts)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| ts.to_string()),
    }
}

fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

pub fn format_schema(schema: &Schema) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Column").fg(Color::Cyan),
        Cell::new("Type").fg(Color::Cyan),
        Cell::new("Nullable").fg(Color::Cyan),
    ]);

    for field in schema.fields() {
        let nullable = if field.is_nullable() {
            Cell::new("Yes").fg(Color::Yellow)
        } else {
            Cell::new("No").fg(Color::Green)
        };

        table.add_row(vec![
            Cell::new(field.name()),
            Cell::new(format!("{:?}", field.data_type())).fg(Color::Magenta),
            nullable,
        ]);
    }

    format!(
        "Schema: results ({} columns)\n{}",
        schema.fields().len(),
        table
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_row(source: &str, count: i64) -> Row {
        Row::from_columns(vec![
            ("source".to_string(), Value::String(source.to_string())),
            ("count".to_string(), Value::Int64(count)),
        ])
    }

    #[test]
    fn output_format_from_str() {
        assert_eq!(
            OutputFormat::from_str("table").unwrap(),
            OutputFormat::Table
        );
        assert_eq!(
            OutputFormat::from_str("TABLE").unwrap(),
            OutputFormat::Table
        );
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("JSON").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("csv").unwrap(), OutputFormat::Csv);
        assert_eq!(OutputFormat::from_str("CSV").unwrap(), OutputFormat::Csv);
        assert!(OutputFormat::from_str("xml").is_err());
    }

    #[test]
    fn format_json_empty() {
        assert_eq!(format_json(&[]), "[]");
    }

    #[test]
    fn format_json_single_row() {
        let row = make_test_row("test", 42);
        let json = format_json(&[row]);
        assert!(json.contains("\"source\":\"test\""));
        assert!(json.contains("\"count\":42"));
    }

    #[test]
    fn format_json_escapes_strings() {
        let row = Row::from_columns(vec![(
            "text".to_string(),
            Value::String("hello\n\"world\"".to_string()),
        )]);
        let json = format_json(&[row]);
        assert!(json.contains("\\n"));
        assert!(json.contains("\\\""));
    }

    #[test]
    fn format_csv_empty() {
        assert_eq!(format_csv(&[], None), "");
    }

    #[test]
    fn format_csv_with_data() {
        let row = make_test_row("test", 42);
        let csv = format_csv(&[row], None);
        assert!(csv.starts_with("source,count\n"));
        assert!(csv.contains("test,42"));
    }

    #[test]
    fn format_csv_escapes_commas() {
        let row = Row::from_columns(vec![(
            "text".to_string(),
            Value::String("hello, world".to_string()),
        )]);
        let csv = format_csv(&[row], None);
        assert!(csv.contains("\"hello, world\""));
    }

    #[test]
    fn format_csv_escapes_quotes() {
        let row = Row::from_columns(vec![(
            "text".to_string(),
            Value::String("say \"hello\"".to_string()),
        )]);
        let csv = format_csv(&[row], None);
        assert!(csv.contains("\"say \"\"hello\"\"\""));
    }

    #[test]
    fn format_table_empty() {
        assert_eq!(format_table(&[], None), "");
    }

    #[test]
    fn format_table_with_data() {
        let row = make_test_row("test", 42);
        let table = format_table(&[row], None);
        assert!(table.contains("source"));
        assert!(table.contains("count"));
        assert!(table.contains("test"));
        assert!(table.contains("42"));
    }

    #[test]
    fn escape_json_string_special_chars() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("\""), "\\\"");
        assert_eq!(escape_json_string("\\"), "\\\\");
        assert_eq!(escape_json_string("\n"), "\\n");
        assert_eq!(escape_json_string("\t"), "\\t");
    }

    #[test]
    fn escape_csv_field_no_special() {
        assert_eq!(escape_csv_field("hello"), "hello");
    }

    #[test]
    fn escape_csv_field_with_comma() {
        assert_eq!(escape_csv_field("a,b"), "\"a,b\"");
    }

    #[test]
    fn escape_csv_field_with_quote() {
        assert_eq!(escape_csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn format_value_json_types() {
        assert_eq!(format_value_json(&Value::Null), "null");
        assert_eq!(format_value_json(&Value::Int64(42)), "42");
        assert_eq!(format_value_json(&Value::UInt64(100)), "100");
        assert_eq!(
            format_value_json(&Value::String("test".to_string())),
            "\"test\""
        );
        assert_eq!(
            format_value_json(&Value::Binary(vec![0xde, 0xad])),
            "\"dead\""
        );
    }

    #[test]
    fn format_table_utf8_truncation() {
        let long_emoji = "🔑".repeat(50);
        let row = Row::from_columns(vec![("key".to_string(), Value::String(long_emoji))]);
        let result = format_table(&[row], None);
        assert!(result.contains("🔑"));
        assert!(result.contains("..."));
    }
}
