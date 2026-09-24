use super::{CompareOp, ExistenceCheck, Filter, FilterExpr, LogicalOp, StringOp, Value};
use crate::error::{GhidraError, Result};
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "filter.pest"]
struct FilterParser;

pub fn parse_filter(input: &str) -> Result<Filter> {
    let pairs = FilterParser::parse(Rule::expr, input)
        .map_err(|e| GhidraError::FilterParseError(format!("{}", e)))?;

    let mut expr = None;
    for pair in pairs {
        if pair.as_rule() == Rule::expr {
            for inner in pair.into_inner() {
                if inner.as_rule() == Rule::logical_expr {
                    expr = Some(parse_logical_expr(inner)?);
                }
            }
        }
    }

    expr.map(|e| Filter { expr: e })
        .ok_or_else(|| GhidraError::FilterParseError("Empty expression".to_string()))
}

// The grammar groups AND terms inside OR terms; parentheses recurse here.
fn parse_logical_expr(pair: pest::iterators::Pair<Rule>) -> Result<FilterExpr> {
    let exprs = pair
        .into_inner()
        .map(|group| {
            let terms = group
                .into_inner()
                .map(parse_logical_term)
                .collect::<Result<Vec<_>>>()?;
            logical_group(LogicalOp::And, terms)
        })
        .collect::<Result<Vec<_>>>()?;
    logical_group(LogicalOp::Or, exprs)
}

fn logical_group(op: LogicalOp, mut exprs: Vec<FilterExpr>) -> Result<FilterExpr> {
    match exprs.len() {
        0 => Err(GhidraError::FilterParseError(
            "No terms in logical expression".to_string(),
        )),
        1 => Ok(exprs.pop().unwrap()),
        _ => Ok(FilterExpr::Logical { op, exprs }),
    }
}

fn parse_logical_term(pair: pest::iterators::Pair<Rule>) -> Result<FilterExpr> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::logical_not => {
                return parse_logical_not(inner);
            }
            Rule::logical_expr => {
                return parse_logical_expr(inner);
            }
            Rule::comparison => {
                return parse_comparison(inner);
            }
            _ => {}
        }
    }
    Err(GhidraError::FilterParseError(
        "Invalid logical term".to_string(),
    ))
}

fn parse_logical_not(pair: pest::iterators::Pair<Rule>) -> Result<FilterExpr> {
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::logical_term {
            let term = parse_logical_term(inner)?;
            return Ok(FilterExpr::Not(Box::new(term)));
        }
    }
    Err(GhidraError::FilterParseError(
        "Invalid NOT expression".to_string(),
    ))
}

fn parse_comparison(pair: pest::iterators::Pair<Rule>) -> Result<FilterExpr> {
    let mut field = None;
    let mut op = None;
    let mut value = None;
    let mut string_op = None;
    let mut existence = None;
    let mut in_values = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::field => {
                field = Some(inner.as_str().to_string());
            }
            Rule::compare_op => {
                let op_str = inner.as_str();
                op = Some(match op_str {
                    "=" => CompareOp::Equal,
                    "!=" => CompareOp::NotEqual,
                    ">" => CompareOp::Greater,
                    ">=" => CompareOp::GreaterEqual,
                    "<" => CompareOp::Less,
                    "<=" => CompareOp::LessEqual,
                    _ => {
                        return Err(GhidraError::FilterParseError(format!(
                            "Unknown compare op: {}",
                            op_str
                        )))
                    }
                });
            }
            Rule::string_op => {
                let op_str = inner.as_str();
                string_op = Some(match op_str {
                    "~" => StringOp::Contains,
                    "^" => StringOp::StartsWith,
                    "$" => StringOp::EndsWith,
                    "=~" => StringOp::Regex,
                    _ => {
                        return Err(GhidraError::FilterParseError(format!(
                            "Unknown string op: {}",
                            op_str
                        )))
                    }
                });
            }
            Rule::value => {
                value = Some(parse_value(inner)?);
            }
            Rule::string_value => {
                value = Some(parse_value(inner)?);
            }
            Rule::existence_check => {
                let check_str = inner.as_str();
                existence = Some(match check_str {
                    "EXISTS" => ExistenceCheck::Exists,
                    "EMPTY" => ExistenceCheck::Empty,
                    "NULL" => ExistenceCheck::Null,
                    _ => {
                        return Err(GhidraError::FilterParseError(format!(
                            "Unknown existence check: {}",
                            check_str
                        )))
                    }
                });
            }
            Rule::value_list => {
                let mut values = Vec::new();
                for val_pair in inner.into_inner() {
                    if val_pair.as_rule() == Rule::value {
                        values.push(parse_value(val_pair)?);
                    }
                }
                in_values = Some(values);
            }
            _ => {}
        }
    }

    let field = field.ok_or_else(|| GhidraError::FilterParseError("Missing field".to_string()))?;

    if let Some(existence_check) = existence {
        return Ok(FilterExpr::Exists {
            field,
            check: existence_check,
        });
    }

    if let Some(values) = in_values {
        for value in &values {
            validate_address_literal(&field, value)?;
        }
        return Ok(FilterExpr::In { field, values });
    }

    if let Some(str_op) = string_op {
        let val =
            value.ok_or_else(|| GhidraError::FilterParseError("Missing value".to_string()))?;
        let val_str = match val {
            Value::String(s) => s,
            _ => {
                return Err(GhidraError::FilterParseError(
                    "String operation requires string value".to_string(),
                ))
            }
        };
        if str_op == StringOp::Regex {
            super::evaluator::validate_regex(&val_str)?;
        }
        return Ok(FilterExpr::StringOp {
            field,
            op: str_op,
            value: val_str,
        });
    }

    if let Some(cmp_op) = op {
        let val =
            value.ok_or_else(|| GhidraError::FilterParseError("Missing value".to_string()))?;
        validate_address_literal(&field, &val)?;
        return Ok(FilterExpr::Compare {
            field,
            op: cmp_op,
            value: val,
        });
    }

    Err(GhidraError::FilterParseError(
        "Invalid comparison".to_string(),
    ))
}

fn validate_address_literal(field: &str, value: &Value) -> Result<()> {
    if !super::evaluator::is_address_field(field) {
        return Ok(());
    }
    let valid = match value {
        Value::Hex(_) => true,
        Value::String(address) => crate::address::ExplicitAddress::parse(address).is_some(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(GhidraError::FilterParseError(format!(
            "Invalid address literal {value:?} for field '{field}': use a 0x-prefixed hexadecimal literal or an explicit address string"
        )))
    }
}

fn parse_value(pair: pest::iterators::Pair<Rule>) -> Result<Value> {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::number => {
                let num_str = inner.as_str();
                if num_str.contains('.') {
                    let num = num_str.parse::<f64>().map_err(|_| {
                        GhidraError::FilterParseError(format!("Invalid number: {}", num_str))
                    })?;
                    return Ok(Value::Number(num));
                } else {
                    let num = num_str.parse::<i64>().map_err(|_| {
                        GhidraError::FilterParseError(format!("Invalid integer: {}", num_str))
                    })?;
                    return Ok(Value::Integer(num));
                }
            }
            Rule::hex_number => {
                let hex_str = &inner.as_str()[2..];
                let num = u64::from_str_radix(hex_str, 16).map_err(|_| {
                    GhidraError::FilterParseError(format!("Invalid hex number: {}", inner.as_str()))
                })?;
                return Ok(Value::Hex(num));
            }
            Rule::boolean => {
                let bool_str = inner.as_str().to_lowercase();
                return Ok(Value::Boolean(bool_str == "true"));
            }
            Rule::quoted_string => {
                let s = inner.as_str();
                // The grammar guarantees one matching pair of ASCII delimiters.
                let s = &s[1..s.len() - 1];
                return Ok(Value::String(s.to_string()));
            }
            Rule::identifier => {
                return Ok(Value::String(inner.as_str().to_string()));
            }
            _ => {}
        }
    }
    Err(GhidraError::FilterParseError("Invalid value".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let filter = parse_filter("name=test").unwrap();
        assert!(matches!(filter.expr, FilterExpr::Compare { .. }));
    }

    #[test]
    fn test_parse_and() {
        let filter = parse_filter("name=test AND size>100").unwrap();
        assert!(matches!(filter.expr, FilterExpr::Logical { .. }));
    }

    #[test]
    fn invalid_regex_is_rejected_before_rows_are_evaluated() {
        for input in ["name=~'['", "name=valid OR name=~'['", "NOT (name=~'[')"] {
            let error = parse_filter(input).err().expect(input);
            assert!(error.to_string().contains("Invalid regex"), "{error}");
        }
    }

    #[test]
    fn test_parse_hex() {
        for input in ["address=0x401000", "address=0X401000", "size=0X401000"] {
            let filter = parse_filter(input).unwrap();
            if let FilterExpr::Compare { value, .. } = filter.expr {
                assert!(matches!(value, Value::Hex(0x401000)));
            } else {
                panic!("Expected Compare expression");
            }
        }
    }

    #[test]
    fn rejects_invalid_address_literals_before_evaluating_any_rows() {
        for field in ["address", "entry_point", "items[0].call_site", "address[0]"] {
            for literal in [
                "16",
                "16.0",
                "-1",
                "true",
                "dead",
                "'00401000'",
                "'FUN_00401000'",
                "'ram:1234'",
                "'0x'",
                "'0xGG'",
                "'0x10000000000000000'",
                "'ram:0x1234:5'",
                "'overlay::0x1000'",
                "'ram:0x1.9'",
            ] {
                for comparison in [
                    format!("{field}={literal}"),
                    format!("{field}!={literal}"),
                    format!("{field}>={literal}"),
                    format!("{field} IN [0x1, {literal}]"),
                ] {
                    let error = parse_filter(&comparison).err().expect(&comparison);
                    let message = error.to_string();
                    assert!(message.contains(field), "{comparison}: {message}");
                    assert!(message.contains("0x-prefixed"), "{comparison}: {message}");
                }
            }
        }

        // Parsing rejects invalid branches even if later evaluation would
        // short-circuit or receive an empty result set.
        for input in [
            "name=ok OR address='ff90'",
            "name=missing AND address=16",
            "NOT (address IN [0x1, 'ram:1'])",
        ] {
            assert!(parse_filter(input).is_err(), "{input}");
        }
    }

    #[test]
    fn address_literal_checks_preserve_patterns_existence_and_other_field_types() {
        let data = serde_json::json!({
            "address": "0x00ff90", "size": 16, "name": "dead", "flag": true,
        });
        for input in [
            "address=0XFF90",
            "address IN [0XFF90]",
            "address~'ff90'",
            "address^'0x'",
            "address$'90'",
            "address=~'^0X0*FF90$'",
            "address EXISTS",
            "NOT address EMPTY",
            "NOT address NULL",
            "size=16",
            "size IN [16, 32]",
            "name=dead",
            "flag=true",
        ] {
            assert!(
                parse_filter(input).unwrap().evaluate(&data).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_incomplete_or_trailing_input() {
        for input in [
            "name=test garbage",
            "size>0 AND",
            "size>0 OR name=",
            "name=test)",
            "(name=test",
            "size>0 &&",
            "name IN []",
            "name EXISTS garbage",
            "name='unterminated",
            "",
        ] {
            assert!(parse_filter(input).is_err(), "accepted {input:?}");
        }
        assert!(parse_filter(" \n (name=test AND size>0) \t ").is_ok());
    }

    #[test]
    fn logical_precedence_parentheses_and_short_circuit() {
        let data = serde_json::json!({"a": 1, "b": 0, "c": 0, "name": "text"});
        for (input, expected) in [
            ("a=1 OR b=1 AND c=1", true),
            ("a=1 || b=1 && c=1", true),
            ("(a=1 OR b=1) AND c=1", false),
            ("NOT a=1 OR b=0 AND NOT c=1", true),
            ("!(a=1 OR b=1)", false),
            ("a=1 OR name>1", true),
            ("a=0 AND name>1", false),
        ] {
            assert_eq!(
                parse_filter(input).unwrap().evaluate(&data).unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn parses_existence_and_membership_through_evaluation() {
        let data = serde_json::json!({
            "name": "test", "empty": "", "nil": null, "tags": ["Crypto", "reviewed"],
            "size": 16, "flag": true, "object": {}, "array": []
        });
        for (input, expected) in [
            ("name EXISTS", true),
            ("missing EXISTS", false),
            ("nil EXISTS", true),
            ("name EMPTY", false),
            ("empty EMPTY", true),
            ("nil EMPTY", true),
            ("object EMPTY", true),
            ("array EMPTY", true),
            ("missing EMPTY", true),
            ("nil NULL", true),
            ("missing NULL", true),
            ("empty NULL", false),
            ("tags IN ['network', 'CRYPTO']", true),
            ("tags IN ['network']", false),
            ("name IN ['TEST']", true),
            ("size IN [1, 0x10]", true),
            ("flag IN [false, true]", true),
            ("NOT missing EXISTS AND tags IN ['crypto']", true),
        ] {
            assert_eq!(
                parse_filter(input).unwrap().evaluate(&data).unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn removes_only_outer_quotes_and_keeps_identifier_values() {
        for (input, name) in [
            (r#"name="'test'""#, "'test'"),
            (r#"name='"test"'"#, "\"test\""),
            (r#"name="''日本語''""#, "''日本語''"),
            (r#"name=''"#, ""),
            ("name=trueish", "trueish"),
            ("name=FALSE_name", "FALSE_name"),
        ] {
            let data = serde_json::json!({"name": name});
            assert!(
                parse_filter(input).unwrap().evaluate(&data).unwrap(),
                "{input}"
            );
        }
    }
}
