use super::{CompareOp, ExistenceCheck, FilterExpr, LogicalOp, StringOp, Value};
use crate::error::{GhidraError, Result};
use regex::RegexBuilder;
use serde_json::Value as JsonValue;

pub fn evaluate(expr: &FilterExpr, data: &JsonValue) -> Result<bool> {
    match expr {
        FilterExpr::Compare { field, op, value } => evaluate_compare(field, *op, value, data),
        FilterExpr::StringOp { field, op, value } => evaluate_string_op(field, *op, value, data),
        FilterExpr::Logical { op, exprs } => evaluate_logical(*op, exprs, data),
        FilterExpr::Not(inner) => Ok(!evaluate(inner, data)?),
        FilterExpr::Exists { field, check } => evaluate_exists(field, *check, data),
        FilterExpr::In { field, values } => evaluate_in(field, values, data),
    }
}

fn get_field_value<'a>(field: &str, data: &'a JsonValue) -> Option<&'a JsonValue> {
    let mut current = data;

    for part in field.split('.') {
        let mut segments = part.split('[');
        current = current.get(segments.next()?)?;
        for segment in segments {
            let index = segment.strip_suffix(']')?.parse::<usize>().ok()?;
            current = current.get(index)?;
        }
    }

    Some(current)
}

fn evaluate_compare(field: &str, op: CompareOp, value: &Value, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let field_value = field_value.unwrap();

    match (field_value, value) {
        (JsonValue::Number(n), val) => compare_numbers(&json_number(n), val, op).ok_or_else(|| {
            GhidraError::InvalidFilter(format!("Cannot compare number with {:?}", val))
        }),
        (JsonValue::String(s), val) if val.as_f64().is_some() => {
            // Preserve hex-first interpretation of bridge address strings,
            // including address-space prefixes, without rounding through f64.
            match parse_numeric_field(s) {
                Some(field_num) => Ok(compare_numbers(&field_num, val, op).unwrap()),
                None => Err(GhidraError::InvalidFilter(format!(
                    "Cannot compare non-numeric string field {:?} numerically",
                    s
                ))),
            }
        }
        (JsonValue::String(s), Value::String(val)) => Ok(match op {
            CompareOp::Equal => strings_equal_lenient(field, s, val),
            CompareOp::NotEqual => !strings_equal_lenient(field, s, val),
            _ => {
                return Err(GhidraError::InvalidFilter(
                    "Cannot use numeric comparison on strings".to_string(),
                ))
            }
        }),
        (JsonValue::Bool(b), Value::Boolean(val)) => Ok(match op {
            CompareOp::Equal => *b == *val,
            CompareOp::NotEqual => *b != *val,
            _ => {
                return Err(GhidraError::InvalidFilter(
                    "Cannot use numeric comparison on booleans".to_string(),
                ))
            }
        }),
        (JsonValue::Array(elems), val) => {
            // Array fields (e.g. `tags`): `=` is any-element-equals; `!=` is
            // NO-element-equals (i.e. `tags != 'x'` ≡ `NOT(tags = 'x')` —
            // naive any-element `!=` would be true for nearly every
            // multi-element array). Ordering comparisons on arrays are false.
            match op {
                CompareOp::Equal | CompareOp::NotEqual => {
                    let any_equal = elems.iter().any(|elem| scalar_equals(elem, val));
                    Ok(if matches!(op, CompareOp::Equal) {
                        any_equal
                    } else {
                        !any_equal
                    })
                }
                _ => Ok(false),
            }
        }
        _ => Ok(false),
    }
}

fn json_number(number: &serde_json::Number) -> Value {
    if let Some(n) = number.as_i64() {
        Value::Integer(n)
    } else if let Some(n) = number.as_u64() {
        Value::Hex(n)
    } else {
        Value::Number(number.as_f64().unwrap())
    }
}

// i128 holds both signed JSON integers and the complete u64 address range.
// Integral float literals also have an exact integer representation here;
// this avoids rounding an address when comparing against e.g. 9007199254740992.0.
fn exact_integer(value: &Value) -> Option<i128> {
    match value {
        Value::Integer(n) => Some(i128::from(*n)),
        Value::Hex(n) => Some(i128::from(*n)),
        Value::Number(n)
            if n.fract() == 0.0 && *n >= i128::MIN as f64 && *n < -(i128::MIN as f64) =>
        {
            Some(*n as i128)
        }
        _ => None,
    }
}

fn compare_numbers(left: &Value, right: &Value, op: CompareOp) -> Option<bool> {
    if let (Some(left), Some(right)) = (exact_integer(left), exact_integer(right)) {
        return Some(match op {
            CompareOp::Equal => left == right,
            CompareOp::NotEqual => left != right,
            CompareOp::Greater => left > right,
            CompareOp::GreaterEqual => left >= right,
            CompareOp::Less => left < right,
            CompareOp::LessEqual => left <= right,
        });
    }
    // Retain the existing tolerance for non-integral floating point values.
    let left = left.as_f64()?;
    let right = right.as_f64()?;
    Some(match op {
        CompareOp::Equal => (left - right).abs() < f64::EPSILON,
        CompareOp::NotEqual => (left - right).abs() >= f64::EPSILON,
        CompareOp::Greater => left > right,
        CompareOp::GreaterEqual => left >= right,
        CompareOp::Less => left < right,
        CompareOp::LessEqual => left <= right,
    })
}

/// Element-vs-value equality for array-field filters. Mirrors the scalar `=`
/// semantics (exact, case-sensitive for strings); type mismatches are simply
/// not-equal rather than errors, since arrays can hold mixed content.
fn scalar_equals(elem: &JsonValue, val: &Value) -> bool {
    match (elem, val) {
        (JsonValue::String(s), Value::String(v)) => s == v,
        (JsonValue::Number(n), v) => {
            compare_numbers(&json_number(n), v, CompareOp::Equal).unwrap_or(false)
        }
        (JsonValue::Bool(b), Value::Boolean(v)) => *b == *v,
        _ => false,
    }
}

/// Equal/NotEqual on two string values for `evaluate_compare`: exact match,
/// or -- for address-shaped fields -- tolerant of a `0x`/`0X` prefix on the
/// filter's value. Ghidra addresses are stored and returned as bare hex
/// (e.g. "ff90"), but every other place in this CLI's own docs/output uses
/// `0xADDR` freely (`ghidra-cli decompile 0x0331`, `ghidra-cli x-ref to 0xff90`),
/// so a quoted `--filter "address = '0xff90'"` used to silently match
/// nothing instead of comparing the same way those other commands do.
fn strings_equal_lenient(field: &str, field_val: &str, filter_val: &str) -> bool {
    if field_val == filter_val {
        return true;
    }
    if !is_address_field(field) {
        return false;
    }
    let stripped = filter_val
        .strip_prefix("0x")
        .or_else(|| filter_val.strip_prefix("0X"));
    match stripped {
        Some(stripped) => field_val.eq_ignore_ascii_case(stripped),
        None => false,
    }
}

/// Field names (last path segment) that hold a Ghidra address as a bare hex
/// string, per the JSON the bridge emits (`address`, `entry_point`, xref
/// `from`/`to`, `min_address`/`max_address`).
fn is_address_field(field: &str) -> bool {
    matches!(
        field.rsplit('.').next().unwrap_or(field),
        "address" | "entry_point" | "from" | "to" | "min_address" | "max_address"
    )
}

/// Parse a JSON string field as a number for numeric comparison. Ghidra
/// address strings are unprefixed hex (optionally with an address-space
/// prefix like "ram:"), so hex is tried first; plain decimal is the
/// fallback for other numeric-looking string fields.
fn parse_numeric_field(s: &str) -> Option<Value> {
    let hex_part = s.rsplit(':').next().unwrap_or(s);
    let hex_part = hex_part
        .strip_prefix("0x")
        .or_else(|| hex_part.strip_prefix("0X"))
        .unwrap_or(hex_part);
    if !hex_part.is_empty() {
        if let Ok(n) = u64::from_str_radix(hex_part, 16) {
            return Some(Value::Hex(n));
        }
    }
    s.parse::<f64>().ok().map(Value::Number)
}

fn evaluate_string_op(field: &str, op: StringOp, value: &str, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let value_lower = value.to_lowercase();
    let matches_str = |field_str: &str| -> Result<bool> {
        Ok(match op {
            StringOp::Contains => field_str.contains(&value_lower),
            StringOp::StartsWith => field_str.starts_with(&value_lower),
            StringOp::EndsWith => field_str.ends_with(&value_lower),
            StringOp::Regex => compiled_regex(value)?.is_match(field_str),
        })
    };

    match field_value.unwrap() {
        // Array fields (e.g. `tags`): any-element semantics — match if any
        // element satisfies the predicate.
        JsonValue::Array(elems) => {
            for elem in elems {
                if let Some(s) = scalar_to_lower_string(elem) {
                    if matches_str(&s)? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        other => match scalar_to_lower_string(other) {
            Some(s) => matches_str(&s),
            None => Ok(false),
        },
    }
}

fn scalar_to_lower_string(v: &JsonValue) -> Option<String> {
    match v {
        JsonValue::String(s) => Some(s.to_lowercase()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Compile a filter regex once per pattern; `evaluate` runs per row, and
/// recompiling on every row dominates runtime on large datasets.
/// Case-insensitive because field values are lowercased before matching —
/// an uppercase pattern like `^PK_` could otherwise never match.
fn compiled_regex(pattern: &str) -> Result<std::rc::Rc<regex::Regex>> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    thread_local! {
        static CACHE: RefCell<HashMap<String, Rc<regex::Regex>>> = RefCell::new(HashMap::new());
    }

    CACHE.with(|cache| {
        if let Some(re) = cache.borrow().get(pattern) {
            return Ok(re.clone());
        }
        let re = Rc::new(
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| GhidraError::InvalidFilter(format!("Invalid regex: {}", e)))?,
        );
        cache.borrow_mut().insert(pattern.to_string(), re.clone());
        Ok(re)
    })
}

fn evaluate_logical(op: LogicalOp, exprs: &[FilterExpr], data: &JsonValue) -> Result<bool> {
    match op {
        LogicalOp::And => {
            for expr in exprs {
                if !evaluate(expr, data)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        LogicalOp::Or => {
            for expr in exprs {
                if evaluate(expr, data)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn evaluate_exists(field: &str, check: ExistenceCheck, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    Ok(match check {
        ExistenceCheck::Exists => field_value.is_some(),
        ExistenceCheck::Empty => match field_value {
            None => true,
            Some(JsonValue::Null) => true,
            Some(JsonValue::String(s)) => s.is_empty(),
            Some(JsonValue::Array(a)) => a.is_empty(),
            Some(JsonValue::Object(o)) => o.is_empty(),
            _ => false,
        },
        ExistenceCheck::Null => {
            matches!(field_value, None | Some(JsonValue::Null))
        }
    })
}

fn evaluate_in(field: &str, values: &[Value], data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let field_value = field_value.unwrap();

    // Array fields (e.g. `tags`): any-element semantics.
    if let JsonValue::Array(elems) = field_value {
        return Ok(elems
            .iter()
            .any(|elem| values.iter().any(|v| scalar_matches_in(elem, v))));
    }

    Ok(values.iter().any(|v| scalar_matches_in(field_value, v)))
}

/// `IN`-list membership for one scalar. Strings compare case-insensitively,
/// matching the operator's pre-existing scalar semantics.
fn scalar_matches_in(field_value: &JsonValue, val: &Value) -> bool {
    match (field_value, val) {
        (JsonValue::String(s), Value::String(v)) => s.eq_ignore_ascii_case(v),
        (JsonValue::Number(n), v) => {
            compare_numbers(&json_number(n), v, CompareOp::Equal).unwrap_or(false)
        }
        (JsonValue::Bool(b), Value::Boolean(v)) => *b == *v,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evaluate_compare() {
        let data = json!({
            "name": "test",
            "size": 100
        });

        let expr = FilterExpr::Compare {
            field: "size".to_string(),
            op: CompareOp::Greater,
            value: Value::Integer(50),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_string_op() {
        let data = json!({
            "name": "test_function"
        });

        let expr = FilterExpr::StringOp {
            field: "name".to_string(),
            op: StringOp::Contains,
            value: "func".to_string(),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_address_range_filter() {
        // Regression: Ghidra addresses come back as hex strings (e.g.
        // "002dad4c"), never JSON numbers. A numeric filter against that
        // field used to silently fall through to `Ok(false)` for every
        // row instead of comparing addresses.
        let in_range = json!({ "name": "f1", "address": "002df100" });
        let below_range = json!({ "name": "f2", "address": "002d0000" });

        let expr = FilterExpr::Logical {
            op: LogicalOp::And,
            exprs: vec![
                FilterExpr::Compare {
                    field: "address".to_string(),
                    op: CompareOp::GreaterEqual,
                    value: Value::Hex(0x002df000),
                },
                FilterExpr::Compare {
                    field: "address".to_string(),
                    op: CompareOp::LessEqual,
                    value: Value::Hex(0x002e3600),
                },
            ],
        };

        assert!(evaluate(&expr, &in_range).unwrap());
        assert!(!evaluate(&expr, &below_range).unwrap());
    }

    #[test]
    fn test_evaluate_quoted_hex_address_equality() {
        // Regression: a quoted filter value ('0xff90') parses as
        // Value::String, not Value::Hex, so it used to fall into plain
        // string equality against the bare-hex stored field and never
        // match, even though every other command in this CLI accepts
        // 0x-prefixed addresses freely.
        let data = json!({ "name": "g_game_state", "address": "ff90" });

        let expr = FilterExpr::Compare {
            field: "address".to_string(),
            op: CompareOp::Equal,
            value: Value::String("0xff90".to_string()),
        };
        assert!(evaluate(&expr, &data).unwrap());

        let expr_ne = FilterExpr::Compare {
            field: "address".to_string(),
            op: CompareOp::NotEqual,
            value: Value::String("0xff90".to_string()),
        };
        assert!(!evaluate(&expr_ne, &data).unwrap());

        // Non-address string fields are unaffected by 0x-stripping.
        let name_expr = FilterExpr::Compare {
            field: "name".to_string(),
            op: CompareOp::Equal,
            value: Value::String("0xff90".to_string()),
        };
        assert!(!evaluate(&name_expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_regex_is_case_insensitive() {
        // Regression: fields are lowercased before matching, so an uppercase
        // pattern like ^PK_ silently matched nothing.
        let data = json!({ "name": "PK_APPITEM_ask" });

        let expr = FilterExpr::StringOp {
            field: "name".to_string(),
            op: StringOp::Regex,
            value: "^PK_".to_string(),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_array_field_contains_any_element() {
        let data = json!({ "tags": ["Crypto", "reviewed"] });

        // ~ is case-insensitive and matches any element
        let expr = FilterExpr::StringOp {
            field: "tags".to_string(),
            op: StringOp::Contains,
            value: "crypto".to_string(),
        };
        assert!(evaluate(&expr, &data).unwrap());

        let expr = FilterExpr::StringOp {
            field: "tags".to_string(),
            op: StringOp::Contains,
            value: "network".to_string(),
        };
        assert!(!evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_array_field_equals_is_exact_any_element() {
        let data = json!({ "tags": ["Crypto", "reviewed"] });

        // = is exact-match (case-sensitive), any element
        let eq = |v: &str| FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::Equal,
            value: Value::String(v.to_string()),
        };
        assert!(evaluate(&eq("Crypto"), &data).unwrap());
        assert!(!evaluate(&eq("crypto"), &data).unwrap());
    }

    #[test]
    fn test_array_field_not_equal_is_no_element_equals() {
        // tags != 'x' must mean NO element equals x, not "some element differs".
        let data = json!({ "tags": ["crypto", "reviewed"] });

        let ne = |v: &str| FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::NotEqual,
            value: Value::String(v.to_string()),
        };
        assert!(!evaluate(&ne("crypto"), &data).unwrap());
        assert!(evaluate(&ne("network"), &data).unwrap());
    }

    #[test]
    fn test_array_field_ordering_comparison_is_false() {
        let data = json!({ "tags": ["crypto"] });
        let expr = FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::Greater,
            value: Value::Integer(1),
        };
        assert!(!evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_array_field_in_any_element() {
        let data = json!({ "tags": ["crypto", "reviewed"] });
        let expr = FilterExpr::In {
            field: "tags".to_string(),
            values: vec![
                Value::String("network".to_string()),
                Value::String("CRYPTO".to_string()), // IN is case-insensitive
            ],
        };
        assert!(evaluate(&expr, &data).unwrap());

        let expr = FilterExpr::In {
            field: "tags".to_string(),
            values: vec![Value::String("network".to_string())],
        };
        assert!(!evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_empty_array_field() {
        let data = json!({ "tags": [] });
        let expr = FilterExpr::StringOp {
            field: "tags".to_string(),
            op: StringOp::Contains,
            value: "x".to_string(),
        };
        assert!(!evaluate(&expr, &data).unwrap());

        // tags != 'x' on an empty array: no element equals x → true
        let expr = FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::NotEqual,
            value: Value::String("x".to_string()),
        };
        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_nested_field() {
        let data = json!({
            "function": {
                "name": "test",
                "xrefs": {
                    "count": 10
                }
            }
        });

        let expr = FilterExpr::Compare {
            field: "function.xrefs.count".to_string(),
            op: CompareOp::Greater,
            value: Value::Integer(5),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn nested_array_paths_follow_the_grammar() {
        let data = json!({"a": [[{"name": "found"}]], "items": [{"size": 2}]});
        for (input, expected) in [
            ("a[0][0].name=found", true),
            ("a[0][0].name EXISTS", true),
            ("items[0].size IN [1,2]", true),
            ("a[1][0].name=found", false),
            ("a[-1][0].name=found", false),
            ("a[0.5][0].name=found", false),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(input)
                    .unwrap()
                    .evaluate(&data)
                    .unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn address_comparisons_preserve_all_integer_bits() {
        let data = json!({"address": "ram:0020000000000001"});
        for (input, expected) in [
            ("address=0x20000000000000", false),
            ("address!=0x20000000000000", true),
            ("address>0x20000000000000", true),
            ("address>=0x20000000000001", true),
            ("address<0x20000000000001", false),
            ("address<=0x20000000000000", false),
            ("address=9007199254740993", true),
            ("address=9007199254740992.0", false),
            ("address>-1", true),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(input)
                    .unwrap()
                    .evaluate(&data)
                    .unwrap(),
                expected,
                "{input}"
            );
        }
        let high = json!({"address": "0xffffffffffffffff"});
        for (input, expected) in [
            ("address=0xffffffffffffffff", true),
            ("address=0xfffffffffffffffe", false),
            ("address>0xfffffffffffffffe", true),
            ("address<18446744073709551616.0", true),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(input)
                    .unwrap()
                    .evaluate(&high)
                    .unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn numeric_equality_is_consistent_for_scalars_arrays_and_in() {
        let data = json!({"n": u64::MAX, "values": [u64::MAX], "negative": i64::MIN});
        for (input, expected) in [
            ("n=0xffffffffffffffff", true),
            ("n=0xfffffffffffffffe", false),
            ("values=0xfffffffffffffffe", false),
            ("values!=0xfffffffffffffffe", true),
            ("n IN [0xfffffffffffffffe]", false),
            ("values IN [0xfffffffffffffffe]", false),
            ("values IN [0xffffffffffffffff]", true),
            ("negative=-9223372036854775808", true),
            ("negative<0xffffffffffffffff", true),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(input)
                    .unwrap()
                    .evaluate(&data)
                    .unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn numeric_string_and_fractional_semantics_are_preserved() {
        let data =
            json!({"value": "10", "fraction": "1.5", "n": 1.5, "name": "word", "values": ["10"]});
        for (input, expected) in [
            ("value=10", false),
            ("value=0x10", true),
            ("value='10'", true),
            ("fraction=1.5", true),
            ("n>1.4", true),
            ("n<1.6", true),
            ("values=0x10", false),
            ("value IN [0x10]", false),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(input)
                    .unwrap()
                    .evaluate(&data)
                    .unwrap(),
                expected,
                "{input}"
            );
        }
        assert!(crate::filter::Filter::parse("name>1")
            .unwrap()
            .evaluate(&data)
            .is_err());
        assert!(crate::filter::Filter::parse("n='1.5'")
            .unwrap()
            .evaluate(&data)
            .is_err());
    }
}
