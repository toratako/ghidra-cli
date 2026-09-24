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
            // Explicit address offsets keep all integer bits. Other numeric
            // string fields retain their existing comparison semantics.
            match parse_numeric_field(field, s) {
                Some(field_num) => Ok(compare_numbers(&field_num, val, op).unwrap()),
                None => Err(GhidraError::InvalidFilter(format!(
                    "Cannot compare non-numeric string field {:?} numerically",
                    s
                ))),
            }
        }
        (JsonValue::String(s), Value::String(val)) => Ok(match op {
            CompareOp::Equal => strings_equal(field, s, val),
            CompareOp::NotEqual => !strings_equal(field, s, val),
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
                    let any_equal = elems.iter().any(|elem| scalar_equals(field, elem, val));
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
// this avoids rounding a JSON integer against e.g. 9007199254740992.0.
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
/// semantics (address-aware, otherwise exact for strings); type mismatches are simply
/// not-equal rather than errors, since arrays can hold mixed content.
fn scalar_equals(field: &str, elem: &JsonValue, val: &Value) -> bool {
    match (elem, val) {
        (JsonValue::String(s), Value::String(v)) => strings_equal(field, s, v),
        (JsonValue::String(s), Value::Hex(_)) if is_address_field(field) => {
            parse_numeric_field(field, s)
                .and_then(|n| compare_numbers(&n, val, CompareOp::Equal))
                .unwrap_or(false)
        }
        (JsonValue::Number(n), v) => {
            compare_numbers(&json_number(n), v, CompareOp::Equal).unwrap_or(false)
        }
        (JsonValue::Bool(b), Value::Boolean(v)) => *b == *v,
        _ => false,
    }
}

/// Address strings compare explicit components, preserving spaces and segments.
/// Other string fields use exact equality.
fn strings_equal(field: &str, field_val: &str, filter_val: &str) -> bool {
    if !is_address_field(field) {
        return field_val == filter_val;
    }
    match (
        crate::address::ExplicitAddress::parse_canonical(field_val),
        crate::address::ExplicitAddress::parse_canonical(filter_val),
    ) {
        (Some(actual), Some(requested)) => actual.same_location(&requested),
        _ => false,
    }
}

/// Structured fields containing addresses rather than arbitrary text.
pub(super) fn is_address_field(field: &str) -> bool {
    let leaf = field.rsplit('.').next().unwrap_or(field);
    matches!(
        leaf.split('[').next().unwrap_or(leaf),
        "address"
            | "entry_point"
            | "from"
            | "to"
            | "min_address"
            | "max_address"
            | "image_base"
            | "start"
            | "end"
            | "call_site"
            | "caller_address"
            | "callee_address"
            | "string_address"
            | "instruction_address"
            | "via"
            | "disasm_at"
            | "first_use"
            | "conflicting_start"
            | "conflicting_end"
            | "containing_function_entry"
    )
}

/// Flat explicit addresses can be compared numerically. Segmented and word
/// offsets require their space semantics; never silently drop a component.
fn parse_numeric_field(field: &str, s: &str) -> Option<Value> {
    if is_address_field(field) {
        let address = crate::address::ExplicitAddress::parse_canonical(s)?;
        if address.components.len() != 1 || address.components[0].contains('.') {
            return None;
        }
        return u64::from_str_radix(&address.components[0][2..], 16)
            .ok()
            .map(Value::Hex);
    }
    // Preserve existing numeric-string semantics outside address fields.
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

pub(super) fn validate_regex(pattern: &str) -> Result<()> {
    compiled_regex(pattern).map(|_| ())
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
    // Address membership shares `=` semantics, including full-width numeric
    // offsets and exact space/segment identity for explicit address strings.
    if is_address_field(field) {
        for value in values {
            if evaluate_compare(field, CompareOp::Equal, value, data)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
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
mod tests;
