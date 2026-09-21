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
    // "0x002dad4c"), never JSON numbers. A numeric filter against that
    // field used to silently fall through to `Ok(false)` for every
    // row instead of comparing addresses.
    let in_range = json!({ "name": "f1", "address": "0x002df100" });
    let below_range = json!({ "name": "f2", "address": "0x002d0000" });

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
    // Quoted explicit addresses compare independent of padding and case.
    let data = json!({ "name": "g_game_state", "address": "0x00ff90" });

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

    // Non-address string fields retain exact equality.
    let name_expr = FilterExpr::Compare {
        field: "name".to_string(),
        op: CompareOp::Equal,
        value: Value::String("0xff90".to_string()),
    };
    assert!(!evaluate(&name_expr, &data).unwrap());
}

#[test]
fn address_filters_require_explicit_components_and_preserve_spaces() {
    let data = json!({"address": "ram:0x0000ff90", "call_site": "0x0000ff90"});
    for (input, expected) in [
        ("address='ram:0XFF90'", true),
        ("address='other:0xff90'", false),
        ("address='RAM:0xff90'", false),
        ("address='0xff90'", false),
        ("call_site='0XFF90'", true),
        ("call_site='0xff91'", false),
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
    for address in ["ff90", "ram:ff90", "ram:0x1234:0xff90", "ram:0xff90.1"] {
        assert!(
            crate::filter::Filter::parse("address>0xff00")
                .unwrap()
                .evaluate(&json!({"address":address}))
                .is_err(),
            "{address}"
        );
    }
    assert!(strings_equal(
        "address",
        "ram:0x1234:0x0005",
        "ram:0X1234:0x5"
    ));
    assert!(!strings_equal(
        "address",
        "ram:0x1234:0x0005",
        "ram:0x5678:0x5"
    ));
}

#[test]
fn address_membership_uses_equality_rules_for_spaces_segments_and_padding() {
    let data = json!({
        "address": "Bank:0x00abcdef",
        "entry_point": "ram:0x1234:0x0005",
        "call_site": "0x0020000000000001",
        "via": "ram:0x10.1",
        "items": [{"address": "0xbank:0x000f"}, {"address": "0xAB:0x0005"}],
    });
    for (field, literal, expected) in [
        ("address", "'Bank:0XABCDEF'", true),
        ("address", "'bank:0xabcdef'", false),
        ("address", "'Other:0xabcdef'", false),
        ("address", "'0xabcdef'", false),
        ("entry_point", "'ram:0X1234:0x5'", true),
        ("entry_point", "'ram:0x5678:0x5'", false),
        ("entry_point", "'ram:0x0005'", false),
        ("call_site", "0X20000000000001", true),
        ("call_site", "0x20000000000000", false),
        ("call_site", "'0X20000000000001'", true),
        ("via", "'ram:0x0010.01'", true),
        ("via", "'ram:0x10.0'", false),
        ("items[0].address", "'0xbank:0X000F'", true),
        ("items[0].address", "'0XBANK:0x000f'", false),
        ("items[1].address", "'0xAB:0X5'", true),
        ("items[1].address", "'0xab:0x5'", false),
        ("items[1].address", "'0x00AB:0x5'", false),
        ("items[1].address", "'ram:0xab:0x5'", false),
    ] {
        for expression in [
            format!("{field}={literal}"),
            format!("{field} IN [{literal}]"),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(&expression)
                    .unwrap()
                    .evaluate(&data)
                    .unwrap(),
                expected,
                "{expression}"
            );
        }
    }
    assert!(
        crate::filter::Filter::parse("address IN ['Other:0xabcdef', 'Bank:0XABCDEF']")
            .unwrap()
            .evaluate(&data)
            .unwrap()
    );

    let addresses = json!({"address": ["0x0020000000000001", "ram:0x1234:0x0005"]});
    for (literal, expected) in [
        ("'0X20000000000001'", true),
        ("0X20000000000001", true),
        ("0x20000000000000", false),
        ("'ram:0x1234:0x5'", true),
        ("'ram:0x5678:0x5'", false),
    ] {
        for expression in [
            format!("address={literal}"),
            format!("address IN [{literal}]"),
        ] {
            assert_eq!(
                crate::filter::Filter::parse(&expression)
                    .unwrap()
                    .evaluate(&addresses)
                    .unwrap(),
                expected,
                "{expression}"
            );
        }
    }
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
    let data = json!({"address": "ram:0x0020000000000001"});
    for (input, expected) in [
        ("address=0x20000000000000", false),
        ("address!=0x20000000000000", true),
        ("address>0x20000000000000", true),
        ("address>=0x20000000000001", true),
        ("address<0x20000000000001", false),
        ("address<=0x20000000000000", false),
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
        ("address IN [0XFFFFFFFFFFFFFFFF]", true),
        ("address IN [0xfffffffffffffffe]", false),
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
fn decimal_comparisons_on_numeric_fields_preserve_integer_precision() {
    let data = json!({"n": 9007199254740993_u64, "high": u64::MAX});
    for (input, expected) in [
        ("n=9007199254740993", true),
        ("n=9007199254740992.0", false),
        ("n>-1", true),
        ("n IN [9007199254740993]", true),
        ("n IN [9007199254740992.0]", false),
        ("high<18446744073709551616.0", true),
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
