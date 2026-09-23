mod planner;

pub(crate) use planner::{FetchParams, FetchSupport, Page, QueryPlan};

use crate::cli::QueryOptions;
use crate::error::{GhidraError, Result};
use crate::filter::Filter;
use serde_json::Value as JsonValue;

#[derive(Default)]
pub struct Query {
    pub filter: Option<Filter>,
    pub fields: Option<FieldSelector>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort: Option<Vec<SortKey>>,
    pub count_only: bool,
}

impl Query {
    /// Build a Query from CLI QueryOptions. Returns None if no query processing is needed.
    pub fn from_options(opts: &QueryOptions) -> Result<Option<Self>> {
        let has_filter = opts.filter.is_some();
        let has_fields = opts.fields.is_some() || opts.exclude_fields.is_some();
        let has_sort = opts.sort.is_some();
        let has_count = opts.count;
        let has_offset = opts.skip.is_some();
        let has_limit = opts.limit.is_some();

        // Pagination also needs client-side processing when the caller fetches
        // all rows. Reapplying a limit to already capped data is idempotent.
        if !has_filter && !has_fields && !has_sort && !has_count && !has_offset && !has_limit {
            return Ok(None);
        }

        let filter = opts.filter.as_ref().map(|f| Filter::parse(f)).transpose()?;
        let fields =
            FieldSelector::from_options(opts.fields.as_deref(), opts.exclude_fields.as_deref())?;
        let sort = opts.sort.as_ref().map(|s| SortKey::parse(s));

        Ok(Some(Self {
            filter,
            fields,
            // QueryPlan removes any offset already applied by the bridge.
            limit: opts.limit,
            offset: opts.skip,
            sort,
            count_only: has_count,
        }))
    }

    /// Process query results from pre-fetched data.
    ///
    /// The caller owns fetching via IPC; this method filters, sorts, paginates,
    /// selects output fields, and returns the resulting JSON value.
    pub fn apply(&self, data: Vec<JsonValue>) -> Result<JsonValue> {
        let paginated = self.select_rows(data)?;

        // Return count if requested
        if self.count_only {
            return Ok(serde_json::json!(paginated.len()));
        }

        let selected = if let Some(fields) = &self.fields {
            self.select_fields(&paginated, fields)?
        } else {
            paginated
        };

        Ok(JsonValue::Array(selected))
    }

    /// Select rows before projection so structured responses can retain their relationships.
    pub(crate) fn select_rows(&self, data: Vec<JsonValue>) -> Result<Vec<JsonValue>> {
        // Apply filter
        let filtered = if let Some(filter) = &self.filter {
            self.apply_filter(&data, filter)?
        } else {
            data
        };

        // Sort original rows: projection must not erase sort keys.
        let sorted = if let Some(sort) = &self.sort {
            self.apply_sort(&filtered, sort)?
        } else {
            filtered
        };

        // Apply pagination
        Ok(self.apply_pagination(&sorted))
    }

    fn apply_filter(&self, data: &[JsonValue], filter: &Filter) -> Result<Vec<JsonValue>> {
        let mut result = Vec::new();

        for item in data {
            if filter.evaluate(item)? {
                result.push(item.clone());
            }
        }

        Ok(result)
    }

    pub(crate) fn select_fields(
        &self,
        data: &[JsonValue],
        selector: &FieldSelector,
    ) -> Result<Vec<JsonValue>> {
        let mut result = Vec::new();

        for item in data {
            if let JsonValue::Object(map) = item {
                let mut new_map = serde_json::Map::new();

                if let Some(include) = &selector.include {
                    for field in include {
                        if let Some(value) = map.get(field) {
                            new_map.insert(field.clone(), value.clone());
                        }
                    }
                } else if let Some(exclude) = &selector.exclude {
                    for (key, value) in map {
                        if !exclude.contains(key) {
                            new_map.insert(key.clone(), value.clone());
                        }
                    }
                } else {
                    new_map = map.clone();
                }

                result.push(JsonValue::Object(new_map));
            } else {
                result.push(item.clone());
            }
        }

        Ok(result)
    }

    fn apply_sort(&self, data: &[JsonValue], sort_keys: &[SortKey]) -> Result<Vec<JsonValue>> {
        let mut result = data.to_vec();

        result.sort_by(|a, b| {
            for sort_key in sort_keys {
                let a_val = self.get_field_for_sort(a, &sort_key.field);
                let b_val = self.get_field_for_sort(b, &sort_key.field);

                let cmp = match (&a_val, &b_val) {
                    (Some(JsonValue::Number(a)), Some(JsonValue::Number(b))) => {
                        compare_numbers(a, b)
                    }
                    (Some(JsonValue::Bool(a)), Some(JsonValue::Bool(b))) => a.cmp(b),
                    (Some(JsonValue::String(a)), Some(JsonValue::String(b))) => a.cmp(b),
                    _ => std::cmp::Ordering::Equal,
                };

                let final_cmp = if sort_key.descending {
                    cmp.reverse()
                } else {
                    cmp
                };

                if final_cmp != std::cmp::Ordering::Equal {
                    return final_cmp;
                }
            }

            std::cmp::Ordering::Equal
        });

        Ok(result)
    }

    fn get_field_for_sort(&self, value: &JsonValue, field: &str) -> Option<JsonValue> {
        if let JsonValue::Object(map) = value {
            map.get(field).cloned()
        } else {
            None
        }
    }

    fn apply_pagination(&self, data: &[JsonValue]) -> Vec<JsonValue> {
        let offset = self.offset.unwrap_or(0);
        // `--limit 0` means "no limit", matching the bridge's convention
        // (its list handlers only cap when limit > 0).
        let limit = match self.limit {
            None | Some(0) => usize::MAX,
            Some(n) => n,
        };

        data.iter().skip(offset).take(limit).cloned().collect()
    }
}

fn compare_numbers(a: &serde_json::Number, b: &serde_json::Number) -> std::cmp::Ordering {
    fn integer(number: &serde_json::Number) -> Option<i128> {
        number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
            .or_else(|| {
                // Integral floats can also be compared exactly to JSON integers.
                let value = number.as_f64()?;
                (value.fract() == 0.0 && value >= i128::MIN as f64 && value < -(i128::MIN as f64))
                    .then_some(value as i128)
            })
    }
    match (integer(a), integer(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => a
            .as_f64()
            .partial_cmp(&b.as_f64())
            .unwrap_or(std::cmp::Ordering::Equal),
    }
}

pub struct FieldSelector {
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
}

impl FieldSelector {
    pub fn include(fields: Vec<String>) -> Self {
        Self {
            include: Some(fields),
            exclude: None,
        }
    }

    pub fn exclude(fields: Vec<String>) -> Self {
        Self {
            include: None,
            exclude: Some(fields),
        }
    }

    pub fn from_options(include: Option<&str>, exclude: Option<&str>) -> Result<Option<Self>> {
        let (input, excluding) = match (include, exclude) {
            (Some(_), Some(_)) => {
                return Err(GhidraError::InvalidFormat(
                    "--fields and --exclude-fields cannot be combined".into(),
                ));
            }
            (Some(input), None) => (input, false),
            (None, Some(input)) => (input, true),
            (None, None) => return Ok(None),
        };
        let fields = input
            .split(',')
            .map(|field| field.trim().to_string())
            .collect();
        Ok(Some(if excluding {
            Self::exclude(fields)
        } else {
            Self::include(fields)
        }))
    }
}

pub struct SortKey {
    pub field: String,
    pub descending: bool,
}

impl SortKey {
    pub fn parse(input: &str) -> Vec<Self> {
        input
            .split(',')
            .map(|s| {
                let s = s.trim();
                if s.starts_with('-') {
                    SortKey {
                        field: s.trim_start_matches('-').to_string(),
                        descending: true,
                    }
                } else {
                    SortKey {
                        field: s.to_string(),
                        descending: false,
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Query {
        Query {
            filter: None,
            fields: None,
            limit: None,
            offset: None,
            sort: None,
            count_only: false,
        }
    }

    #[test]
    fn test_sort_key_parse() {
        let keys = SortKey::parse("name,-size");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].field, "name");
        assert!(!keys[0].descending);
        assert_eq!(keys[1].field, "size");
        assert!(keys[1].descending);
    }

    #[test]
    fn boolean_sort_selects_the_page_before_projection() {
        let query = Query {
            sort: Some(SortKey::parse("-no_return,name")),
            limit: Some(1),
            fields: Some(FieldSelector::include(vec!["name".into()])),
            ..Query::default()
        };
        let result = query
            .apply(vec![
                serde_json::json!({"name": "ordinary", "no_return": false}),
                serde_json::json!({"name": "exit", "no_return": true}),
                serde_json::json!({"name": "abort", "no_return": true}),
            ])
            .unwrap();
        assert_eq!(result, serde_json::json!([{"name": "abort"}]));
    }

    #[test]
    fn numeric_sort_preserves_integer_precision_and_mixed_numeric_order() {
        let expected = vec![
            serde_json::json!({"value": i64::MIN}),
            serde_json::json!({"value": -1}),
            serde_json::json!({"value": -0.5}),
            serde_json::json!({"value": 0}),
            serde_json::json!({"value": 0.5}),
            serde_json::json!({"value": 9007199254740992.0}),
            serde_json::json!({"value": 9007199254740993_u64}),
            serde_json::json!({"value": u64::MAX}),
        ];
        for descending in [false, true] {
            let mut expected = expected.clone();
            if descending {
                expected.reverse();
            }
            let mut input = expected.clone();
            input.reverse();
            let query = Query {
                sort: Some(SortKey::parse(if descending { "-value" } else { "value" })),
                ..Query::default()
            };
            assert_eq!(query.apply(input).unwrap(), serde_json::json!(expected));
        }
    }

    fn rows(n: usize) -> Vec<JsonValue> {
        (0..n).map(|i| serde_json::json!({ "id": i })).collect()
    }

    #[test]
    fn test_limit_zero_means_all_rows() {
        // Regression: `--limit 0` used to produce take(0) => empty output
        let mut query = query();
        query.limit = Some(0);
        assert_eq!(query.apply_pagination(&rows(5)).len(), 5);
    }

    #[test]
    fn test_limit_none_means_all_rows() {
        let query = query();
        assert_eq!(query.apply_pagination(&rows(5)).len(), 5);
    }

    #[test]
    fn test_limit_applies_after_offset() {
        let mut query = query();
        query.limit = Some(2);
        query.offset = Some(1);
        let page = query.apply_pagination(&rows(5));
        assert_eq!(page.len(), 2);
        assert_eq!(page[0]["id"], 1);
    }

    #[test]
    fn test_limit_zero_with_offset_returns_remainder() {
        let mut query = query();
        query.limit = Some(0);
        query.offset = Some(2);
        assert_eq!(query.apply_pagination(&rows(5)).len(), 3);
    }

    #[test]
    fn projection_does_not_change_filter_sort_or_page_selection() {
        let data = vec![
            serde_json::json!({"name": "small", "size": 1}),
            serde_json::json!({"name": "z", "size": 100}),
            serde_json::json!({"name": "a", "size": 100}),
            serde_json::json!({"name": "medium", "size": 50}),
        ];
        for (include, exclude) in [(Some("name"), None), (None, Some("size"))] {
            let opts = QueryOptions {
                program: None,
                project: None,
                filter: Some("size>1".to_string()),
                fields: include.map(str::to_string),
                exclude_fields: exclude.map(str::to_string),
                format: None,
                json: false,
                sort: Some("-size,name".to_string()),
                skip: Some(1),
                limit: Some(1),
                count: false,
            };
            let mut query = Query::from_options(&opts).unwrap().unwrap();
            let result: JsonValue = query.apply(data.clone()).unwrap();
            assert_eq!(result, serde_json::json!([{"name": "z"}]));
            query.count_only = true;
            assert_eq!(query.apply(data.clone()).unwrap(), serde_json::json!(1));
            query.count_only = false;
            query.limit = Some(0);
            let result: JsonValue = query.apply(data.clone()).unwrap();
            assert_eq!(
                result,
                serde_json::json!([{"name": "z"}, {"name": "medium"}])
            );
        }
    }
}
