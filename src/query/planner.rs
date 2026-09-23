//! Decide which list operations run in Java and retain the Rust post-processing.

use super::Query;
use crate::filter::{FilterExpr, StringOp};

/// Operations that the command's adapter actually forwards to the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchSupport {
    Client,
    Limit,
    Paged(&'static str),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct FetchParams {
    pub limit: Option<usize>,
    pub filter: Option<String>,
    pub offset: Option<usize>,
}

pub(crate) struct QueryPlan {
    pub fetch: FetchParams,
    pub post: Option<Query>,
    /// Effective page before a pushed offset is consumed by the bridge.
    pub page: Page,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Page {
    pub offset: usize,
    pub limit: Option<usize>,
}

impl QueryPlan {
    /// Resolve the limit once and retain anything the bridge cannot apply.
    pub fn new(
        mut query: Option<Query>,
        default_limit: Option<usize>,
        support: FetchSupport,
    ) -> Self {
        let list_field = match support {
            FetchSupport::Paged(field) => Some(field),
            _ => None,
        };
        let mut fetch = FetchParams::default();
        let mut page = Page::default();
        if query.is_none() && default_limit.is_some() {
            query = Some(Query::default());
        }
        if let Some(post) = &mut query {
            let selects_rows =
                post.filter.is_some() || post.sort.is_some() || post.offset.is_some();
            // Preserve the output default, including after filtering/sorting.
            // --count ignores the default; an explicit --limit still applies.
            if post.limit.is_none() && !post.count_only {
                post.limit = default_limit;
            }
            page = Page {
                offset: post.offset.unwrap_or(0),
                limit: post.limit.filter(|&n| n != 0),
            };
            fetch.filter = match (list_field, post.filter.as_ref().map(|f| &f.expr)) {
                (
                    Some(list_field),
                    Some(FilterExpr::StringOp {
                        field,
                        op: StringOp::Contains,
                        value,
                    }),
                ) if field == list_field => Some(value.clone()),
                _ => None,
            };
            let can_page = list_field.is_some()
                && post.sort.is_none()
                && !post.count_only
                && (post.filter.is_none() || fetch.filter.is_some());
            fetch.limit = if support == FetchSupport::Client
                || ((selects_rows || post.count_only) && !can_page)
            {
                None
            } else {
                post.limit.filter(|&n| n != 0)
            };
            if can_page {
                // Offset is not idempotent: never apply it a second time.
                fetch.offset = post.offset.take().filter(|&n| n != 0);
            }
        }
        Self {
            fetch,
            post: query,
            page,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::QueryOptions;
    use serde_json::{json, Value};

    fn options() -> QueryOptions {
        QueryOptions {
            program: None,
            project: None,
            filter: None,
            fields: None,
            exclude_fields: None,
            format: None,
            limit: None,
            skip: None,
            sort: None,
            count: false,
            json: false,
        }
    }

    fn plan(opts: &QueryOptions, support: FetchSupport) -> QueryPlan {
        QueryPlan::new(Query::from_options(opts).unwrap(), Some(2), support)
    }

    #[test]
    fn contains_pages_matching_rows_and_consumes_offset_once() {
        let mut opts = options();
        opts.filter = Some("name~item".into());
        opts.skip = Some(3);
        let plan = plan(&opts, FetchSupport::Paged("name"));
        assert_eq!(
            plan.fetch,
            FetchParams {
                filter: Some("item".into()),
                limit: Some(2),
                offset: Some(3),
            }
        );
        let post = plan.post.unwrap();
        assert!(post.filter.is_some());
        assert_eq!(post.offset, None);
        assert_eq!(post.limit, Some(2));
    }

    #[test]
    fn unsupported_filters_or_offsets_never_cap_before_client_selection() {
        for filter in [
            None,
            Some("name^item"),
            Some("name=item"),
            Some("size>0"),
            Some("tags~item"),
            Some("name~item AND size>0"),
        ] {
            for support in [
                FetchSupport::Client,
                FetchSupport::Limit,
                FetchSupport::Paged("name"),
            ] {
                let mut opts = options();
                opts.filter = filter.map(str::to_string);
                opts.skip = Some(2);
                opts.limit = Some(3);
                let plan = plan(&opts, support);
                if filter.is_some() || support != FetchSupport::Paged("name") {
                    assert_eq!(plan.fetch, FetchParams::default());
                    assert_eq!(plan.post.unwrap().offset, Some(2));
                }
            }
        }
    }

    #[test]
    fn sort_and_count_keep_all_matches_for_rust() {
        for count in [false, true] {
            let mut opts = options();
            opts.filter = Some("name~item".into());
            opts.skip = Some(1);
            opts.count = count;
            opts.sort = (!count).then(|| "-size".into());
            let plan = plan(&opts, FetchSupport::Paged("name"));
            assert_eq!(plan.fetch.filter.as_deref(), Some("item"));
            assert_eq!(plan.fetch.limit, None);
            assert_eq!(plan.fetch.offset, None);
            assert_eq!(plan.post.as_ref().unwrap().offset, Some(1));
            assert_eq!(plan.post.unwrap().limit, if count { None } else { Some(2) });
        }
    }

    #[test]
    fn planned_results_match_full_fetch_pipeline() {
        let rows = vec![
            json!({"name":"other", "size":0}),
            json!({"name":"item_c", "size":10}),
            json!({"name":"ITEM_B", "size":30}),
            json!({"name":"item_a", "size":20}),
            json!({"name":"tail_item", "size":40}),
        ];
        // Exercise the cross-product against the existing full-fetch behavior,
        // including projection that removes the sort key and explicit zero.
        for support in [
            FetchSupport::Client,
            FetchSupport::Limit,
            FetchSupport::Paged("name"),
        ] {
            for filter in [
                None,
                Some("name~item"),
                Some("name^item"),
                Some("size>0"),
                Some("name~item AND size>15"),
            ] {
                for sort in [None, Some("-size,name")] {
                    for count in [false, true] {
                        for offset in [None, Some(0), Some(2), Some(99)] {
                            for limit in [None, Some(0), Some(1), Some(3)] {
                                let mut opts = options();
                                opts.filter = filter.map(str::to_string);
                                opts.sort = sort.map(str::to_string);
                                opts.count = count;
                                opts.skip = offset;
                                opts.limit = limit;
                                opts.fields = Some("name".into());
                                let plan = plan(&opts, support);
                                let fetched: Vec<Value> = rows
                                    .iter()
                                    .filter(|row| {
                                        plan.fetch.filter.as_ref().is_none_or(|s| {
                                            row["name"]
                                                .as_str()
                                                .unwrap()
                                                .to_lowercase()
                                                .contains(&s.to_lowercase())
                                        })
                                    })
                                    .skip(plan.fetch.offset.unwrap_or(0))
                                    .take(plan.fetch.limit.unwrap_or(usize::MAX))
                                    .cloned()
                                    .collect();
                                let actual = plan.post.unwrap().apply(fetched).unwrap();
                                // Reference: full-data client query with the output's
                                // default cap (count and explicit zero exempt).
                                if opts.limit.is_none() && !count {
                                    opts.limit = Some(2);
                                }
                                let reference = Query::from_options(&opts).unwrap().unwrap();
                                let expected = reference.apply(rows.clone()).unwrap();
                                assert_eq!(actual, expected, "{opts:?}, support={support:?}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn default_limits_share_the_residual_query_path() {
        for default in [None, Some(0), Some(2)] {
            let plan = QueryPlan::new(None, default, FetchSupport::Paged("name"));
            assert_eq!(plan.post.as_ref().and_then(|q| q.limit), default);
            assert_eq!(plan.fetch.limit, default.filter(|&n| n != 0));
            assert_eq!(plan.page.limit, default.filter(|&n| n != 0));
            let client = QueryPlan::new(None, default, FetchSupport::Client);
            assert_eq!(client.post.as_ref().and_then(|q| q.limit), default);
            assert_eq!(client.fetch, FetchParams::default());
        }
        let mut opts = options();
        opts.limit = Some(0);
        let plan = plan(&opts, FetchSupport::Paged("name"));
        assert_eq!(plan.fetch.limit, None);
        assert_eq!(
            plan.post.unwrap().apply(vec![]).unwrap(),
            serde_json::json!([])
        );
    }

    #[test]
    fn client_queries_retain_default_limits_even_for_projection_only() {
        let mut opts = options();
        opts.fields = Some("name".into());
        let plan = plan(&opts, FetchSupport::Client);
        assert_eq!(plan.fetch, FetchParams::default());
        assert_eq!(plan.post.unwrap().limit, Some(2));
    }
}
