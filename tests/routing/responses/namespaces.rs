//! Recorded namespaces response fixtures.

use serde_json::{json, Value};

pub(super) fn receipt_fixture(command: &str, args: &Value) -> Value {
    let target = &args["target"];
    if command == "namespace_delete" {
        let recursive = args["recursive"] == true;
        let mut deleted = vec![
            json!({"id":target["id"],"name":target["name"],"path":target["path"],
            "parent":target["parent"],"type":"Namespace","address":null}),
        ];
        let mut counts = json!({"Namespace":1});
        if recursive {
            deleted.push(
                json!({"id":"10","name":"helper","path":"app::Widget::helper",
                "parent":"app::Widget","type":"Function","address":"0x1000"}),
            );
            counts["Function"] = json!(1);
        }
        json!({"status":"deleted","target":target,"recursive":recursive,
            "count":deleted.len(),"deleted":deleted,"counts":counts})
    } else {
        let mut after = target.clone();
        let status = if command == "namespace_rename" {
            after["name"] = args["new_name"].clone();
            "renamed"
        } else {
            after["parent"] = args["parent"]["path"].clone();
            "moved"
        };
        after["path"] = json!(match after["parent"].as_str() {
            Some(parent) => format!("{}::{}", parent, after["name"].as_str().unwrap()),
            None => after["name"].as_str().unwrap().to_owned(),
        });
        let status = if after == *target {
            "unchanged"
        } else {
            status
        };
        json!({"status":status,"before":target,"after":after,"function_changes":[]})
    }
}
