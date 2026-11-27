//! Schema inference: map a JSON document to its shape without retaining
//! any sensitive data.

use serde_json::Value;

/// Replace every value in `json` with a type placeholder (`<string>`,
/// `<int>`, `<float>`, `<bool>`, `<null>`), recursing into objects and
/// inferring arrays from their first element.
///
/// ```text
/// [{"id": 1, "name": "alice", "admin": false}]
/// → [{"id": <int>, "name": <string>, "admin": <bool>}]
/// ```
pub fn infer_schema(json: &Value) -> Value {
    match json {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), infer_schema(v)))
                .collect(),
        ),
        Value::Array(items) => match items.first() {
            Some(first) => Value::Array(vec![infer_schema(first)]),
            None => Value::String("<empty array>".to_owned()),
        },
        Value::String(_) => Value::String("<string>".to_owned()),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                Value::String("<int>".to_owned())
            } else {
                Value::String("<float>".to_owned())
            }
        }
        Value::Bool(_) => Value::String("<bool>".to_owned()),
        Value::Null => Value::String("<null>".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_object_and_array() {
        let doc = json!({
            "id": 7,
            "email": "a@b.com",
            "score": 9.5,
            "admin": false,
            "meta": {"joined": "2024-01-01", "tags": ["x", "y"]},
            "empty": [],
            "gone": null
        });
        assert_eq!(
            infer_schema(&doc),
            json!({
                "id": "<int>",
                "email": "<string>",
                "score": "<float>",
                "admin": "<bool>",
                "meta": {"joined": "<string>", "tags": ["<string>"]},
                "empty": "<empty array>",
                "gone": "<null>"
            })
        );
    }

    #[test]
    fn no_sensitive_data_retained() {
        let doc = json!([{"secret_token": "hunter2", "n": 1}]);
        let schema = infer_schema(&doc);
        assert_eq!(schema, json!([{"secret_token": "<string>", "n": "<int>"}]));
    }
}
