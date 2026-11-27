//! Tree-sitter AST walk extracting Supabase client call sites and fetch
//! endpoints (with constant folding and template-literal extraction).

use super::Discovery;
use std::collections::HashMap;
use tree_sitter::{Language, Node, Parser, TreeCursor};

/// Strip surrounding quotes from a string-literal node's text.
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && (bytes[0] == b'"' || bytes[0] == b'\'') {
        text[1..text.len() - 1].to_owned()
    } else {
        text.to_owned()
    }
}

/// Collect top-level string-literal bindings (`const base = '/api/v2'`).
fn collect_vars(cursor: &mut TreeCursor, source: &str, vars: &mut HashMap<String, String>) {
    if cursor.node().kind() == "variable_declarator" {
        if let (Some(name), Some(value)) = (
            cursor.node().child_by_field_name("name"),
            cursor.node().child_by_field_name("value"),
        ) {
            if name.kind() == "identifier" && value.kind() == "string" {
                vars.insert(
                    source[name.byte_range()].to_owned(),
                    unquote(&source[value.byte_range()]),
                );
            }
        }
    }
    if cursor.goto_first_child() {
        loop {
            collect_vars(cursor, source, vars);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Resolve a node to its string value: string literals, known constants,
/// `+` concatenations, and template literals. Template substitutions become
/// `{param}` unless they resolve to a known constant.
fn resolve(node: Node, source: &str, vars: &HashMap<String, String>) -> Option<String> {
    match node.kind() {
        "string" => Some(unquote(&source[node.byte_range()])),
        "identifier" => vars.get(&source[node.byte_range()]).cloned(),
        "binary_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let op = node.child_by_field_name("operator")?;
            if &source[op.byte_range()] != "+" {
                return None;
            }
            Some(format!(
                "{}{}",
                resolve(left, source, vars)?,
                resolve(right, source, vars)?
            ))
        }
        "template_string" => {
            let mut out = String::new();
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    match cursor.node().kind() {
                        "string_fragment" => {
                            out.push_str(&source[cursor.node().byte_range()]);
                        }
                        "template_substitution" => {
                            let sub = resolve(cursor.node(), source, vars)
                                .unwrap_or_else(|| "{param}".to_owned());
                            out.push_str(&sub);
                        }
                        _ => {}
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            Some(out)
        }
        // Resolve the expression inside `${…}`; unknown expressions yield
        // None and the caller substitutes `{param}`.
        "template_substitution" => {
            let inner = node.named_child(0)?;
            resolve(inner, source, vars)
        }
        _ => None,
    }
}

/// Extract a `fetch('<path>')` endpoint from a call expression.
fn endpoint(node: Node, source: &str, vars: &HashMap<String, String>) -> Option<Discovery> {
    let callee = node.child_by_field_name("function")?;
    let callee_text = &source[callee.byte_range()];
    if callee_text != "fetch" && !callee_text.ends_with(".fetch") {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let path = resolve(args.named_child(0)?, source, vars)?;
    if !path.starts_with('/') {
        return None;
    }
    let mut method = "GET".to_owned();
    if let Some(opts) = args.named_child(1) {
        let mut cursor = opts.walk();
        if cursor.goto_first_child() {
            loop {
                let pair = cursor.node();
                if pair.kind() == "pair" {
                    let key = pair.child_by_field_name("key");
                    let value = pair.child_by_field_name("value");
                    if let (Some(k), Some(v)) = (key, value) {
                        if &source[k.byte_range()] == "method" && v.kind() == "string" {
                            method = unquote(&source[v.byte_range()]).to_uppercase();
                        }
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    Some(Discovery::Endpoint { path, method })
}

/// Walk the whole tree, extracting matching call expressions.
fn walk(
    cursor: &mut TreeCursor,
    source: &str,
    vars: &HashMap<String, String>,
    out: &mut Vec<Discovery>,
) {
    if cursor.node().kind() == "call_expression" {
        if let Some(d) = classify(cursor.node(), source) {
            out.push(d);
        } else if let Some(d) = endpoint(cursor.node(), source, vars) {
            out.push(d);
        }
    }
    if cursor.goto_first_child() {
        loop {
            walk(cursor, source, vars, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Classify one `call_expression` node as a Supabase client call.
fn classify(node: Node, source: &str) -> Option<Discovery> {
    let callee = node.child_by_field_name("function")?;
    let callee_text = &source[callee.byte_range()];
    let first_arg = || {
        node.child_by_field_name("arguments")
            .and_then(|args| args.named_child(0))
            .filter(|a| a.kind() == "string")
            .map(|a| unquote(&source[a.byte_range()]))
    };

    // storage.from('<bucket>') — object of the member expression is `storage`.
    if let Some(obj) = callee.child_by_field_name("object") {
        let obj_text = &source[obj.byte_range()];
        if obj_text.ends_with("storage") {
            let member = callee.child_by_field_name("property")?;
            if &source[member.byte_range()] == "from" {
                return first_arg().map(|name| Discovery::Bucket { name });
            }
        }
    }

    let property = callee.child_by_field_name("property")?;
    let prop_text = &source[property.byte_range()];
    match prop_text {
        "from" => first_arg().map(|name| Discovery::Table { name }),
        "rpc" => {
            let name = first_arg()?;
            let params = node
                .child_by_field_name("arguments")
                .and_then(|args| args.named_child(1))
                .map(|a| source[a.byte_range()].to_owned());
            Some(Discovery::Rpc { name, params })
        }
        "invoke" if callee_text.contains("functions") => {
            first_arg().map(|name| Discovery::EdgeFunction { name })
        }
        _ => None,
    }
}

fn parse(source: &str, language: Language) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

/// Parse `source` as JS, then TS/TSX fallback, and extract call sites.
pub fn discover_ast(source: &str) -> Vec<Discovery> {
    let tree = parse(source, tree_sitter_javascript::LANGUAGE.into())
        .or_else(|| parse(source, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()));
    let Some(tree) = tree else {
        return Vec::new();
    };
    // Pass 1: string-literal constants for folding. Pass 2: call sites.
    let mut vars = HashMap::new();
    let mut cursor = tree.walk();
    collect_vars(&mut cursor, source, &mut vars);
    let mut out = Vec::new();
    let mut cursor = tree.walk();
    walk(&mut cursor, source, &vars, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_folding_and_template_literals() {
        let src = r#"
            const base = '/api/v2';
            fetch(base + '/users');
            fetch(`/users/${userId}`, { method: 'post' });
            fetch(base);
            fetch(other + '/x');
        "#;
        assert_eq!(
            discover_ast(src),
            vec![
                Discovery::Endpoint {
                    path: "/api/v2/users".to_owned(),
                    method: "GET".to_owned(),
                },
                Discovery::Endpoint {
                    path: "/users/{param}".to_owned(),
                    method: "POST".to_owned(),
                },
                Discovery::Endpoint {
                    path: "/api/v2".to_owned(),
                    method: "GET".to_owned(),
                },
            ]
        );
    }
}
