//! Deliberately limited static JavaScript source-to-sink analysis.

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::SourceType;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Flow {
    pub source: String,
    pub sink: String,
    pub line: u32,
}

/// Track direct URL-controlled sources through simple variable assignments
/// into common HTML/script execution sinks. This does not model control flow,
/// object properties, sanitizers, framework templates, or runtime behavior.
pub(super) fn source_to_sink(source: &str) -> Vec<Flow> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::unambiguous()).parse();
    if !parsed.diagnostics.is_empty() {
        return Vec::new();
    }
    let mut analyzer = Analyzer {
        line_starts: std::iter::once(0)
            .chain(
                source
                    .match_indices('\n')
                    .map(|(index, _)| (index + 1) as u32),
            )
            .collect(),
        ..Analyzer::default()
    };
    analyzer.visit_program(&parsed.program);
    analyzer.flows
}

#[derive(Default)]
struct Analyzer {
    /// Variable name to the URL-controlled source it was assigned from.
    tainted: HashMap<String, &'static str>,
    flows: Vec<Flow>,
    line_starts: Vec<u32>,
}

impl Analyzer {
    /// The first URL-controlled source in `expression`, if any. A literal or
    /// a value computed only from literals yields `None`.
    fn taint_source(&self, expression: &Expression<'_>) -> Option<&'static str> {
        let mut visitor = TaintVisitor {
            variables: &self.tainted,
            source: None,
        };
        visitor.visit_expression(expression);
        visitor.source
    }

    fn add_flow(&mut self, sink: &str, source: &'static str, offset: u32) {
        let line = self
            .line_starts
            .partition_point(|start| *start <= offset)
            .max(1) as u32;
        if !self
            .flows
            .iter()
            .any(|flow| flow.sink == sink && flow.line == line && flow.source == source)
        {
            self.flows.push(Flow {
                source: source.to_owned(),
                sink: sink.to_owned(),
                line,
            });
        }
    }
}

impl<'a> Visit<'a> for Analyzer {
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(id) = &node.id {
            let source = node.init.as_ref().and_then(|init| self.taint_source(init));
            if let Some(source) = source {
                self.tainted.insert(id.name.to_string(), source);
            } else {
                // A later safe (or uninitialized) declaration must not inherit
                // taint from another variable with the same identifier.
                self.tainted.remove(id.name.as_str());
            }
        }
        walk::walk_variable_declarator(self, node);
    }

    fn visit_assignment_expression(&mut self, node: &AssignmentExpression<'a>) {
        let source = self.taint_source(&node.right);
        if let Some(target) = node.left.as_member_expression() {
            if let Some(source) = source {
                if let Some(sink) = member_property(target).filter(|name| is_sink(name)) {
                    self.add_flow(sink, source, node.span.start);
                }
            }
        } else if let AssignmentTarget::AssignmentTargetIdentifier(id) = &node.left {
            if let Some(source) = source {
                self.tainted.insert(id.name.to_string(), source);
            } else {
                self.tainted.remove(id.name.as_str());
            }
        }
        walk::walk_assignment_expression(self, node);
    }

    fn visit_call_expression(&mut self, node: &CallExpression<'a>) {
        if let Some(sink) =
            member_property_from_expression(&node.callee).filter(|name| is_call_sink(name))
        {
            let source = node.arguments.iter().find_map(|arg| {
                let expression = match arg {
                    Argument::SpreadElement(spread) => &spread.argument,
                    arg => arg.to_expression(),
                };
                self.taint_source(expression)
            });
            if let Some(source) = source {
                self.add_flow(sink, source, node.span.start);
            }
        }
        walk::walk_call_expression(self, node);
    }
}

struct TaintVisitor<'a> {
    variables: &'a HashMap<String, &'static str>,
    source: Option<&'static str>,
}

impl TaintVisitor<'_> {
    fn mark(&mut self, source: &'static str) {
        self.source.get_or_insert(source);
    }
}

impl<'a> Visit<'a> for TaintVisitor<'a> {
    fn visit_static_member_expression(&mut self, node: &StaticMemberExpression<'a>) {
        let prop = node.property.name.as_str();
        let object = member_property_from_expression(&node.object).unwrap_or_default();
        let root = expression_root(&node.object);
        if root == Some("location") || (root == Some("window") && object == "location") {
            match prop {
                "search" => self.mark("location.search"),
                "hash" => self.mark("location.hash"),
                "href" => self.mark("location.href"),
                _ => {}
            }
        } else if root == Some("document") && prop == "referrer" {
            self.mark("document.referrer");
        } else if root == Some("window") && prop == "name" {
            self.mark("window.name");
        }
        walk::walk_static_member_expression(self, node);
    }

    fn visit_computed_member_expression(&mut self, node: &ComputedMemberExpression<'a>) {
        if expression_root(&node.object) == Some("location") {
            if let Expression::StringLiteral(value) = &node.expression {
                match value.value.as_str() {
                    Some("search") => self.mark("location.search"),
                    Some("hash") => self.mark("location.hash"),
                    _ => {}
                }
            }
        }
        walk::walk_computed_member_expression(self, node);
    }

    fn visit_identifier_reference(&mut self, node: &IdentifierReference<'a>) {
        if let Some(source) = self.variables.get(node.name.as_str()) {
            self.mark(source);
        }
    }
}

fn expression_root<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        Expression::StaticMemberExpression(member) => expression_root(&member.object),
        Expression::ComputedMemberExpression(member) => expression_root(&member.object),
        _ => None,
    }
}

fn member_property_from_expression<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
        _ => None,
    }
}

fn member_property<'a>(member: &MemberExpression<'a>) -> Option<&'a str> {
    match member {
        MemberExpression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
        MemberExpression::ComputedMemberExpression(member) => match &member.expression {
            Expression::StringLiteral(value) => value.value.as_str(),
            _ => None,
        },
        MemberExpression::PrivateFieldExpression(_) => None,
    }
}

fn is_sink(property: &str) -> bool {
    matches!(property, "innerHTML" | "outerHTML")
}

fn is_call_sink(property: &str) -> bool {
    matches!(property, "write" | "writeln" | "insertAdjacentHTML")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_location_flow_through_variable_to_html_sink() {
        let flows =
            source_to_sink("const input = location.search; document.body.innerHTML = input;");
        assert_eq!(
            flows,
            [Flow {
                source: "location.search".into(),
                sink: "innerHTML".into(),
                line: 1,
            }]
        );
    }

    #[test]
    fn detects_direct_and_call_sinks_but_not_untainted_values() {
        let flows = source_to_sink("document.write(location.hash); element.insertAdjacentHTML('beforeend', location.search);");
        assert_eq!(
            flows
                .iter()
                .map(|flow| flow.sink.as_str())
                .collect::<Vec<_>>(),
            ["write", "insertAdjacentHTML"]
        );
        assert!(source_to_sink("document.body.innerHTML = 'safe'; eval('safe');").is_empty());
        assert!(
            source_to_sink("const input = document.title; target.innerHTML = input;").is_empty()
        );
    }

    #[test]
    fn static_string_never_reaches_a_sink() {
        assert!(
            source_to_sink(r#"document.getElementById("out").innerHTML = "static string";"#)
                .is_empty()
        );
    }

    #[test]
    fn location_hash_into_inner_html_fires_exactly_once() {
        let flows = source_to_sink(r#"document.getElementById("out").innerHTML = location.hash;"#);
        assert_eq!(
            flows,
            [Flow {
                source: "location.hash".into(),
                sink: "innerHTML".into(),
                line: 1,
            }]
        );
    }

    #[test]
    fn safe_reassignment_clears_taint_before_a_sink() {
        assert!(source_to_sink(
            "let input = location.hash; input = 'safe'; target.innerHTML = input;"
        )
        .is_empty());
    }

    #[test]
    fn only_allowlisted_attacker_controlled_sources_reach_sinks() {
        for source in [
            "location.search",
            "location.hash",
            "location.href",
            "document.referrer",
            "window.name",
        ] {
            let flows = source_to_sink(&format!("document.write({source});"));
            assert_eq!(flows.len(), 1, "expected an allowlisted source: {source}");
        }

        for source in [
            "document.URL",
            "document.documentURI",
            "window.location.pathname",
            "document.title",
        ] {
            let flows = source_to_sink(&format!("document.write({source});"));
            assert!(flows.is_empty(), "unexpected source accepted: {source}");
        }
    }

    #[test]
    fn invalid_javascript_is_ignored() {
        assert!(
            source_to_sink("const = location.search; target.innerHTML = location.search;")
                .is_empty()
        );
    }
}
