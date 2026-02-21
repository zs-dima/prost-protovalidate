use std::fmt;

use prost_protovalidate_types::{FieldPath, FieldPathElement, field_path_element};
use prost_reflect::{FieldDescriptor, Kind, Value};

/// A single instance where a validation rule was not met.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Violation {
    /// The dot-separated field path where the violation occurred (e.g. `email`, `home.lat`).
    pub field_path: String,

    /// The dot-separated rule path that was violated (e.g. `string.min_len`).
    pub rule_path: String,

    /// Machine-readable constraint identifier (e.g. `string.min_len`, `required`).
    pub rule_id: String,

    /// Human-readable violation message.
    pub message: String,

    /// The field descriptor for the violated field, if available.
    pub field_descriptor: Option<FieldDescriptor>,

    /// The field value that failed validation, when available.
    pub field_value: Option<Value>,

    /// The descriptor for the violated rule field, when available.
    pub rule_descriptor: Option<FieldDescriptor>,

    /// The value of the violated rule field, when available.
    pub rule_value: Option<Value>,

    /// Wire-compatible violation payload.
    pub proto: prost_protovalidate_types::Violation,
}

impl Violation {
    pub(crate) fn new(
        field_path: impl Into<String>,
        rule_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let rule_id = rule_id.into();
        let mut out = Self {
            field_path: field_path.into(),
            rule_path: rule_id.clone(),
            rule_id,
            message: message.into(),
            field_descriptor: None,
            field_value: None,
            rule_descriptor: None,
            rule_value: None,
            proto: prost_protovalidate_types::Violation::default(),
        };
        out.sync_proto();
        out
    }

    fn sync_proto(&mut self) {
        if self.proto.field.is_none() {
            self.proto.field = parse_path(&self.field_path);
        }
        self.proto.rule = parse_path(&self.rule_path);
        self.proto.rule_id = if self.rule_id.is_empty() {
            None
        } else {
            Some(self.rule_id.clone())
        };
        self.proto.message = if self.message.is_empty() {
            None
        } else {
            Some(self.message.clone())
        };
    }

    pub(crate) fn with_field_descriptor(mut self, desc: &FieldDescriptor) -> Self {
        self.field_descriptor = Some(desc.clone());
        if let Some(path) = self.proto.field.as_mut() {
            if let Some(first) = path.elements.first_mut() {
                let subscript = normalize_subscript_for_descriptor(first.subscript.take(), desc);
                *first = field_path_element_from_descriptor(desc);
                first.subscript = subscript;
            } else {
                path.elements.push(field_path_element_from_descriptor(desc));
            }
        } else {
            self.proto.field = Some(FieldPath {
                elements: vec![field_path_element_from_descriptor(desc)],
            });
        }
        self
    }

    pub(crate) fn with_field_value(mut self, value: Value) -> Self {
        self.field_value = Some(value);
        self
    }

    pub(crate) fn with_rule_path(mut self, rule_path: impl Into<String>) -> Self {
        self.rule_path = rule_path.into();
        self.sync_proto();
        self
    }

    pub(crate) fn with_rule_descriptor(mut self, descriptor: FieldDescriptor) -> Self {
        self.rule_descriptor = Some(descriptor);
        self
    }

    pub(crate) fn with_rule_value(mut self, value: Value) -> Self {
        self.rule_value = Some(value);
        self
    }

    pub(crate) fn mark_for_key(&mut self) {
        self.proto.for_key = Some(true);
    }

    /// Prepend a parent field path element.
    pub(crate) fn prepend_path(&mut self, parent: &str) {
        if parent.is_empty() {
            return;
        }
        self.field_path = prepend_path_string(parent, &self.field_path);
        prepend_proto_field_path(&mut self.proto.field, parent, None);
        self.sync_proto();
    }

    pub(crate) fn prepend_path_with_descriptor(
        &mut self,
        parent: &str,
        descriptor: &FieldDescriptor,
    ) {
        if parent.is_empty() {
            return;
        }
        self.field_path = prepend_path_string(parent, &self.field_path);
        prepend_proto_field_path(&mut self.proto.field, parent, Some(descriptor));
        self.sync_proto();
    }

    /// Prepend a parent rule path element.
    pub(crate) fn prepend_rule_path(&mut self, parent: &str) {
        if parent.is_empty() {
            return;
        }
        if self.rule_path.is_empty() {
            self.rule_path = parent.to_string();
        } else {
            self.rule_path = format!("{parent}.{}", self.rule_path);
        }
        self.sync_proto();
    }
}

fn field_path_element_from_descriptor(desc: &FieldDescriptor) -> FieldPathElement {
    let mut out = FieldPathElement {
        field_number: i32::try_from(desc.number()).ok(),
        field_name: Some(desc.name().to_string()),
        field_type: Some(if desc.is_group() {
            prost_types::field_descriptor_proto::Type::Group
        } else {
            kind_to_descriptor_type(&desc.kind())
        } as i32),
        key_type: None,
        value_type: None,
        subscript: None,
    };

    if desc.is_map() {
        if let Some(entry) = desc.kind().as_message() {
            if let Some(key_field) = entry.get_field_by_name("key") {
                out.key_type = Some(kind_to_descriptor_type(&key_field.kind()) as i32);
            }
            if let Some(value_field) = entry.get_field_by_name("value") {
                out.value_type = Some(kind_to_descriptor_type(&value_field.kind()) as i32);
            }
        }
    }

    out
}

fn normalize_subscript_for_descriptor(
    subscript: Option<field_path_element::Subscript>,
    desc: &FieldDescriptor,
) -> Option<field_path_element::Subscript> {
    let subscript = subscript?;

    if !desc.is_map() {
        return Some(subscript);
    }

    let kind = desc.kind();
    let Some(entry_desc) = kind.as_message() else {
        return Some(subscript);
    };
    let Some(key_field) = entry_desc.get_field_by_name("key") else {
        return Some(subscript);
    };

    match (subscript, key_field.kind()) {
        (
            field_path_element::Subscript::Index(value),
            Kind::Int32
            | Kind::Int64
            | Kind::Sint32
            | Kind::Sint64
            | Kind::Sfixed32
            | Kind::Sfixed64,
        ) => i64::try_from(value)
            .map(field_path_element::Subscript::IntKey)
            .ok()
            .or(Some(field_path_element::Subscript::Index(value))),
        (
            field_path_element::Subscript::Index(value),
            Kind::Uint32 | Kind::Uint64 | Kind::Fixed32 | Kind::Fixed64,
        ) => Some(field_path_element::Subscript::UintKey(value)),
        (subscript, _) => Some(subscript),
    }
}

fn kind_to_descriptor_type(kind: &Kind) -> prost_types::field_descriptor_proto::Type {
    match *kind {
        Kind::Double => prost_types::field_descriptor_proto::Type::Double,
        Kind::Float => prost_types::field_descriptor_proto::Type::Float,
        Kind::Int64 => prost_types::field_descriptor_proto::Type::Int64,
        Kind::Uint64 => prost_types::field_descriptor_proto::Type::Uint64,
        Kind::Int32 => prost_types::field_descriptor_proto::Type::Int32,
        Kind::Fixed64 => prost_types::field_descriptor_proto::Type::Fixed64,
        Kind::Fixed32 => prost_types::field_descriptor_proto::Type::Fixed32,
        Kind::Bool => prost_types::field_descriptor_proto::Type::Bool,
        Kind::String => prost_types::field_descriptor_proto::Type::String,
        Kind::Message(_) => prost_types::field_descriptor_proto::Type::Message,
        Kind::Bytes => prost_types::field_descriptor_proto::Type::Bytes,
        Kind::Uint32 => prost_types::field_descriptor_proto::Type::Uint32,
        Kind::Enum(_) => prost_types::field_descriptor_proto::Type::Enum,
        Kind::Sfixed32 => prost_types::field_descriptor_proto::Type::Sfixed32,
        Kind::Sfixed64 => prost_types::field_descriptor_proto::Type::Sfixed64,
        Kind::Sint32 => prost_types::field_descriptor_proto::Type::Sint32,
        Kind::Sint64 => prost_types::field_descriptor_proto::Type::Sint64,
    }
}

fn prepend_path_string(parent: &str, current: &str) -> String {
    if current.is_empty() {
        return parent.to_string();
    }
    if current.starts_with('[') {
        return format!("{parent}{current}");
    }
    format!("{parent}.{current}")
}

fn prepend_proto_field_path(
    path: &mut Option<FieldPath>,
    parent: &str,
    descriptor: Option<&FieldDescriptor>,
) {
    let Some(mut prefix) = parse_path(parent) else {
        return;
    };

    if let Some(descriptor) = descriptor {
        if let Some(first) = prefix.elements.first_mut() {
            let subscript = normalize_subscript_for_descriptor(first.subscript.take(), descriptor);
            *first = field_path_element_from_descriptor(descriptor);
            first.subscript = subscript;
        } else {
            prefix
                .elements
                .push(field_path_element_from_descriptor(descriptor));
        }
    }

    let Some(mut suffix) = path.take() else {
        *path = Some(prefix);
        return;
    };

    if let (Some(last_prefix), Some(first_suffix)) =
        (prefix.elements.last_mut(), suffix.elements.first())
    {
        if is_subscript_only_element(first_suffix) && last_prefix.subscript.is_none() {
            last_prefix.subscript.clone_from(&first_suffix.subscript);
            suffix.elements.remove(0);
        }
    }

    prefix.elements.extend(suffix.elements);
    *path = Some(prefix);
}

fn is_subscript_only_element(element: &FieldPathElement) -> bool {
    element.field_name.is_none()
        && element.field_number.is_none()
        && element.field_type.is_none()
        && element.key_type.is_none()
        && element.value_type.is_none()
        && element.subscript.is_some()
}

fn parse_path(path: &str) -> Option<FieldPath> {
    if path.is_empty() {
        return None;
    }

    let mut elements = Vec::new();
    for segment in split_segments(path) {
        let (name, subscripts) = split_name_and_subscripts(segment);

        if !name.is_empty() || subscripts.is_empty() {
            elements.push(FieldPathElement {
                field_name: if name.is_empty() { None } else { Some(name) },
                ..FieldPathElement::default()
            });
        }

        for (idx, subscript) in subscripts.into_iter().enumerate() {
            if idx == 0 && !elements.is_empty() {
                if let Some(last) = elements.last_mut() {
                    last.subscript = Some(subscript);
                }
            } else {
                elements.push(FieldPathElement {
                    subscript: Some(subscript),
                    ..FieldPathElement::default()
                });
            }
        }
    }

    Some(FieldPath { elements })
}

fn split_segments(path: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;

    for (idx, ch) in path.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => {
                segments.push(&path[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }

    if start < path.len() {
        segments.push(&path[start..]);
    }

    segments
}

fn split_name_and_subscripts(segment: &str) -> (String, Vec<field_path_element::Subscript>) {
    let name_end = segment.find('[').unwrap_or(segment.len());
    let name = segment[..name_end].to_string();
    let mut subscripts = Vec::new();
    let mut rest = &segment[name_end..];

    while let Some(open_idx) = rest.find('[') {
        let Some(close_rel) = rest[open_idx + 1..].find(']') else {
            break;
        };
        let close_idx = open_idx + 1 + close_rel;
        let token = &rest[open_idx + 1..close_idx];
        if let Some(subscript) = parse_subscript(token) {
            subscripts.push(subscript);
        }
        rest = &rest[close_idx + 1..];
    }

    (name, subscripts)
}

fn parse_subscript(token: &str) -> Option<field_path_element::Subscript> {
    if token.starts_with('"') && token.ends_with('"') && token.len() >= 2 {
        if let Ok(decoded) = serde_json::from_str::<String>(token) {
            return Some(field_path_element::Subscript::StringKey(decoded));
        }
    }

    if token.eq_ignore_ascii_case("true") {
        return Some(field_path_element::Subscript::BoolKey(true));
    }

    if token.eq_ignore_ascii_case("false") {
        return Some(field_path_element::Subscript::BoolKey(false));
    }

    if let Ok(index) = token.parse::<u64>() {
        return Some(field_path_element::Subscript::Index(index));
    }

    if let Ok(int_key) = token.parse::<i64>() {
        return Some(field_path_element::Subscript::IntKey(int_key));
    }

    None
}

fn field_path_string(path: Option<&FieldPath>) -> String {
    let Some(path) = path else {
        return String::new();
    };

    let mut out = String::new();
    for element in &path.elements {
        if let Some(name) = &element.field_name {
            if !name.is_empty() {
                if !out.is_empty() && !out.ends_with(']') {
                    out.push('.');
                }
                out.push_str(name);
            }
        }

        if let Some(subscript) = &element.subscript {
            out.push('[');
            match subscript {
                field_path_element::Subscript::Index(i)
                | field_path_element::Subscript::UintKey(i) => out.push_str(&i.to_string()),
                field_path_element::Subscript::BoolKey(b) => out.push_str(&b.to_string()),
                field_path_element::Subscript::IntKey(i) => out.push_str(&i.to_string()),
                field_path_element::Subscript::StringKey(s) => {
                    let encoded = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
                    out.push_str(&encoded);
                }
            }
            out.push(']');
        }
    }

    out
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rendered_path = if self.field_path.is_empty() {
            field_path_string(self.proto.field.as_ref())
        } else {
            self.field_path.clone()
        };

        if !rendered_path.is_empty() {
            write!(f, "{rendered_path}: ")?;
        }
        if !self.message.is_empty() {
            write!(f, "{}", self.message)
        } else if !self.rule_id.is_empty() {
            write!(f, "[{}]", self.rule_id)
        } else {
            write!(f, "[unknown]")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Violation, field_path_string};
    use pretty_assertions::assert_eq;

    fn descriptor_field(message: &str, field: &str) -> prost_reflect::FieldDescriptor {
        prost_protovalidate_types::DESCRIPTOR_POOL
            .get_message_by_name(message)
            .and_then(|message| message.get_field_by_name(field))
            .expect("descriptor field must exist")
    }

    #[test]
    fn prepend_path_with_descriptor_preserves_nested_descriptor_metadata() {
        let parent = descriptor_field("buf.validate.FieldRules", "string");
        let child = descriptor_field("buf.validate.StringRules", "min_len");

        let mut violation = Violation::new("min_len", "string.min_len", "must be >= 1")
            .with_field_descriptor(&child);
        violation.prepend_path_with_descriptor("string", &parent);

        let path = violation
            .proto
            .field
            .as_ref()
            .expect("field path should be populated");
        assert_eq!(path.elements.len(), 2);

        let parent_element = &path.elements[0];
        assert_eq!(parent_element.field_name.as_deref(), Some("string"));
        assert_eq!(
            parent_element.field_number,
            i32::try_from(parent.number()).ok()
        );

        let child_element = &path.elements[1];
        assert_eq!(child_element.field_name.as_deref(), Some("min_len"));
        assert_eq!(
            child_element.field_number,
            i32::try_from(child.number()).ok()
        );
    }

    #[test]
    fn field_path_string_round_trips_json_escaped_subscripts() {
        let raw = "line\n\t\"quote\"\\slash";
        let encoded = serde_json::to_string(raw).expect("json encoding should succeed");
        let mut violation = Violation::new(format!("[{encoded}]"), "string.min_len", "bad");
        violation.prepend_path("rules");

        let rendered = field_path_string(violation.proto.field.as_ref());
        assert_eq!(rendered, format!("rules[{encoded}]"));
    }

    #[test]
    fn field_path_string_uses_proper_json_escaping_for_map_keys() {
        let raw = "line\nvalue";
        let encoded = serde_json::to_string(raw).expect("json encoding should succeed");
        let violation = Violation::new(
            format!("pattern[{encoded}]"),
            "string.pattern",
            "must match pattern",
        );
        assert_eq!(
            field_path_string(violation.proto.field.as_ref()),
            format!("pattern[{encoded}]")
        );
    }

    #[test]
    fn violation_display_prefers_field_and_message_then_rule_id_then_unknown() {
        let with_path_and_message = Violation::new("one.two", "bar", "foo");
        assert_eq!(with_path_and_message.to_string(), "one.two: foo");

        let message_only = Violation::new("", "bar", "foo");
        assert_eq!(message_only.to_string(), "foo");

        let rule_id_only = Violation::new("", "bar", "");
        assert_eq!(rule_id_only.to_string(), "[bar]");

        let unknown = Violation::new("", "", "");
        assert_eq!(unknown.to_string(), "[unknown]");
    }
}
