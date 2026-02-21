use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cel::extractors::{Arguments, This};
use cel::objects::Key as CelKey;
use cel::{
    Context, ExecutionError as CelExecutionError, FunctionContext, Program, Value as CelValue,
};
use chrono::{FixedOffset, Utc};
use prost_reflect::{DynamicMessage, FieldDescriptor, MessageDescriptor, ReflectMessage};
use prost_types::Timestamp;

use crate::config::ValidationConfig;
use crate::error::{CompilationError, Error, RuntimeError, ValidationError};
use crate::violation::Violation;

use super::super::rules::string as string_rules;
use super::{Evaluator, MessageEvaluator};

pub(crate) struct CelRuleProgram {
    pub rule_id: String,
    pub message: Option<String>,
    pub rule_path: String,
    pub program: Program,
    pub rule_binding: Option<CelValue>,
    pub rules_binding: Option<CelValue>,
    pub rule_descriptor: Option<FieldDescriptor>,
    pub rule_value: Option<prost_reflect::Value>,
}

impl CelRuleProgram {
    fn evaluate_message_with_this(
        &self,
        msg: &DynamicMessage,
        cfg: &ValidationConfig,
    ) -> Result<Option<Violation>, Error> {
        self.evaluate_with_this_value(reflect_message_to_cel(msg)?, cfg)
    }

    fn evaluate_value_with_this(
        &self,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<Option<Violation>, Error> {
        self.evaluate_with_this_value(reflect_value_to_cel(val)?, cfg)
    }

    fn evaluate_with_this_value(
        &self,
        this: CelValue,
        cfg: &ValidationConfig,
    ) -> Result<Option<Violation>, Error> {
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("this", this);

        let now = (cfg.now_fn)();
        ctx.add_variable("now", timestamp_to_cel(&now)?)
            .map_err(|e| RuntimeError {
                cause: format!("failed to bind CEL variable `now`: {e}"),
            })?;
        if let Some(rule) = &self.rule_binding {
            ctx.add_variable_from_value("rule", rule.clone());
        }
        if let Some(rules) = &self.rules_binding {
            ctx.add_variable_from_value("rules", rules.clone());
        }

        let value = self.program.execute(&ctx).map_err(|e| RuntimeError {
            cause: format!("failed to execute CEL rule `{}`: {e}", self.rule_id),
        })?;

        match value {
            CelValue::Bool(true) => Ok(None),
            CelValue::Bool(false) => Ok(Some(
                self.with_rule_metadata(
                    Violation::new(
                        "",
                        self.rule_id.clone(),
                        self.message
                            .clone()
                            .unwrap_or_else(|| "validation failed".to_string()),
                    )
                    .with_rule_path(self.rule_path.clone()),
                ),
            )),
            CelValue::String(msg) => {
                let msg = msg.as_ref().clone();
                if msg.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(
                        self.with_rule_metadata(
                            Violation::new(
                                "",
                                self.rule_id.clone(),
                                self.message.clone().unwrap_or(msg),
                            )
                            .with_rule_path(self.rule_path.clone()),
                        ),
                    ))
                }
            }
            other => Err(RuntimeError {
                cause: format!(
                    "CEL rule `{}` returned unsupported type `{}` (expected bool or string)",
                    self.rule_id,
                    other.type_of(),
                ),
            }
            .into()),
        }
    }

    fn with_rule_metadata(&self, mut violation: Violation) -> Violation {
        if let Some(rule_desc) = &self.rule_descriptor {
            violation = violation.with_rule_descriptor(rule_desc.clone());
        }
        if let Some(rule_value) = &self.rule_value {
            violation = violation.with_rule_value(rule_value.clone());
        }
        violation
    }
}

fn build_cel_context() -> Context<'static> {
    let mut ctx = Context::default();
    register_protovalidate_functions(&mut ctx);
    ctx
}

fn register_protovalidate_functions(ctx: &mut Context<'_>) {
    ctx.add_function("unique", cel_unique);
    ctx.add_function("getField", cel_get_field);
    ctx.add_function("isNan", cel_is_nan);
    ctx.add_function("isInf", cel_is_inf);
    ctx.add_function("isHostname", cel_is_hostname);
    ctx.add_function("isEmail", cel_is_email);
    ctx.add_function("isIp", cel_is_ip);
    ctx.add_function("isIpPrefix", cel_is_ip_prefix);
    ctx.add_function("isUri", cel_is_uri);
    ctx.add_function("isUriRef", cel_is_uri_ref);
    ctx.add_function("isHostAndPort", cel_is_host_and_port);
    ctx.add_function("startsWith", cel_starts_with);
    ctx.add_function("endsWith", cel_ends_with);
}

fn call_args_without_this<'a>(
    ftx: &FunctionContext<'_, '_>,
    args: &'a [CelValue],
) -> Result<&'a [CelValue], CelExecutionError> {
    if ftx.this.is_some() {
        return Ok(args);
    }

    if args.is_empty() {
        return Err(CelExecutionError::NoSuchOverload);
    }
    Ok(&args[1..])
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum UniqueKey {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(u64),
    String(Arc<String>),
    Bytes(Arc<Vec<u8>>),
}

fn unique_key(value: &CelValue) -> Option<UniqueKey> {
    match value {
        CelValue::Bool(v) => Some(UniqueKey::Bool(*v)),
        CelValue::Int(v) => Some(UniqueKey::Int(*v)),
        CelValue::UInt(v) => Some(UniqueKey::Uint(*v)),
        CelValue::Float(v) => Some(UniqueKey::Float(v.to_bits())),
        CelValue::String(v) => Some(UniqueKey::String(Arc::clone(v))),
        CelValue::Bytes(v) => Some(UniqueKey::Bytes(Arc::clone(v))),
        _ => None,
    }
}

fn cel_unique(This(this): This<CelValue>) -> Result<bool, CelExecutionError> {
    let CelValue::List(values) = this else {
        return Err(CelExecutionError::NoSuchOverload);
    };

    let mut seen = HashSet::with_capacity(values.len());
    for value in values.iter() {
        let Some(key) = unique_key(value) else {
            return Err(CelExecutionError::NoSuchOverload);
        };
        if !seen.insert(key) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::needless_pass_by_value)]
fn cel_get_field(
    This(this): This<CelValue>,
    field_name: Arc<String>,
) -> Result<CelValue, CelExecutionError> {
    let CelValue::Map(map) = this else {
        return Err(CelExecutionError::NoSuchOverload);
    };
    map.get(&CelKey::String(Arc::clone(&field_name)))
        .cloned()
        .ok_or_else(|| CelExecutionError::no_such_key(field_name.as_ref()))
}

fn cel_is_nan(
    ftx: &FunctionContext<'_, '_>,
    This(value): This<f64>,
    Arguments(args): Arguments,
) -> Result<bool, CelExecutionError> {
    let tail = call_args_without_this(ftx, args.as_slice())?;
    if !tail.is_empty() {
        return Err(CelExecutionError::NoSuchOverload);
    }
    Ok(value.is_nan())
}

fn cel_is_inf(
    ftx: &FunctionContext<'_, '_>,
    This(value): This<f64>,
    Arguments(args): Arguments,
) -> Result<bool, CelExecutionError> {
    let tail = call_args_without_this(ftx, args.as_slice())?;
    let sign = match tail {
        [] => 0,
        [CelValue::Int(sign)] => *sign,
        _ => return Err(CelExecutionError::NoSuchOverload),
    };

    Ok(value.is_infinite()
        && (sign == 0
            || (sign > 0 && value.is_sign_positive())
            || (sign < 0 && value.is_sign_negative())))
}

fn cel_is_hostname(This(value): This<Arc<String>>) -> bool {
    string_rules::is_hostname(value.as_ref())
}

fn cel_is_email(This(value): This<Arc<String>>) -> bool {
    string_rules::is_email(value.as_ref())
}

fn cel_is_ip(
    ftx: &FunctionContext<'_, '_>,
    This(value): This<Arc<String>>,
    Arguments(args): Arguments,
) -> Result<bool, CelExecutionError> {
    let tail = call_args_without_this(ftx, args.as_slice())?;
    match tail {
        [] => Ok(string_rules::is_ip_with_version(value.as_ref(), 0)),
        [CelValue::Int(version)] => Ok(string_rules::is_ip_with_version(value.as_ref(), *version)),
        _ => Err(CelExecutionError::NoSuchOverload),
    }
}

fn cel_is_ip_prefix(
    ftx: &FunctionContext<'_, '_>,
    This(value): This<Arc<String>>,
    Arguments(args): Arguments,
) -> Result<bool, CelExecutionError> {
    let tail = call_args_without_this(ftx, args.as_slice())?;
    match tail {
        [] => Ok(string_rules::is_ip_prefix_with_options(
            value.as_ref(),
            0,
            false,
        )),
        [CelValue::Int(version)] => Ok(string_rules::is_ip_prefix_with_options(
            value.as_ref(),
            *version,
            false,
        )),
        [CelValue::Bool(strict)] => Ok(string_rules::is_ip_prefix_with_options(
            value.as_ref(),
            0,
            *strict,
        )),
        [CelValue::Int(version), CelValue::Bool(strict)] => Ok(
            string_rules::is_ip_prefix_with_options(value.as_ref(), *version, *strict),
        ),
        _ => Err(CelExecutionError::NoSuchOverload),
    }
}

fn cel_is_uri(This(value): This<Arc<String>>) -> bool {
    string_rules::is_uri(value.as_ref())
}

fn cel_is_uri_ref(This(value): This<Arc<String>>) -> bool {
    string_rules::is_uri_ref(value.as_ref())
}

fn cel_is_host_and_port(This(value): This<Arc<String>>, port_required: bool) -> bool {
    string_rules::is_host_and_port(value.as_ref(), port_required)
}

fn cel_starts_with(
    This(this): This<CelValue>,
    prefix: CelValue,
) -> Result<bool, CelExecutionError> {
    match (this, prefix) {
        (CelValue::String(value), CelValue::String(prefix)) => {
            Ok(value.starts_with(prefix.as_ref()))
        }
        (CelValue::Bytes(value), CelValue::Bytes(prefix)) => {
            Ok(value.starts_with(prefix.as_slice()))
        }
        _ => Err(CelExecutionError::NoSuchOverload),
    }
}

fn cel_ends_with(This(this): This<CelValue>, suffix: CelValue) -> Result<bool, CelExecutionError> {
    match (this, suffix) {
        (CelValue::String(value), CelValue::String(suffix)) => Ok(value.ends_with(suffix.as_ref())),
        (CelValue::Bytes(value), CelValue::Bytes(suffix)) => Ok(value.ends_with(suffix.as_slice())),
        _ => Err(CelExecutionError::NoSuchOverload),
    }
}

fn timestamp_to_cel(ts: &Timestamp) -> Result<cel::Timestamp, RuntimeError> {
    if !(0..=999_999_999).contains(&ts.nanos) {
        return Err(RuntimeError {
            cause: format!(
                "invalid timestamp nanos `{}` for CEL `now` binding",
                ts.nanos
            ),
        });
    }

    #[allow(clippy::cast_sign_loss)]
    let nanos_u32 = ts.nanos as u32;
    let Some(utc_dt) = chrono::DateTime::<Utc>::from_timestamp(ts.seconds, nanos_u32) else {
        return Err(RuntimeError {
            cause: format!(
                "invalid timestamp `{}` seconds / `{}` nanos for CEL `now` binding",
                ts.seconds, ts.nanos
            ),
        });
    };
    let Some(offset) = FixedOffset::east_opt(0) else {
        return Err(RuntimeError {
            cause: "failed to construct UTC fixed offset for CEL timestamp".to_string(),
        });
    };
    let fixed = utc_dt.with_timezone(&offset);
    Ok(cel::Timestamp(fixed))
}

/// CEL evaluator for message-level expressions.
pub(crate) struct CelMessageEval {
    pub programs: Vec<CelRuleProgram>,
}

impl MessageEvaluator for CelMessageEval {
    fn tautology(&self) -> bool {
        self.programs.is_empty()
    }

    fn evaluate_message(&self, msg: &DynamicMessage, cfg: &ValidationConfig) -> Result<(), Error> {
        let mut violations = Vec::new();
        for program in &self.programs {
            if let Some(violation) = program.evaluate_message_with_this(msg, cfg)? {
                violations.push(violation);
                if cfg.fail_fast {
                    break;
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

/// CEL evaluator for field-level expressions.
pub(crate) struct CelFieldEval {
    pub programs: Vec<CelRuleProgram>,
}

impl Evaluator for CelFieldEval {
    fn tautology(&self) -> bool {
        self.programs.is_empty()
    }

    fn evaluate(
        &self,
        _msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let mut violations = Vec::new();
        for program in &self.programs {
            if let Some(violation) = program.evaluate_value_with_this(val, cfg)? {
                violations.push(violation);
                if cfg.fail_fast {
                    break;
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(violations).into())
        }
    }
}

pub(crate) fn compile_programs(
    simple_exprs: &[String],
    rules: &[prost_protovalidate_types::Rule],
    path_prefix: &str,
) -> Result<Vec<CelRuleProgram>, CompilationError> {
    let mut out = Vec::with_capacity(simple_exprs.len() + rules.len());

    for (idx, expr) in simple_exprs.iter().enumerate() {
        let program = Program::compile(expr).map_err(|e| CompilationError {
            cause: format!("failed to compile CEL expression `{expr}`: {e}"),
        })?;
        out.push(CelRuleProgram {
            rule_id: expr.clone(),
            message: None,
            rule_path: format!("{path_prefix}_expression[{idx}]"),
            program,
            rule_binding: None,
            rules_binding: None,
            rule_descriptor: None,
            rule_value: None,
        });
    }

    for (idx, rule) in rules.iter().enumerate() {
        let expr = rule.expression.clone().ok_or_else(|| CompilationError {
            cause: format!("missing CEL expression in `{path_prefix}` rule at index {idx}",),
        })?;

        let program = Program::compile(&expr).map_err(|e| CompilationError {
            cause: format!("failed to compile CEL rule `{expr}`: {e}"),
        })?;

        out.push(CelRuleProgram {
            rule_id: rule.id.clone().unwrap_or_else(|| expr.clone()),
            message: rule.message.clone(),
            rule_path: format!("{path_prefix}[{idx}]"),
            program,
            rule_binding: None,
            rules_binding: None,
            rule_descriptor: None,
            rule_value: None,
        });
    }

    Ok(out)
}

pub(crate) fn message_to_cel_value(msg: &DynamicMessage) -> Result<CelValue, CompilationError> {
    reflect_message_to_cel(msg).map_err(|err| CompilationError { cause: err.cause })
}

pub(crate) fn value_to_cel_value(
    value: &prost_reflect::Value,
) -> Result<CelValue, CompilationError> {
    reflect_value_to_cel(value).map_err(|err| CompilationError { cause: err.cause })
}

fn reflect_message_to_cel(msg: &DynamicMessage) -> Result<CelValue, RuntimeError> {
    let mut out: HashMap<CelKey, CelValue> = HashMap::new();
    for field in msg.descriptor().fields() {
        let has_field = msg.has_field(&field);
        let is_proto3_optional = field
            .containing_oneof()
            .is_some_and(|oneof| oneof.is_synthetic());
        if field.supports_presence() && !has_field && is_proto3_optional {
            continue;
        }

        let value = if has_field {
            reflect_value_to_cel(&msg.get_field(&field))?
        } else if let Some(message_desc) = field.kind().as_message() {
            if field.is_map() || field.is_list() {
                reflect_value_to_cel(&field.default_value())?
            } else {
                absent_message_to_cel(message_desc)?
            }
        } else {
            reflect_value_to_cel(&field.default_value())?
        };
        out.insert(CelKey::String(Arc::new(field.name().to_string())), value);
    }
    Ok(CelValue::Map(out.into()))
}

fn absent_message_to_cel(message: &MessageDescriptor) -> Result<CelValue, RuntimeError> {
    let mut out: HashMap<CelKey, CelValue> = HashMap::new();

    for field in message.fields() {
        let is_proto3_optional = field
            .containing_oneof()
            .is_some_and(|oneof| oneof.is_synthetic());
        if field.supports_presence() && is_proto3_optional {
            continue;
        }

        let value = if field.kind().as_message().is_some() && !field.is_map() {
            // For absent nested messages, expose a shallow object so chained
            // selectors can read scalar defaults without infinite recursion.
            CelValue::Map(HashMap::<CelKey, CelValue>::new().into())
        } else {
            reflect_value_to_cel(&field.default_value())?
        };
        out.insert(CelKey::String(Arc::new(field.name().to_string())), value);
    }

    Ok(CelValue::Map(out.into()))
}

fn reflect_map_key_to_cel(key: &prost_reflect::MapKey) -> CelKey {
    match key {
        prost_reflect::MapKey::Bool(v) => CelKey::Bool(*v),
        prost_reflect::MapKey::I32(v) => CelKey::Int(i64::from(*v)),
        prost_reflect::MapKey::I64(v) => CelKey::Int(*v),
        prost_reflect::MapKey::U32(v) => CelKey::Uint(u64::from(*v)),
        prost_reflect::MapKey::U64(v) => CelKey::Uint(*v),
        prost_reflect::MapKey::String(v) => CelKey::String(Arc::new(v.clone())),
    }
}

fn reflect_value_to_cel(value: &prost_reflect::Value) -> Result<CelValue, RuntimeError> {
    match value {
        prost_reflect::Value::Bool(v) => Ok(CelValue::Bool(*v)),
        prost_reflect::Value::I32(v) | prost_reflect::Value::EnumNumber(v) => {
            Ok(CelValue::Int(i64::from(*v)))
        }
        prost_reflect::Value::I64(v) => Ok(CelValue::Int(*v)),
        prost_reflect::Value::U32(v) => Ok(CelValue::UInt(u64::from(*v))),
        prost_reflect::Value::U64(v) => Ok(CelValue::UInt(*v)),
        prost_reflect::Value::F32(v) => Ok(CelValue::Float(f64::from(*v))),
        prost_reflect::Value::F64(v) => Ok(CelValue::Float(*v)),
        prost_reflect::Value::String(v) => Ok(CelValue::String(Arc::new(v.clone()))),
        prost_reflect::Value::Bytes(v) => Ok(CelValue::Bytes(Arc::new(v.to_vec()))),
        prost_reflect::Value::Message(m) => reflect_message_to_cel(m),
        prost_reflect::Value::List(values) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(reflect_value_to_cel(value)?);
            }
            Ok(CelValue::List(Arc::new(out)))
        }
        prost_reflect::Value::Map(map) => {
            let mut out: HashMap<CelKey, CelValue> = HashMap::with_capacity(map.len());
            for (key, value) in map {
                out.insert(reflect_map_key_to_cel(key), reflect_value_to_cel(value)?);
            }
            Ok(CelValue::Map(out.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use cel::objects::Key as CelKey;
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::config::ValidationConfig;
    use crate::error::Error;

    #[test]
    fn reflect_value_to_cel_passes_through_non_finite_floats() {
        let nan = reflect_value_to_cel(&prost_reflect::Value::F32(f32::NAN))
            .expect("NaN should convert to CEL value");
        let CelValue::Float(v) = nan else {
            panic!("expected float value");
        };
        assert!(v.is_nan());

        let inf = reflect_value_to_cel(&prost_reflect::Value::F64(f64::INFINITY))
            .expect("Infinity should convert to CEL value");
        assert_eq!(inf, CelValue::Float(f64::INFINITY));

        let neg_inf = reflect_value_to_cel(&prost_reflect::Value::F64(f64::NEG_INFINITY))
            .expect("NEG_INFINITY should convert to CEL value");
        assert_eq!(neg_inf, CelValue::Float(f64::NEG_INFINITY));
    }

    #[test]
    fn reflect_value_to_cel_passes_through_nested_non_finite_values() {
        let value = prost_reflect::Value::List(vec![prost_reflect::Value::F64(f64::NEG_INFINITY)]);
        let cel = reflect_value_to_cel(&value).expect("nested Infinity should convert");
        let CelValue::List(items) = cel else {
            panic!("expected list value");
        };
        assert_eq!(items[0], CelValue::Float(f64::NEG_INFINITY));
    }

    #[test]
    fn reflect_value_to_cel_preserves_map_key_types() {
        let mut map = HashMap::new();
        map.insert(
            prost_reflect::MapKey::I32(1),
            prost_reflect::Value::String("one".to_string()),
        );
        let value = prost_reflect::Value::Map(map);
        let cel_value = reflect_value_to_cel(&value).expect("conversion should succeed");
        let CelValue::Map(map) = cel_value else {
            panic!("expected map value");
        };

        assert!(map.get(&CelKey::Int(1)).is_some());
        assert!(
            map.get(&CelKey::String(Arc::new("1".to_string())))
                .is_none()
        );
    }

    #[test]
    fn go_compat_cel_helper_functions_are_available() {
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("f", f64::INFINITY);

        let unique = Program::compile("[1, 2, 2].unique()")
            .expect("program should compile")
            .execute(&ctx)
            .expect("execution should succeed");
        assert_eq!(unique, CelValue::Bool(false));

        let get_field = Program::compile("getField({'a': 1}, 'a')")
            .expect("program should compile")
            .execute(&ctx)
            .expect("execution should succeed");
        assert_eq!(get_field, CelValue::Int(1));

        let ip_prefix = Program::compile("'192.168.1.0/24'.isIpPrefix(4, true)")
            .expect("program should compile")
            .execute(&ctx)
            .expect("execution should succeed");
        assert_eq!(ip_prefix, CelValue::Bool(true));

        let is_inf = Program::compile("f.isInf(1)")
            .expect("program should compile")
            .execute(&ctx)
            .expect("execution should succeed");
        assert_eq!(is_inf, CelValue::Bool(true));

        let bytes_prefix = Program::compile("b'foobar'.startsWith(b'foo')")
            .expect("program should compile")
            .execute(&ctx)
            .expect("execution should succeed");
        assert_eq!(bytes_prefix, CelValue::Bool(true));
    }

    #[test]
    fn compile_programs_covers_empty_success_and_compile_failures() {
        let empty = compile_programs(&[], &[], "cel").expect("empty compile should succeed");
        assert!(empty.is_empty());

        let ok_rules = vec![
            prost_protovalidate_types::Rule {
                id: Some("foo".to_string()),
                expression: Some("this == 123".to_string()),
                ..prost_protovalidate_types::Rule::default()
            },
            prost_protovalidate_types::Rule {
                id: Some("bar".to_string()),
                expression: Some("'a string'".to_string()),
                ..prost_protovalidate_types::Rule::default()
            },
        ];
        let compiled = compile_programs(&[], &ok_rules, "cel").expect("valid CEL rules compile");
        assert_eq!(compiled.len(), 2);

        let bad_syntax = vec![prost_protovalidate_types::Rule {
            id: Some("bad".to_string()),
            expression: Some("!@#$%^&".to_string()),
            ..prost_protovalidate_types::Rule::default()
        }];
        assert!(compile_programs(&[], &bad_syntax, "cel").is_err());

        let missing_expression = vec![prost_protovalidate_types::Rule {
            id: Some("missing".to_string()),
            expression: None,
            ..prost_protovalidate_types::Rule::default()
        }];
        assert!(compile_programs(&[], &missing_expression, "cel").is_err());
    }

    #[test]
    fn cel_rule_program_and_set_evaluation_matches_expected_violation_paths() {
        let cfg = ValidationConfig::default();

        let bool_program = CelRuleProgram {
            rule_id: "foo".to_string(),
            message: Some("fizz".to_string()),
            rule_path: "cel[0]".to_string(),
            program: Program::compile("false").expect("program should compile"),
            rule_binding: None,
            rules_binding: None,
            rule_descriptor: None,
            rule_value: None,
        };
        let string_program = CelRuleProgram {
            rule_id: "bar".to_string(),
            message: None,
            rule_path: "cel[1]".to_string(),
            program: Program::compile("'buzz'").expect("program should compile"),
            rule_binding: None,
            rules_binding: None,
            rule_descriptor: None,
            rule_value: None,
        };

        let bool_violation = bool_program
            .evaluate_value_with_this(&prost_reflect::Value::Bool(false), &cfg)
            .expect("bool rule should evaluate")
            .expect("false should produce violation");
        assert_eq!(bool_violation.rule_id, "foo");
        assert_eq!(bool_violation.message, "fizz");

        let string_violation = string_program
            .evaluate_value_with_this(&prost_reflect::Value::Bool(false), &cfg)
            .expect("string rule should evaluate")
            .expect("non-empty string should produce violation");
        assert_eq!(string_violation.rule_id, "bar");
        assert_eq!(string_violation.message, "buzz");

        let invalid_type_program = CelRuleProgram {
            rule_id: "bad_type".to_string(),
            message: None,
            rule_path: "cel[2]".to_string(),
            program: Program::compile("1.23").expect("program should compile"),
            rule_binding: None,
            rules_binding: None,
            rule_descriptor: None,
            rule_value: None,
        };
        assert!(matches!(
            invalid_type_program.evaluate_value_with_this(&prost_reflect::Value::Bool(false), &cfg),
            Err(Error::Runtime(_))
        ));

        let eval = CelFieldEval {
            programs: vec![bool_program, string_program],
        };
        let fail_slow = eval
            .evaluate(
                &DynamicMessage::new(prost_protovalidate_types::FieldRules::default().descriptor()),
                &prost_reflect::Value::Bool(false),
                &cfg,
            )
            .expect_err("violations should be returned");
        let Error::Validation(fail_slow) = fail_slow else {
            panic!("expected validation error");
        };
        assert_eq!(fail_slow.violations.len(), 2);

        let fail_fast_cfg = ValidationConfig {
            fail_fast: true,
            ..ValidationConfig::default()
        };
        let fail_fast = eval
            .evaluate(
                &DynamicMessage::new(prost_protovalidate_types::FieldRules::default().descriptor()),
                &prost_reflect::Value::Bool(false),
                &fail_fast_cfg,
            )
            .expect_err("violations should be returned");
        let Error::Validation(fail_fast) = fail_fast else {
            panic!("expected validation error");
        };
        assert_eq!(fail_fast.violations.len(), 1);
    }
}
