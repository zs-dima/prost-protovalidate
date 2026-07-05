use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use cel::common::ast::{EntryExpr, Expr, IdedExpr};
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

use super::super::formats;
use super::{Evaluator, MessageEvaluator};

/// Dotted field paths used by `has(...)` in a compiled CEL program, rooted at
/// a specific top-level binding (`this`, `rules`, or `rule`).
///
/// Each entry is a vector of field names from the binding root to the field
/// queried by `has()`. When the corresponding message is reflected into CEL,
/// fields whose path is in this set are *omitted* from the resulting map if
/// they are absent — so `has()` correctly returns `false`. Fields **not** in
/// the set are emitted with default values, so direct-access expressions like
/// `this.x.y == 1` still see spec-compliant defaults.
pub(crate) type PresencePaths = HashSet<Vec<String>>;

/// Walks a compiled CEL program's AST and collects every dotted field path
/// reached by `has(<binding>.path...)`. Paths that bottom out at any other
/// identifier (comprehension variables, dynamic operands, unknown roots) are
/// ignored — those code paths fall through to the default-value branch when
/// reflecting messages, which is the safe choice.
pub(crate) fn collect_has_paths(program: &Program, binding: &str) -> PresencePaths {
    let mut paths = PresencePaths::new();
    walk_expr_for_has(program.expression(), binding, &mut paths);
    paths
}

fn walk_expr_for_has(ided: &IdedExpr, binding: &str, paths: &mut PresencePaths) {
    match &ided.expr {
        Expr::Select(s) => {
            walk_expr_for_has(&s.operand, binding, paths);
            if s.test {
                if let Some(path) = extract_select_path(&s.operand, &s.field, binding) {
                    paths.insert(path);
                }
            }
        }
        Expr::Call(c) => {
            if let Some(target) = &c.target {
                walk_expr_for_has(target, binding, paths);
            }
            for arg in &c.args {
                walk_expr_for_has(arg, binding, paths);
            }
        }
        Expr::Comprehension(c) => {
            walk_expr_for_has(&c.iter_range, binding, paths);
            walk_expr_for_has(&c.accu_init, binding, paths);
            walk_expr_for_has(&c.loop_cond, binding, paths);
            walk_expr_for_has(&c.loop_step, binding, paths);
            walk_expr_for_has(&c.result, binding, paths);
        }
        Expr::List(l) => {
            for el in &l.elements {
                walk_expr_for_has(el, binding, paths);
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                match &entry.expr {
                    EntryExpr::MapEntry(me) => {
                        walk_expr_for_has(&me.key, binding, paths);
                        walk_expr_for_has(&me.value, binding, paths);
                    }
                    EntryExpr::StructField(sf) => {
                        walk_expr_for_has(&sf.value, binding, paths);
                    }
                }
            }
        }
        Expr::Struct(s) => {
            for entry in &s.entries {
                match &entry.expr {
                    EntryExpr::MapEntry(me) => {
                        walk_expr_for_has(&me.key, binding, paths);
                        walk_expr_for_has(&me.value, binding, paths);
                    }
                    EntryExpr::StructField(sf) => {
                        walk_expr_for_has(&sf.value, binding, paths);
                    }
                }
            }
        }
        Expr::Unspecified | Expr::Ident(_) | Expr::Literal(_) => {}
    }
}

/// Returns `true` if the compiled CEL program's AST contains any bare
/// identifier matching `name` (e.g. `now`, `this`). Used to skip context
/// bindings the program never references so we don't pay their cost
/// per-evaluation. Conservative: any structural match counts, even if the
/// expression containing the identifier is unreachable at runtime.
pub(crate) fn program_references_ident(program: &Program, name: &str) -> bool {
    expr_references_ident(program.expression(), name)
}

fn expr_references_ident(ided: &IdedExpr, name: &str) -> bool {
    match &ided.expr {
        Expr::Ident(n) => n == name,
        Expr::Select(s) => expr_references_ident(&s.operand, name),
        Expr::Call(c) => {
            c.target
                .as_ref()
                .is_some_and(|t| expr_references_ident(t, name))
                || c.args.iter().any(|a| expr_references_ident(a, name))
        }
        Expr::Comprehension(c) => {
            // The comprehension's iteration variable can shadow `name`. To
            // keep the analysis simple and conservative, we still descend
            // into all subexpressions and flag a match — false positives
            // only cost a cheap binding, not correctness.
            expr_references_ident(&c.iter_range, name)
                || expr_references_ident(&c.accu_init, name)
                || expr_references_ident(&c.loop_cond, name)
                || expr_references_ident(&c.loop_step, name)
                || expr_references_ident(&c.result, name)
        }
        Expr::List(l) => l.elements.iter().any(|e| expr_references_ident(e, name)),
        Expr::Map(m) => m.entries.iter().any(|entry| match &entry.expr {
            EntryExpr::MapEntry(me) => {
                expr_references_ident(&me.key, name) || expr_references_ident(&me.value, name)
            }
            EntryExpr::StructField(sf) => expr_references_ident(&sf.value, name),
        }),
        Expr::Struct(s) => s.entries.iter().any(|entry| match &entry.expr {
            EntryExpr::MapEntry(me) => {
                expr_references_ident(&me.key, name) || expr_references_ident(&me.value, name)
            }
            EntryExpr::StructField(sf) => expr_references_ident(&sf.value, name),
        }),
        Expr::Unspecified | Expr::Literal(_) => false,
    }
}

/// Climbs a chain of non-test `Select`s starting at `operand` until it hits
/// an `Ident` matching `target_binding`, building the dotted path from root to
/// `leaf`. Returns `None` for any other shape (comprehension iterators,
/// arbitrary expressions) — those are intentionally not registered.
fn extract_select_path(
    operand: &IdedExpr,
    leaf: &str,
    target_binding: &str,
) -> Option<Vec<String>> {
    let mut path = vec![leaf.to_string()];
    let mut current = &operand.expr;
    loop {
        match current {
            Expr::Select(s) if !s.test => {
                path.push(s.field.clone());
                current = &s.operand.expr;
            }
            Expr::Ident(name) if name == target_binding => {
                path.reverse();
                return Some(path);
            }
            _ => return None,
        }
    }
}

/// Controls how violations are generated for different CEL rule contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CelViolationMode {
    /// Standard field-level: include message and rule path.
    Field,
    /// Message-level `cel` rules: only emit `constraint_id` (no message, no rule path).
    MessageRule,
    /// Message-level `cel_expression`: emit `constraint_id` and computed message, no rule path.
    MessageExpression,
}

pub(crate) struct CelRuleProgram {
    pub rule_id: String,
    pub message: Option<String>,
    pub rule_path: String,
    pub program: Program,
    /// Raw `rules` binding source — reflected into a CEL value per-evaluation
    /// using `rules_presence_paths`, so `has(rules.x)` and `rules.x` honour
    /// the program's actual usage of `has()`.
    pub rules_message: Option<DynamicMessage>,
    pub rule_descriptor: Option<FieldDescriptor>,
    /// Raw `rule` binding source (a single field's value, often itself a
    /// message). Reflected into a CEL value per-evaluation using
    /// `rule_presence_paths`.
    pub rule_value: Option<prost_reflect::Value>,
    /// Extension field path element for predefined rule violations.
    pub extension_element: Option<prost_protovalidate_types::FieldPathElement>,
    /// Violation output mode (field-level vs message-level).
    pub violation_mode: CelViolationMode,
    /// Dotted paths reached by `has(this. ...)` in this program's AST.
    pub this_presence_paths: PresencePaths,
    /// Dotted paths reached by `has(rules. ...)` in this program's AST.
    pub rules_presence_paths: PresencePaths,
    /// Dotted paths reached by `has(rule. ...)` in this program's AST.
    pub rule_presence_paths: PresencePaths,
    /// `true` if the program references the `now` identifier anywhere in its
    /// AST. When `false`, evaluation skips the `cfg.now_fn()` call and the
    /// associated CEL context binding — saving one `SystemTime::now()`
    /// syscall per evaluation under the default configuration.
    pub references_now: bool,
}

impl CelRuleProgram {
    fn evaluate_message_with_this(
        &self,
        msg: &DynamicMessage,
        cfg: &ValidationConfig,
    ) -> Result<Option<Violation>, Error> {
        let this = reflect_message_to_cel(msg, &self.this_presence_paths, &[])?;
        self.evaluate_with_this_value(this, cfg)
    }

    fn evaluate_value_with_this(
        &self,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<Option<Violation>, Error> {
        let this = reflect_value_to_cel(val, &self.this_presence_paths, &[])?;
        self.evaluate_with_this_value(this, cfg)
    }

    fn evaluate_with_this_value(
        &self,
        this: CelValue,
        cfg: &ValidationConfig,
    ) -> Result<Option<Violation>, Error> {
        // Per-evaluation variables go into a child scope of the shared base
        // context, so the ~40 builtin and custom function registrations are
        // paid once per process instead of once per program execution.
        let mut ctx = BASE_CONTEXT.new_inner_scope();
        ctx.add_variable_from_value("this", this);

        if self.references_now {
            let now = (cfg.now_fn)();
            ctx.add_variable("now", timestamp_to_cel(&now)?)
                .map_err(|e| RuntimeError {
                    cause: format!("failed to bind CEL variable `now`: {e}"),
                })?;
        }
        if let Some(rule_value) = &self.rule_value {
            let rule_cel = reflect_value_to_cel(rule_value, &self.rule_presence_paths, &[])?;
            ctx.add_variable_from_value("rule", rule_cel);
        }
        if let Some(rules_msg) = &self.rules_message {
            let rules_cel = reflect_message_to_cel(rules_msg, &self.rules_presence_paths, &[])?;
            ctx.add_variable_from_value("rules", rules_cel);
        }

        let value = self.program.execute(&ctx).map_err(|e| RuntimeError {
            cause: format!("failed to execute CEL rule `{}`: {e}", self.rule_id),
        })?;

        match value {
            CelValue::Bool(true) => Ok(None),
            CelValue::Bool(false) => match self.violation_mode {
                CelViolationMode::MessageRule => Ok(Some(
                    Violation::new("", self.rule_id.clone(), "").without_rule_path(),
                )),
                CelViolationMode::MessageExpression => {
                    let message = format!("\"{}\" returned false", self.rule_id);
                    Ok(Some(
                        Violation::new("", self.rule_id.clone(), message).without_rule_path(),
                    ))
                }
                CelViolationMode::Field => {
                    let message = self.message.clone().unwrap_or_default();
                    Ok(Some(
                        self.with_rule_metadata(
                            Violation::new("", self.rule_id.clone(), message)
                                .with_rule_path(self.rule_path.clone()),
                        ),
                    ))
                }
            },
            CelValue::String(msg) => {
                let msg = msg.as_ref().clone();
                if msg.is_empty() {
                    Ok(None)
                } else {
                    match self.violation_mode {
                        CelViolationMode::MessageRule => Ok(Some(
                            Violation::new("", self.rule_id.clone(), "").without_rule_path(),
                        )),
                        CelViolationMode::MessageExpression => Ok(Some(
                            Violation::new("", self.rule_id.clone(), msg).without_rule_path(),
                        )),
                        CelViolationMode::Field => {
                            let message = self.message.clone().unwrap_or(msg);
                            Ok(Some(
                                self.with_rule_metadata(
                                    Violation::new("", self.rule_id.clone(), message)
                                        .with_rule_path(self.rule_path.clone()),
                                ),
                            ))
                        }
                    }
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
        if let Some(ext_element) = &self.extension_element {
            violation = violation.with_rule_extension_element(ext_element.clone());
        }
        violation
    }
}

/// Shared root context: CEL builtins plus the protovalidate function set.
/// Evaluations bind their variables (`this`, `now`, `rule`, `rules`) in a
/// child scope; none of these exist in the root, so lookup semantics match a
/// freshly built context.
static BASE_CONTEXT: LazyLock<Context<'static>> = LazyLock::new(build_cel_context);

fn build_cel_context() -> Context<'static> {
    let mut ctx = Context::default();
    register_protovalidate_functions(&mut ctx);
    ctx
}

fn register_protovalidate_functions(ctx: &mut Context<'_>) {
    // Override the built-in `int` to also handle Timestamp → seconds since epoch.
    ctx.add_function("int", cel_int);
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
    ctx.add_function("format", cel_format);
}

/// Override of the built-in CEL `int()` function to add `Timestamp → i64` conversion
/// (seconds since Unix epoch), which the upstream `cel` crate does not support.
fn cel_int(
    ftx: &FunctionContext<'_, '_>,
    This(this): This<CelValue>,
) -> Result<CelValue, CelExecutionError> {
    match this {
        CelValue::Timestamp(ts) => Ok(CelValue::Int(ts.timestamp())),
        CelValue::String(v) => v
            .parse::<i64>()
            .map(CelValue::Int)
            .map_err(|e| ftx.error(format!("string parse error: {e}"))),
        CelValue::Float(v) => {
            #[allow(clippy::cast_precision_loss)] // Boundary check; precision loss is acceptable.
            if v > i64::MAX as f64 || v < i64::MIN as f64 {
                return Err(ftx.error("integer overflow"));
            }
            #[allow(clippy::cast_possible_truncation)] // Truncating float to int is intentional.
            Ok(CelValue::Int(v as i64))
        }
        CelValue::Int(v) => Ok(CelValue::Int(v)),
        CelValue::UInt(v) => Ok(CelValue::Int(
            v.try_into().map_err(|_| ftx.error("integer overflow"))?,
        )),
        v => Err(ftx.error(format!("cannot convert {v:?} to int"))),
    }
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
    formats::is_hostname(value.as_ref())
}

fn cel_is_email(This(value): This<Arc<String>>) -> bool {
    formats::is_email(value.as_ref())
}

fn cel_is_ip(
    ftx: &FunctionContext<'_, '_>,
    This(value): This<Arc<String>>,
    Arguments(args): Arguments,
) -> Result<bool, CelExecutionError> {
    let tail = call_args_without_this(ftx, args.as_slice())?;
    match tail {
        [] => Ok(formats::is_ip_with_version(value.as_ref(), 0)),
        [CelValue::Int(version)] => Ok(formats::is_ip_with_version(value.as_ref(), *version)),
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
        [] => Ok(formats::is_ip_prefix_with_options(value.as_ref(), 0, false)),
        [CelValue::Int(version)] => Ok(formats::is_ip_prefix_with_options(
            value.as_ref(),
            *version,
            false,
        )),
        [CelValue::Bool(strict)] => Ok(formats::is_ip_prefix_with_options(
            value.as_ref(),
            0,
            *strict,
        )),
        [CelValue::Int(version), CelValue::Bool(strict)] => Ok(formats::is_ip_prefix_with_options(
            value.as_ref(),
            *version,
            *strict,
        )),
        _ => Err(CelExecutionError::NoSuchOverload),
    }
}

fn cel_is_uri(This(value): This<Arc<String>>) -> bool {
    formats::is_uri(value.as_ref())
}

fn cel_is_uri_ref(This(value): This<Arc<String>>) -> bool {
    formats::is_uri_ref(value.as_ref())
}

fn cel_is_host_and_port(This(value): This<Arc<String>>, port_required: bool) -> bool {
    formats::is_host_and_port(value.as_ref(), port_required)
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

/// CEL `string.format(\[args\])` — simple `%s`/`%d`/`%f`/`%e`/`%x` placeholder replacement.
fn cel_format(
    This(this): This<CelValue>,
    Arguments(args): Arguments,
) -> Result<CelValue, CelExecutionError> {
    let CelValue::String(template) = this else {
        return Err(CelExecutionError::NoSuchOverload);
    };
    let arg_list: Vec<CelValue> = match args.first() {
        Some(CelValue::List(list)) => list.as_ref().clone(),
        _ => args.as_ref().clone(),
    };
    let mut result = String::new();
    let mut arg_idx = 0;
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&spec) = chars.peek() {
                chars.next();
                if spec == '%' {
                    result.push('%');
                } else if arg_idx < arg_list.len() {
                    let arg = &arg_list[arg_idx];
                    arg_idx += 1;
                    match spec {
                        's' | 'e' | 'x' => result.push_str(&cel_value_to_string(arg)),
                        'd' => match arg {
                            CelValue::Int(v) => result.push_str(&v.to_string()),
                            CelValue::UInt(v) => result.push_str(&v.to_string()),
                            #[allow(clippy::cast_possible_truncation)]
                            CelValue::Float(v) => result.push_str(&(*v as i64).to_string()),
                            _ => result.push_str(&cel_value_to_string(arg)),
                        },
                        'f' => match arg {
                            CelValue::Float(v) => {
                                use std::fmt::Write;
                                let _ = write!(result, "{v:.6}");
                            }
                            CelValue::Int(v) => {
                                use std::fmt::Write;
                                let _ = write!(result, "{v}.000000");
                            }
                            CelValue::UInt(v) => {
                                use std::fmt::Write;
                                let _ = write!(result, "{v}.000000");
                            }
                            _ => result.push_str(&cel_value_to_string(arg)),
                        },
                        _ => {
                            result.push('%');
                            result.push(spec);
                        }
                    }
                } else {
                    result.push('%');
                    result.push(spec);
                }
            } else {
                result.push('%');
            }
        } else {
            result.push(ch);
        }
    }
    Ok(CelValue::String(Arc::new(result)))
}

fn cel_value_to_string(v: &CelValue) -> String {
    match v {
        CelValue::String(s) => s.as_ref().clone(),
        CelValue::Int(n) => n.to_string(),
        CelValue::UInt(n) => n.to_string(),
        CelValue::Float(n) => format!("{n}"),
        CelValue::Bool(b) => b.to_string(),
        CelValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
        CelValue::Null => "null".to_string(),
        _ => format!("{v:?}"),
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

#[allow(clippy::similar_names)] // `rule_presence_paths` vs `rules_presence_paths` is the intended distinction.
pub(crate) fn compile_programs(
    simple_exprs: &[String],
    rules: &[prost_protovalidate_types::Rule],
    path_prefix: &str,
    simple_mode: CelViolationMode,
    rule_mode: CelViolationMode,
) -> Result<Vec<CelRuleProgram>, CompilationError> {
    let mut out = Vec::with_capacity(simple_exprs.len() + rules.len());

    for (idx, expr) in simple_exprs.iter().enumerate() {
        let program = Program::compile(expr).map_err(|e| CompilationError {
            cause: format!("failed to compile CEL expression `{expr}`: {e}"),
        })?;
        let this_presence_paths = collect_has_paths(&program, "this");
        let rules_presence_paths = collect_has_paths(&program, "rules");
        let rule_presence_paths = collect_has_paths(&program, "rule");
        let references_now = program_references_ident(&program, "now");
        out.push(CelRuleProgram {
            rule_id: expr.clone(),
            message: None,
            rule_path: format!("{path_prefix}_expression[{idx}]"),
            program,
            rules_message: None,
            rule_descriptor: None,
            rule_value: None,
            extension_element: None,
            violation_mode: simple_mode,
            this_presence_paths,
            rules_presence_paths,
            rule_presence_paths,
            references_now,
        });
    }

    for (idx, rule) in rules.iter().enumerate() {
        let expr = rule.expression.clone().ok_or_else(|| CompilationError {
            cause: format!("missing CEL expression in `{path_prefix}` rule at index {idx}"),
        })?;

        let program = Program::compile(&expr).map_err(|e| CompilationError {
            cause: format!("failed to compile CEL rule `{expr}`: {e}"),
        })?;
        let this_presence_paths = collect_has_paths(&program, "this");
        let rules_presence_paths = collect_has_paths(&program, "rules");
        let rule_presence_paths = collect_has_paths(&program, "rule");
        let references_now = program_references_ident(&program, "now");

        out.push(CelRuleProgram {
            rule_id: rule.id.clone().unwrap_or_else(|| expr.clone()),
            message: rule.message.clone(),
            rule_path: format!("{path_prefix}[{idx}]"),
            program,
            rules_message: None,
            rule_descriptor: None,
            rule_value: None,
            extension_element: None,
            violation_mode: rule_mode,
            this_presence_paths,
            rules_presence_paths,
            rule_presence_paths,
            references_now,
        });
    }

    Ok(out)
}

fn reflect_message_to_cel(
    msg: &DynamicMessage,
    presence_paths: &PresencePaths,
    current_path: &[String],
) -> Result<CelValue, RuntimeError> {
    // Unwrap well-known wrapper types to their inner scalar value.
    if let Some(cel) = try_unwrap_well_known_message(msg) {
        return Ok(cel);
    }
    let mut out: HashMap<CelKey, CelValue> = HashMap::new();
    for field in msg.descriptor().fields() {
        let has_field = msg.has_field(&field);
        let field_name = field.name().to_string();
        let mut field_path = Vec::with_capacity(current_path.len() + 1);
        field_path.extend_from_slice(current_path);
        field_path.push(field_name.clone());

        let value = if has_field || field.is_map() || field.is_list() {
            reflect_value_to_cel(&msg.get_field(&field), presence_paths, &field_path)?
        } else if presence_paths.contains(&field_path) {
            // `has()` is used on this exact path — omit the key so the CEL
            // map-key check correctly returns `false` for the absent field.
            continue;
        } else if let Some(message_desc) = field.kind().as_message() {
            absent_message_to_cel(message_desc, presence_paths, &field_path)?
        } else {
            reflect_value_to_cel(&field.default_value(), presence_paths, &field_path)?
        };
        out.insert(CelKey::String(Arc::new(field_name)), value);
    }
    Ok(CelValue::Map(out.into()))
}

/// Unwrap well-known protobuf wrapper types, Duration, and Timestamp to native CEL values.
fn try_unwrap_well_known_message(msg: &DynamicMessage) -> Option<CelValue> {
    match msg.descriptor().full_name() {
        "google.protobuf.BoolValue" => {
            let v = msg
                .get_field_by_name("value")
                .is_some_and(|v| v.as_bool().unwrap_or(false));
            Some(CelValue::Bool(v))
        }
        "google.protobuf.Int32Value" => {
            let v = msg
                .get_field_by_name("value")
                .map_or(0, |v| v.as_i32().unwrap_or(0));
            Some(CelValue::Int(i64::from(v)))
        }
        "google.protobuf.Int64Value" => {
            let v = msg
                .get_field_by_name("value")
                .map_or(0, |v| v.as_i64().unwrap_or(0));
            Some(CelValue::Int(v))
        }
        "google.protobuf.UInt32Value" => {
            let v = msg
                .get_field_by_name("value")
                .map_or(0, |v| v.as_u32().unwrap_or(0));
            Some(CelValue::UInt(u64::from(v)))
        }
        "google.protobuf.UInt64Value" => {
            let v = msg
                .get_field_by_name("value")
                .map_or(0, |v| v.as_u64().unwrap_or(0));
            Some(CelValue::UInt(v))
        }
        "google.protobuf.FloatValue" => {
            let v = msg
                .get_field_by_name("value")
                .map_or(0.0, |v| v.as_f32().map_or(0.0, f64::from));
            Some(CelValue::Float(v))
        }
        "google.protobuf.DoubleValue" => {
            let v = msg
                .get_field_by_name("value")
                .map_or(0.0, |v| v.as_f64().unwrap_or(0.0));
            Some(CelValue::Float(v))
        }
        "google.protobuf.StringValue" => {
            let v = msg
                .get_field_by_name("value")
                .map_or_else(String::new, |v| v.as_str().unwrap_or("").to_string());
            Some(CelValue::String(Arc::new(v)))
        }
        "google.protobuf.BytesValue" => {
            let v = msg.get_field_by_name("value").map_or_else(Vec::new, |v| {
                v.as_bytes().map_or_else(Vec::new, |b| b.to_vec())
            });
            Some(CelValue::Bytes(Arc::new(v)))
        }
        "google.protobuf.Duration" => {
            let seconds = msg
                .get_field_by_name("seconds")
                .map_or(0i64, |v| v.as_i64().unwrap_or(0));
            let nanos = msg
                .get_field_by_name("nanos")
                .map_or(0i32, |v| v.as_i32().unwrap_or(0));
            let duration = chrono::TimeDelta::new(seconds, nanos.unsigned_abs())
                .unwrap_or(chrono::TimeDelta::zero());
            Some(CelValue::Duration(duration))
        }
        "google.protobuf.Timestamp" => {
            let seconds = msg
                .get_field_by_name("seconds")
                .map_or(0i64, |v| v.as_i64().unwrap_or(0));
            let nanos = msg
                .get_field_by_name("nanos")
                .map_or(0i32, |v| v.as_i32().unwrap_or(0));
            #[allow(clippy::cast_sign_loss)]
            let nanos_u32 = nanos.max(0) as u32;
            if let Some(utc_dt) = chrono::DateTime::<Utc>::from_timestamp(seconds, nanos_u32) {
                if let Some(offset) = FixedOffset::east_opt(0) {
                    return Some(CelValue::Timestamp(utc_dt.with_timezone(&offset)));
                }
            }
            // Fall through to Map representation if timestamp is invalid
            None
        }
        _ => None,
    }
}

fn absent_message_to_cel(
    message: &MessageDescriptor,
    presence_paths: &PresencePaths,
    current_path: &[String],
) -> Result<CelValue, RuntimeError> {
    let mut out: HashMap<CelKey, CelValue> = HashMap::new();

    for field in message.fields() {
        let field_name = field.name().to_string();
        let mut field_path = Vec::with_capacity(current_path.len() + 1);
        field_path.extend_from_slice(current_path);
        field_path.push(field_name.clone());

        if presence_paths.contains(&field_path) {
            // `has()` is used on this nested path through an absent message —
            // omit the key so `has()` correctly reports `false`.
            continue;
        }

        let value = if field.kind().as_message().is_some() && !field.is_map() && !field.is_list() {
            // For absent nested messages, expose a shallow object so chained
            // selectors can read scalar defaults without infinite recursion.
            CelValue::Map(HashMap::<CelKey, CelValue>::new().into())
        } else {
            reflect_value_to_cel(&field.default_value(), presence_paths, &field_path)?
        };
        out.insert(CelKey::String(Arc::new(field_name)), value);
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

fn reflect_value_to_cel(
    value: &prost_reflect::Value,
    presence_paths: &PresencePaths,
    current_path: &[String],
) -> Result<CelValue, RuntimeError> {
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
        prost_reflect::Value::Message(m) => reflect_message_to_cel(m, presence_paths, current_path),
        prost_reflect::Value::List(values) => {
            // List elements share the parent list's path — `has()` cannot
            // address individual indices, so per-element pathing isn't needed.
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                out.push(reflect_value_to_cel(value, presence_paths, current_path)?);
            }
            Ok(CelValue::List(Arc::new(out)))
        }
        prost_reflect::Value::Map(map) => {
            let mut out: HashMap<CelKey, CelValue> = HashMap::with_capacity(map.len());
            for (key, value) in map {
                out.insert(
                    reflect_map_key_to_cel(key),
                    reflect_value_to_cel(value, presence_paths, current_path)?,
                );
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

    fn no_presence() -> PresencePaths {
        PresencePaths::new()
    }

    #[test]
    fn program_references_ident_detects_now_only_when_used() {
        let with_now = Program::compile("now > timestamp('2020-01-01T00:00:00Z')")
            .expect("`now > timestamp(...)` must compile");
        assert!(program_references_ident(&with_now, "now"));

        let without_now =
            Program::compile("this.value > 0").expect("`this.value > 0` must compile");
        assert!(!program_references_ident(&without_now, "now"));

        // `now` referenced from inside a nested call/comprehension is still detected.
        let nested =
            Program::compile("[1, 2, 3].all(x, x > 0) && now > timestamp('2020-01-01T00:00:00Z')")
                .expect("compound `all() && now > …` must compile");
        assert!(program_references_ident(&nested, "now"));
    }

    #[test]
    fn program_references_ident_detects_now_inside_has_select() {
        // CEL's `has(x.field)` parses as `Select { test: true, operand: x,
        // field }`. The walker must descend into the `Select` operand and
        // flag the `Ident("now")` there. (Bare `has(now)` is rejected by
        // the CEL parser as an invalid `has()` argument — the macro
        // requires a field-select expression.)
        let program = Program::compile("has(this.x) && now > timestamp('2020-01-01T00:00:00Z')")
            .expect("`has(this.x) && now > …` must compile");
        assert!(program_references_ident(&program, "now"));
    }

    #[test]
    fn program_references_ident_detects_now_as_select_operand() {
        // `now.getSeconds()` reaches `now` via `Select` (or method-call
        // sugar). The walker's `Select` arm descends into the operand.
        let program =
            Program::compile("now.getSeconds() > 0").expect("`now.getSeconds()` must compile");
        assert!(program_references_ident(&program, "now"));
    }

    #[test]
    fn program_references_ident_walks_into_struct_and_map_literals() {
        // `Map` literal: `{'k': now}`. The walker's `Map` arm descends
        // into entry values.
        let in_map = Program::compile("{'k': now}.size() > 0")
            .expect("map literal containing `now` must compile");
        assert!(program_references_ident(&in_map, "now"));

        // `Map` literal that does NOT contain `now` — confirms the walker
        // doesn't over-flag.
        let no_now = Program::compile("{'k': this.value}.size() > 0")
            .expect("map literal without `now` must compile");
        assert!(!program_references_ident(&no_now, "now"));
    }

    #[test]
    fn program_references_ident_conservative_on_comprehension_shadowing() {
        // CEL allows arbitrary iteration-variable names. `[1, 2].all(now, …)`
        // shadows the global `now` binding inside the body, so a fully-precise
        // walker could return `false`. Our walker is conservative: it still
        // descends into the body and returns `true`. False positives only
        // cost a cheap context binding, not correctness — and the test pins
        // the behaviour so a future "smarter" walker can't accidentally
        // regress us into a missed-real-reference state.
        let shadowed = Program::compile("[1, 2].all(now, now > 0)")
            .expect("comprehension with `now` as iter-var must compile");
        assert!(program_references_ident(&shadowed, "now"));
    }

    #[test]
    fn program_references_ident_handles_multiple_occurrences() {
        let twice = Program::compile(
            "now > timestamp('2020-01-01T00:00:00Z') && now < timestamp('2030-01-01T00:00:00Z')",
        )
        .expect("compound `now > … && now < …` must compile");
        assert!(program_references_ident(&twice, "now"));
    }

    #[test]
    fn reflect_value_to_cel_passes_through_non_finite_floats() {
        let nan = reflect_value_to_cel(&prost_reflect::Value::F32(f32::NAN), &no_presence(), &[])
            .expect("NaN should convert to CEL value");
        let CelValue::Float(v) = nan else {
            panic!("expected float value");
        };
        assert!(v.is_nan());

        let inf = reflect_value_to_cel(
            &prost_reflect::Value::F64(f64::INFINITY),
            &no_presence(),
            &[],
        )
        .expect("Infinity should convert to CEL value");
        assert_eq!(inf, CelValue::Float(f64::INFINITY));

        let neg_inf = reflect_value_to_cel(
            &prost_reflect::Value::F64(f64::NEG_INFINITY),
            &no_presence(),
            &[],
        )
        .expect("NEG_INFINITY should convert to CEL value");
        assert_eq!(neg_inf, CelValue::Float(f64::NEG_INFINITY));
    }

    #[test]
    fn reflect_value_to_cel_passes_through_nested_non_finite_values() {
        let value = prost_reflect::Value::List(vec![prost_reflect::Value::F64(f64::NEG_INFINITY)]);
        let cel = reflect_value_to_cel(&value, &no_presence(), &[])
            .expect("nested Infinity should convert");
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
        let cel_value =
            reflect_value_to_cel(&value, &no_presence(), &[]).expect("conversion should succeed");
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
        let empty = compile_programs(
            &[],
            &[],
            "cel",
            CelViolationMode::Field,
            CelViolationMode::Field,
        )
        .expect("empty compile should succeed");
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
        let compiled = compile_programs(
            &[],
            &ok_rules,
            "cel",
            CelViolationMode::Field,
            CelViolationMode::Field,
        )
        .expect("valid CEL rules compile");
        assert_eq!(compiled.len(), 2);

        let bad_syntax = vec![prost_protovalidate_types::Rule {
            id: Some("bad".to_string()),
            expression: Some("!@#$%^&".to_string()),
            ..prost_protovalidate_types::Rule::default()
        }];
        assert!(
            compile_programs(
                &[],
                &bad_syntax,
                "cel",
                CelViolationMode::Field,
                CelViolationMode::Field
            )
            .is_err()
        );

        let missing_expression = vec![prost_protovalidate_types::Rule {
            id: Some("missing".to_string()),
            expression: None,
            ..prost_protovalidate_types::Rule::default()
        }];
        assert!(
            compile_programs(
                &[],
                &missing_expression,
                "cel",
                CelViolationMode::Field,
                CelViolationMode::Field
            )
            .is_err()
        );
    }

    #[test]
    fn cel_rule_program_and_set_evaluation_matches_expected_violation_paths() {
        let cfg = ValidationConfig::default();

        let bool_program = CelRuleProgram {
            rule_id: "foo".to_string(),
            message: Some("fizz".to_string()),
            rule_path: "cel[0]".to_string(),
            program: Program::compile("false").expect("program should compile"),
            rules_message: None,
            rule_descriptor: None,
            rule_value: None,
            extension_element: None,
            violation_mode: CelViolationMode::Field,
            this_presence_paths: no_presence(),
            rules_presence_paths: no_presence(),
            rule_presence_paths: no_presence(),
            references_now: false,
        };
        let string_program = CelRuleProgram {
            rule_id: "bar".to_string(),
            message: None,
            rule_path: "cel[1]".to_string(),
            program: Program::compile("'buzz'").expect("program should compile"),
            rules_message: None,
            rule_descriptor: None,
            rule_value: None,
            extension_element: None,
            violation_mode: CelViolationMode::Field,
            this_presence_paths: no_presence(),
            rules_presence_paths: no_presence(),
            rule_presence_paths: no_presence(),
            references_now: false,
        };

        let bool_violation = bool_program
            .evaluate_value_with_this(&prost_reflect::Value::Bool(false), &cfg)
            .expect("bool rule should evaluate")
            .expect("false should produce violation");
        assert_eq!(bool_violation.rule_id(), "foo");
        assert_eq!(bool_violation.message(), "fizz");

        let string_violation = string_program
            .evaluate_value_with_this(&prost_reflect::Value::Bool(false), &cfg)
            .expect("string rule should evaluate")
            .expect("non-empty string should produce violation");
        assert_eq!(string_violation.rule_id(), "bar");
        assert_eq!(string_violation.message(), "buzz");

        let invalid_type_program = CelRuleProgram {
            rule_id: "bad_type".to_string(),
            message: None,
            rule_path: "cel[2]".to_string(),
            program: Program::compile("1.23").expect("program should compile"),
            rules_message: None,
            rule_descriptor: None,
            rule_value: None,
            extension_element: None,
            violation_mode: CelViolationMode::Field,
            this_presence_paths: no_presence(),
            rules_presence_paths: no_presence(),
            rule_presence_paths: no_presence(),
            references_now: false,
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
        assert_eq!(fail_slow.len(), 2);

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
        assert_eq!(fail_fast.len(), 1);
    }

    // ---- cel_int unit tests ----

    #[test]
    fn cel_int_converts_timestamp_to_epoch_seconds() {
        let ctx = build_cel_context();
        let program =
            Program::compile("int(timestamp('2023-01-01T00:00:00Z'))").expect("should compile");
        let result = program.execute(&ctx).expect("should execute");
        assert_eq!(result, CelValue::Int(1_672_531_200));
    }

    #[test]
    fn cel_int_converts_string_to_int() {
        let ctx = build_cel_context();
        let program = Program::compile("int('42')").expect("should compile");
        let result = program.execute(&ctx).expect("should execute");
        assert_eq!(result, CelValue::Int(42));
    }

    #[test]
    fn cel_int_converts_negative_string() {
        let ctx = build_cel_context();
        let program = Program::compile("int('-100')").expect("should compile");
        let result = program.execute(&ctx).expect("should execute");
        assert_eq!(result, CelValue::Int(-100));
    }

    #[test]
    fn cel_int_truncates_float() {
        let ctx = build_cel_context();
        let program = Program::compile("int(3.9)").expect("should compile");
        let result = program.execute(&ctx).expect("should execute");
        assert_eq!(result, CelValue::Int(3));
    }

    #[test]
    fn cel_int_passes_through_int() {
        let ctx = build_cel_context();
        let program = Program::compile("int(7)").expect("should compile");
        let result = program.execute(&ctx).expect("should execute");
        assert_eq!(result, CelValue::Int(7));
    }

    #[test]
    fn cel_int_converts_uint_to_int() {
        let ctx = build_cel_context();
        let program = Program::compile("int(uint(5))").expect("should compile");
        let result = program.execute(&ctx).expect("should execute");
        assert_eq!(result, CelValue::Int(5));
    }

    // ---- presence-aware reflection tests ----
    //
    // The two tests below were originally introduced by PR #7 to demonstrate
    // that `has(this.string)` should return `false` for an unset oneof
    // message member (and `true` once it's set). They are preserved verbatim
    // — under AST-driven asymmetric reflection they still pass, alongside
    // the spec-compliant default-value access exercised by the tests further
    // down.

    #[test]
    fn absent_presence_tracking_fields_are_absent_for_cel_has() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let message = DynamicMessage::new(descriptor);

        let has_program = Program::compile("has(this.string)").expect("program should compile");
        let presence = collect_has_paths(&has_program, "this");
        let this = reflect_message_to_cel(&message, &presence, &[])
            .expect("message should convert to CEL");
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("this", this);
        let has_absent_oneof_message = has_program.execute(&ctx).expect("execution should succeed");
        assert_eq!(has_absent_oneof_message, CelValue::Bool(false));

        let guarded_program = Program::compile("!has(this.string) || this.string.min_len == 1")
            .expect("program should compile");
        let presence = collect_has_paths(&guarded_program, "this");
        let this =
            reflect_message_to_cel(&message, &presence, &[]).expect("message should convert");
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("this", this);
        let guarded_absent_oneof_message = guarded_program
            .execute(&ctx)
            .expect("execution should short-circuit instead of reading an absent message");
        assert_eq!(guarded_absent_oneof_message, CelValue::Bool(true));
    }

    #[test]
    fn present_presence_tracking_fields_are_present_for_cel_has() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let string_field = descriptor
            .get_field_by_name("string")
            .expect("FieldRules should have string rules");
        let string_message = DynamicMessage::new(
            string_field
                .kind()
                .as_message()
                .expect("string rules should be a message")
                .clone(),
        );
        let mut message = DynamicMessage::new(descriptor);
        message.set_field(&string_field, prost_reflect::Value::Message(string_message));

        let program = Program::compile("has(this.string)").expect("program should compile");
        let presence = collect_has_paths(&program, "this");
        let this = reflect_message_to_cel(&message, &presence, &[])
            .expect("message should convert to CEL");
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("this", this);
        let has_present_oneof_message = program.execute(&ctx).expect("execution should succeed");
        assert_eq!(has_present_oneof_message, CelValue::Bool(true));
    }

    /// Regression test for the `ignore_proto2 / ignore_proto3 / ignore_editions`
    /// conformance suite. With the outer message field set to an empty
    /// submessage and the inner field being a proto3 `optional` scalar,
    /// direct-access expressions without `has()` guards must see the inner
    /// scalar at its default value rather than erroring with "No such key".
    #[test]
    fn absent_presence_tracked_scalar_inside_present_message_returns_default() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let string_field = descriptor
            .get_field_by_name("string")
            .expect("FieldRules should have string rules");
        let string_message = DynamicMessage::new(
            string_field
                .kind()
                .as_message()
                .expect("string rules should be a message")
                .clone(),
        );
        let mut message = DynamicMessage::new(descriptor);
        message.set_field(&string_field, prost_reflect::Value::Message(string_message));

        // `suffix` is `optional string suffix = 6;` in StringRules — a
        // presence-tracked scalar. The expression doesn't use `has()`, so the
        // AST walker leaves the path alone and reflection synthesizes the
        // default value `""`.
        let program = Program::compile("this.string.suffix == ''").expect("program should compile");
        let presence = collect_has_paths(&program, "this");
        let this =
            reflect_message_to_cel(&message, &presence, &[]).expect("message should convert");
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("this", this);
        let result = program
            .execute(&ctx)
            .expect("absent presence-tracked scalar should resolve to its default, not error");
        assert_eq!(result, CelValue::Bool(true));
    }

    /// Regression test for the `custom_rules / message_expression_embed`
    /// conformance case. An absent presence-tracked **message** field that's
    /// accessed via chained selectors (without a `has()` guard) must
    /// synthesize a shallow default-populated map so the chained scalar
    /// access returns the scalar's default value.
    #[test]
    fn absent_message_field_chained_access_returns_default() {
        let descriptor = prost_protovalidate_types::FieldRules::default().descriptor();
        let message = DynamicMessage::new(descriptor);

        // `this.string` is absent (the oneof is unset). `this.string.suffix`
        // is a chained scalar selector. Without `has()` it must read as the
        // scalar default.
        let program = Program::compile("this.string.suffix == ''").expect("program should compile");
        let presence = collect_has_paths(&program, "this");
        let this =
            reflect_message_to_cel(&message, &presence, &[]).expect("message should convert");
        let mut ctx = build_cel_context();
        ctx.add_variable_from_value("this", this);
        let result = program
            .execute(&ctx)
            .expect("chained access on absent presence-tracked message should resolve to default");
        assert_eq!(result, CelValue::Bool(true));
    }

    /// Unit test for the AST walker itself: verify it correctly extracts
    /// `has()` paths for the relevant top-level bindings while ignoring
    /// comprehension-local iter variables and other-binding accesses.
    #[test]
    fn ast_walker_collects_has_paths_for_known_bindings() {
        let p1 = Program::compile("has(this.x)").expect("compile");
        let paths = collect_has_paths(&p1, "this");
        assert!(paths.contains(&vec!["x".to_string()]));
        assert_eq!(paths.len(), 1);

        let p2 = Program::compile("has(this.x.y)").expect("compile");
        let paths = collect_has_paths(&p2, "this");
        assert!(paths.contains(&vec!["x".to_string(), "y".to_string()]));

        // `has(rules.lt)` registers only under the `rules` binding.
        let p3 = Program::compile("has(rules.lt)").expect("compile");
        assert!(collect_has_paths(&p3, "rules").contains(&vec!["lt".to_string()]));
        assert!(collect_has_paths(&p3, "this").is_empty());

        // Comprehension-local `item.x` must not count under the outer `this`
        // binding — the operand chain bottoms out at `Ident("item")`, not
        // `Ident("this")`.
        let p4 = Program::compile("this.list.exists(item, has(item.x))").expect("compile");
        assert!(collect_has_paths(&p4, "this").is_empty());
    }
}
