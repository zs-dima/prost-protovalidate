use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, RwLock};

use prost::Message;
use prost::encoding::{WireType, decode_key, decode_varint, encode_key, encode_varint};
use prost_reflect::{
    DescriptorPool, DynamicMessage, ExtensionDescriptor, FieldDescriptor, MessageDescriptor,
    ReflectMessage, Value,
};

use prost_protovalidate_types::{
    FieldConstraintsDynExt, FieldConstraintsExt, FieldRules, Ignore, MessageConstraintsExt,
    MessageRules, OneofConstraintsExt, field_rules,
};

use crate::error::CompilationError;

use super::evaluator::Evaluator;
use super::evaluator::Evaluators;
use super::evaluator::any::AnyEval;
use super::evaluator::cel::{
    CelFieldEval, CelMessageEval, CelRuleProgram, CelViolationMode, compile_programs,
    message_to_cel_value, value_to_cel_value,
};
use super::evaluator::embedded::EmbeddedMessageEval;
use super::evaluator::enum_check::DefinedEnumEval;
use super::evaluator::field::{FieldEval, IgnoreMode};
use super::evaluator::list::ListEval;
use super::evaluator::map::MapEval;
use super::evaluator::message::MessageEval;
use super::evaluator::oneof::{MessageOneofEval, OneofEval};
use super::evaluator::value::ValueEval;
use super::evaluator::wrapper::WrapperEval;
use super::lookups;
use super::rules;

/// Build-through cache of message evaluators keyed by descriptor full name.
pub(crate) struct Builder {
    /// Serializes cache writes.
    build_lock: Mutex<()>,
    /// Evaluator cache.
    cache: RwLock<HashMap<String, Arc<MessageEval>>>,
    /// Whether unknown types can be lazily built.
    lazy: bool,
    /// Whether unknown rule fields should be ignored instead of causing compilation errors.
    allow_unknown_fields: bool,
    /// Descriptor pool used to resolve custom/predefined rule extensions.
    descriptor_pool: DescriptorPool,
    /// Initialization-time error (e.g. invalid descriptor set bytes).
    init_err: Option<CompilationError>,
}

impl Builder {
    fn read_cache(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Arc<MessageEval>>> {
        self.cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_cache(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Arc<MessageEval>>> {
        self.cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_build(&self) -> std::sync::MutexGuard<'_, ()> {
        self.build_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn new() -> Self {
        Self::with_config(true, false, &[])
    }

    pub fn with_config(
        lazy: bool,
        allow_unknown_fields: bool,
        additional_descriptor_sets: &[Vec<u8>],
    ) -> Self {
        let (descriptor_pool, init_err) = build_descriptor_pool(additional_descriptor_sets);
        Self {
            build_lock: Mutex::new(()),
            cache: RwLock::new(HashMap::new()),
            lazy,
            allow_unknown_fields,
            descriptor_pool,
            init_err,
        }
    }

    /// Load a cached evaluator or build a new one.
    pub fn load_or_build(&self, desc: &MessageDescriptor) -> Arc<MessageEval> {
        let key = desc.full_name().to_string();

        if let Some(err) = &self.init_err {
            let eval = Arc::new(MessageEval::new());
            eval.set_err(CompilationError {
                cause: err.cause.clone(),
            });
            return eval;
        }

        // Fast path
        {
            let cache = self.read_cache();
            if let Some(eval) = cache.get(&key) {
                return Arc::clone(eval);
            }
        }

        if !self.lazy {
            let eval = Arc::new(MessageEval::new());
            eval.set_err(CompilationError {
                cause: format!("no evaluator available for {key}"),
            });
            return eval;
        }

        // Slow path
        let _guard = self.lock_build();

        {
            let cache = self.read_cache();
            if let Some(eval) = cache.get(&key) {
                return Arc::clone(eval);
            }
        }

        let mut local_cache = self.read_cache().clone();
        let eval = self.build(desc, &mut local_cache);
        *self.write_cache() = local_cache;

        eval
    }

    /// Preload an evaluator into the cache, even when lazy compilation is disabled.
    pub fn preload(&self, desc: &MessageDescriptor) {
        if self.init_err.is_some() {
            return;
        }

        let key = desc.full_name().to_string();
        if self.read_cache().contains_key(&key) {
            return;
        }

        let _guard = self.lock_build();
        if self.read_cache().contains_key(&key) {
            return;
        }

        let mut local_cache = self.read_cache().clone();
        let _ = self.build(desc, &mut local_cache);
        *self.write_cache() = local_cache;
    }

    /// Build an evaluator for a message descriptor.
    /// Recursive types are handled by inserting a placeholder Arc before recursing.
    fn build(
        &self,
        desc: &MessageDescriptor,
        cache: &mut HashMap<String, Arc<MessageEval>>,
    ) -> Arc<MessageEval> {
        let key = desc.full_name().to_string();

        if let Some(eval) = cache.get(&key) {
            return Arc::clone(eval);
        }

        let eval = Arc::new(MessageEval::new());
        cache.insert(key, Arc::clone(&eval));
        self.build_message(desc, &eval, cache);
        eval
    }

    fn build_message(
        &self,
        desc: &MessageDescriptor,
        msg_eval: &Arc<MessageEval>,
        cache: &mut HashMap<String, Arc<MessageEval>>,
    ) {
        let msg_rules = match desc.message_constraints() {
            Ok(rules) => rules,
            Err(err) => {
                if self.allow_unknown_fields {
                    None
                } else {
                    msg_eval.set_err(CompilationError {
                        cause: format!(
                            "failed to resolve message rules for {}: {err}",
                            desc.full_name()
                        ),
                    });
                    return;
                }
            }
        };

        if let Some(ref rules) = msg_rules {
            if let Err(err) = Self::process_message_expressions(rules, msg_eval) {
                msg_eval.set_err(err);
                return;
            }
            Self::process_message_oneof_rules(desc, rules, msg_eval);
        }

        if let Err(err) = Self::process_oneof_rules(desc, msg_eval) {
            msg_eval.set_err(err);
            return;
        }
        self.process_fields(desc, msg_rules.as_ref(), msg_eval, cache);
    }

    fn process_message_expressions(
        msg_rules: &MessageRules,
        msg_eval: &Arc<MessageEval>,
    ) -> Result<(), CompilationError> {
        let programs = compile_programs(
            &msg_rules.cel_expression,
            &msg_rules.cel,
            "cel",
            CelViolationMode::MessageExpression,
            CelViolationMode::MessageRule,
        )?;
        if !programs.is_empty() {
            msg_eval.append(Box::new(CelMessageEval { programs }));
        }
        Ok(())
    }

    fn process_message_oneof_rules(
        desc: &MessageDescriptor,
        msg_rules: &MessageRules,
        msg_eval: &Arc<MessageEval>,
    ) {
        for rule in &msg_rules.oneof {
            if rule.fields.is_empty() {
                msg_eval.set_err(CompilationError {
                    cause: format!(
                        "at least one field must be specified in oneof rule for message {}",
                        desc.full_name()
                    ),
                });
                return;
            }

            let mut seen = std::collections::HashSet::new();
            for name in &rule.fields {
                if !seen.insert(name.as_str()) {
                    msg_eval.set_err(CompilationError {
                        cause: format!(
                            "duplicate {name} in oneof rule for message {}",
                            desc.full_name()
                        ),
                    });
                    return;
                }
                if desc.get_field_by_name(name).is_none() {
                    msg_eval.set_err(CompilationError {
                        cause: format!("field {name} not found in message {}", desc.full_name()),
                    });
                    return;
                }
            }

            msg_eval.append_nested(Box::new(MessageOneofEval {
                field_names: rule.fields.clone(),
                required: rule.required.unwrap_or(false),
            }));
        }
    }

    fn process_oneof_rules(
        desc: &MessageDescriptor,
        msg_eval: &Arc<MessageEval>,
    ) -> Result<(), CompilationError> {
        for oneof in desc.oneofs() {
            if oneof.is_synthetic() {
                continue;
            }
            let required = oneof.try_is_required().map_err(|err| CompilationError {
                cause: format!(
                    "failed to decode oneof rules for {}.{}: {err}",
                    desc.full_name(),
                    oneof.name()
                ),
            })?;
            msg_eval.append_nested(Box::new(OneofEval {
                descriptor: oneof.clone(),
                required,
            }));
        }
        Ok(())
    }

    fn process_fields(
        &self,
        desc: &MessageDescriptor,
        msg_rules: Option<&MessageRules>,
        msg_eval: &Arc<MessageEval>,
        cache: &mut HashMap<String, Arc<MessageEval>>,
    ) {
        for field in desc.fields() {
            let field_rules_dynamic = match self.resolve_field_rules_dynamic(&field) {
                Ok(rules) => rules,
                Err(err) => {
                    let fld_eval = FieldEval {
                        value: ValueEval::new(field.clone()),
                        required: false,
                        has_presence: field.supports_presence(),
                        is_legacy_required: field.is_required(),
                        ignore: IgnoreMode::Unspecified,
                        err: Some(err),
                    };
                    msg_eval.append_nested(Box::new(fld_eval));
                    continue;
                }
            };

            let field_rules = match field.field_constraints() {
                Ok(rules) => rules,
                Err(err) => {
                    if self.allow_unknown_fields {
                        None
                    } else {
                        let fld_eval = FieldEval {
                            value: ValueEval::new(field.clone()),
                            required: false,
                            has_presence: field.supports_presence(),
                            is_legacy_required: field.is_required(),
                            ignore: IgnoreMode::Unspecified,
                            err: Some(CompilationError {
                                cause: format!(
                                    "failed to resolve field rules for {}: {err}",
                                    field.full_name()
                                ),
                            }),
                        };
                        msg_eval.append_nested(Box::new(fld_eval));
                        continue;
                    }
                }
            };
            let fld_eval = self.build_field(
                &field,
                field_rules.as_ref(),
                field_rules_dynamic.as_ref(),
                msg_rules,
                cache,
            );
            msg_eval.append_nested(Box::new(fld_eval));
        }
    }

    fn resolve_field_rules_dynamic(
        &self,
        field: &FieldDescriptor,
    ) -> Result<Option<DynamicMessage>, CompilationError> {
        let Some(raw_rules) = field.field_constraints_dynamic() else {
            return Ok(None);
        };

        let resolved_rules = self.reparse_with_descriptor_pool(&raw_rules)?;
        if !self.allow_unknown_fields && has_unknown_fields_recursive(&resolved_rules) {
            return Err(CompilationError {
                cause: format!(
                    "unknown rules in {}; provide additional descriptor sets or enable AllowUnknownFields",
                    field.full_name()
                ),
            });
        }

        Ok(Some(resolved_rules))
    }

    fn reparse_with_descriptor_pool(
        &self,
        message: &DynamicMessage,
    ) -> Result<DynamicMessage, CompilationError> {
        let descriptor = message.descriptor();
        let full_name = descriptor.full_name();
        let Some(target_desc) = self.descriptor_pool.get_message_by_name(full_name) else {
            return Ok(message.clone());
        };

        let encoded = message.encode_to_vec();
        DynamicMessage::decode(target_desc, encoded.as_slice()).map_err(|err| CompilationError {
            cause: format!("failed to reparse dynamic rule message `{full_name}`: {err}"),
        })
    }

    fn predefined_extension_descriptor(&self) -> Result<ExtensionDescriptor, CompilationError> {
        self.descriptor_pool
            .get_extension_by_name("buf.validate.predefined")
            .ok_or_else(|| CompilationError {
                cause: "missing `buf.validate.predefined` extension descriptor".to_string(),
            })
    }

    fn build_field(
        &self,
        field_desc: &FieldDescriptor,
        field_rules: Option<&FieldRules>,
        field_rules_dynamic: Option<&DynamicMessage>,
        msg_rules: Option<&MessageRules>,
        cache: &mut HashMap<String, Arc<MessageEval>>,
    ) -> FieldEval {
        let ignore = ignore_mode(field_rules.and_then(|r| r.ignore));

        let ignore = if ignore == IgnoreMode::Unspecified
            && is_part_of_message_oneof(msg_rules, field_desc)
        {
            IgnoreMode::IfZeroValue
        } else {
            ignore
        };

        let mut value_eval = ValueEval::new(field_desc.clone());
        let effective_rules = field_rules.cloned().unwrap_or_default();

        if ignore != IgnoreMode::Always {
            if let Err(err) = self.build_value(
                field_desc,
                &effective_rules,
                field_rules_dynamic,
                &mut value_eval,
                cache,
                false,
            ) {
                return FieldEval {
                    value: value_eval,
                    required: field_rules.and_then(|r| r.required).unwrap_or(false),
                    has_presence: field_desc.supports_presence(),
                    is_legacy_required: field_desc.is_required(),
                    ignore,
                    err: Some(err),
                };
            }
        }

        FieldEval {
            value: value_eval,
            required: field_rules.and_then(|r| r.required).unwrap_or(false),
            has_presence: field_desc.supports_presence(),
            is_legacy_required: field_desc.is_required(),
            ignore,
            err: None,
        }
    }

    fn build_value(
        &self,
        fdesc: &FieldDescriptor,
        field_rules: &FieldRules,
        field_rules_dynamic: Option<&DynamicMessage>,
        val_eval: &mut ValueEval,
        cache: &mut HashMap<String, Arc<MessageEval>>,
        nested: bool,
    ) -> Result<(), CompilationError> {
        let ignore = ignore_mode(field_rules.ignore);
        if ignore == IgnoreMode::Always {
            return Ok(());
        }
        val_eval.rule_metadata = collect_rule_metadata(field_rules_dynamic);
        validate_rule_type_matches_field(fdesc, field_rules, nested)?;
        validate_repeated_unique_rule_type(fdesc, field_rules, nested)?;
        Self::process_ignore_empty(fdesc, ignore, val_eval, nested);
        Self::process_field_expressions(field_rules, val_eval)?;
        self.process_embedded_message(fdesc, val_eval, cache, nested)?;
        self.process_wrapper_rules(
            fdesc,
            field_rules,
            field_rules_dynamic,
            val_eval,
            cache,
            nested,
        )?;
        Self::process_standard_rules(fdesc, field_rules, val_eval, nested)?;
        self.process_predefined_rules(fdesc, field_rules_dynamic, val_eval, nested)?;
        Self::process_any_rules(fdesc, field_rules, val_eval, nested);
        Self::process_enum_rules(fdesc, field_rules, val_eval);
        self.process_map_rules(
            fdesc,
            field_rules,
            field_rules_dynamic,
            val_eval,
            cache,
            nested,
        )?;
        self.process_repeated_rules(
            fdesc,
            field_rules,
            field_rules_dynamic,
            val_eval,
            cache,
            nested,
        )?;
        Ok(())
    }

    fn process_ignore_empty(
        fdesc: &FieldDescriptor,
        ignore: IgnoreMode,
        val_eval: &mut ValueEval,
        nested: bool,
    ) {
        val_eval.ignore_empty = nested && ignore == IgnoreMode::IfZeroValue;
        val_eval.zero = val_eval
            .ignore_empty
            .then(|| nested_zero_value(fdesc, nested));
    }

    fn process_field_expressions(
        field_rules: &FieldRules,
        val_eval: &mut ValueEval,
    ) -> Result<(), CompilationError> {
        let programs = compile_programs(
            &field_rules.cel_expression,
            &field_rules.cel,
            "cel",
            CelViolationMode::Field,
            CelViolationMode::Field,
        )?;
        if !programs.is_empty() {
            val_eval.push_rule(Box::new(CelFieldEval { programs }));
        }
        Ok(())
    }

    fn process_embedded_message(
        &self,
        fdesc: &FieldDescriptor,
        val_eval: &mut ValueEval,
        cache: &mut HashMap<String, Arc<MessageEval>>,
        nested: bool,
    ) -> Result<(), CompilationError> {
        if !lookups::is_message_field(fdesc) || fdesc.is_map() || (fdesc.is_list() && !nested) {
            return Ok(());
        }

        let msg_desc = fdesc
            .kind()
            .as_message()
            .cloned()
            .ok_or_else(|| CompilationError {
                cause: format!("no message descriptor for field {}", fdesc.full_name()),
            })?;

        let embed_eval = self.build(&msg_desc, cache);
        if let Some(cause) = embed_eval.compilation_error_cause() {
            return Err(CompilationError {
                cause: format!(
                    "failed to compile embedded type {} for {}: {cause}",
                    msg_desc.full_name(),
                    fdesc.full_name(),
                ),
            });
        }
        val_eval.push_nested(Box::new(EmbeddedMessageEval {
            message: embed_eval,
        }));

        Ok(())
    }

    fn process_wrapper_rules(
        &self,
        fdesc: &FieldDescriptor,
        rules: &FieldRules,
        field_rules_dynamic: Option<&DynamicMessage>,
        val_eval: &mut ValueEval,
        cache: &mut HashMap<String, Arc<MessageEval>>,
        nested: bool,
    ) -> Result<(), CompilationError> {
        if !lookups::is_message_field(fdesc) || fdesc.is_map() || (fdesc.is_list() && !nested) {
            return Ok(());
        }

        let msg_desc = match fdesc.kind().as_message() {
            Some(d) => d.clone(),
            None => return Ok(()),
        };

        let Some(expected_rule) = lookups::expected_wrapper_rule(msg_desc.full_name()) else {
            return Ok(());
        };

        if let Some(actual_rule) = field_rule_variant_name(rules) {
            if actual_rule != expected_rule {
                return Err(CompilationError {
                    cause: format!(
                        "expected rule `{expected_rule}`, got `{actual_rule}` on field `{}`",
                        fdesc.full_name()
                    ),
                });
            }
        }

        if let Some(value_field) = msg_desc.get_field_by_name("value") {
            let mut unwrapped = ValueEval::new(val_eval.descriptor.clone());
            self.build_value(
                &value_field,
                rules,
                field_rules_dynamic,
                &mut unwrapped,
                cache,
                nested,
            )?;
            let mut inner = Evaluators::new();
            inner.0.extend(unwrapped.rules.0);
            inner.0.extend(unwrapped.nested_rules.0);
            if !inner.tautology() {
                val_eval.push_rule(Box::new(WrapperEval { inner }));
            }
        }

        Ok(())
    }

    fn process_standard_rules(
        fdesc: &FieldDescriptor,
        rules: &FieldRules,
        val_eval: &mut ValueEval,
        nested: bool,
    ) -> Result<(), CompilationError> {
        if lookups::is_message_field(fdesc) && !fdesc.is_map() && (!fdesc.is_list() || nested) {
            if let Some(msg_desc) = fdesc.kind().as_message() {
                if lookups::expected_wrapper_rule(msg_desc.full_name()).is_some() {
                    return Ok(());
                }
            }
        }

        if let Some(eval) = rules::build_standard_rules(rules, fdesc)? {
            val_eval.push_rule(Box::new(eval));
        }
        Ok(())
    }

    #[allow(clippy::similar_names)]
    fn process_predefined_rules(
        &self,
        fdesc: &FieldDescriptor,
        field_rules_dynamic: Option<&DynamicMessage>,
        val_eval: &mut ValueEval,
        nested: bool,
    ) -> Result<(), CompilationError> {
        if lookups::is_message_field(fdesc) && !fdesc.is_map() && (!fdesc.is_list() || nested) {
            if let Some(msg_desc) = fdesc.kind().as_message() {
                if lookups::expected_wrapper_rule(msg_desc.full_name()).is_some() {
                    return Ok(());
                }
            }
        }

        let Some((rule_type, rule_message)) = active_rule_message(field_rules_dynamic) else {
            return Ok(());
        };

        let predefined_extension = self.predefined_extension_descriptor()?;
        let rules_binding = message_to_cel_value(&rule_message)?;
        let mut programs = Vec::new();

        // Reparse the rule message using the builder's pool so extension fields
        // from user-provided descriptor sets become visible.
        let reparsed = self.reparse_with_descriptor_pool(&rule_message)?;

        // Process predefined rules from extension fields.
        for (extension_desc, extension_value) in reparsed.extensions() {
            let predefined =
                decode_predefined_from_extension(&extension_desc, &predefined_extension)?;
            if predefined.cel.is_empty() {
                continue;
            }

            let rule_binding = value_to_cel_value(extension_value)?;
            let ext_element = extension_path_element(&extension_desc);
            let mut compiled = compile_predefined_rule_programs(
                &predefined.cel,
                rule_type.name(),
                &format!("[{}]", extension_desc.full_name()),
                &rule_binding,
                &rules_binding,
                None,
                Some(extension_value),
            )?;
            for prog in &mut compiled {
                prog.extension_element = Some(ext_element.clone());
            }
            programs.append(&mut compiled);
        }

        if !programs.is_empty() {
            val_eval.push_rule(Box::new(CelFieldEval { programs }));
        }

        Ok(())
    }

    fn process_any_rules(
        fdesc: &FieldDescriptor,
        rules: &FieldRules,
        val_eval: &mut ValueEval,
        nested: bool,
    ) {
        if !lookups::is_message_field(fdesc) || (fdesc.is_list() && !nested) {
            return;
        }

        let msg_desc = match fdesc.kind().as_message() {
            Some(d) => d.clone(),
            None => return,
        };

        if msg_desc.full_name() != "google.protobuf.Any" {
            return;
        }

        if let Some(field_rules::Type::Any(any_rules)) = &rules.r#type {
            let eval = AnyEval {
                r#in: any_rules.r#in.iter().cloned().collect(),
                not_in: any_rules.not_in.iter().cloned().collect(),
            };
            if !eval.tautology() {
                val_eval.push_rule(Box::new(eval));
            }
        }
    }

    fn process_enum_rules(fdesc: &FieldDescriptor, rules: &FieldRules, val_eval: &mut ValueEval) {
        let enum_desc = match fdesc.kind().as_enum() {
            Some(e) => e.clone(),
            None => return,
        };

        if let Some(field_rules::Type::Enum(enum_rules)) = &rules.r#type {
            if enum_rules.defined_only.unwrap_or(false) {
                val_eval.push_rule(Box::new(DefinedEnumEval {
                    enum_descriptor: enum_desc,
                }));
            }
        }
    }

    fn process_map_rules(
        &self,
        fdesc: &FieldDescriptor,
        rules: &FieldRules,
        field_rules_dynamic: Option<&DynamicMessage>,
        val_eval: &mut ValueEval,
        cache: &mut HashMap<String, Arc<MessageEval>>,
        nested: bool,
    ) -> Result<(), CompilationError> {
        if !fdesc.is_map() || nested {
            return Ok(());
        }

        let map_entry = fdesc
            .kind()
            .as_message()
            .cloned()
            .ok_or_else(|| CompilationError {
                cause: format!("no map entry descriptor for field {}", fdesc.full_name()),
            })?;

        let key_desc = map_entry
            .get_field_by_name("key")
            .ok_or_else(|| CompilationError {
                cause: format!("no key field in map entry for {}", fdesc.full_name()),
            })?;

        let value_desc = map_entry
            .get_field_by_name("value")
            .ok_or_else(|| CompilationError {
                cause: format!("no value field in map entry for {}", fdesc.full_name()),
            })?;

        let mut key_rules = ValueEval::new(key_desc.clone());
        let mut value_rules = ValueEval::new(value_desc.clone());
        let default_rules = FieldRules::default();
        let map_rules = match &rules.r#type {
            Some(field_rules::Type::Map(map_rules)) => Some(map_rules.as_ref()),
            _ => None,
        };
        let map_rules_dynamic = map_rules_dynamic(field_rules_dynamic);
        let key_rules_dynamic = map_rules_dynamic
            .as_ref()
            .and_then(|message| nested_field_rules_dynamic(message, "keys"));
        let value_rules_dynamic = map_rules_dynamic
            .as_ref()
            .and_then(|message| nested_field_rules_dynamic(message, "values"));

        if let Some(key_field_rules) = map_rules.and_then(|m| m.keys.as_ref()) {
            self.build_value(
                &key_desc,
                key_field_rules,
                key_rules_dynamic.as_ref(),
                &mut key_rules,
                cache,
                true,
            )?;
        } else {
            self.build_value(
                &key_desc,
                &default_rules,
                key_rules_dynamic.as_ref(),
                &mut key_rules,
                cache,
                true,
            )?;
        }
        if let Some(value_field_rules) = map_rules.and_then(|m| m.values.as_ref()) {
            self.build_value(
                &value_desc,
                value_field_rules,
                value_rules_dynamic.as_ref(),
                &mut value_rules,
                cache,
                true,
            )?;
        } else {
            self.build_value(
                &value_desc,
                &default_rules,
                value_rules_dynamic.as_ref(),
                &mut value_rules,
                cache,
                true,
            )?;
        }

        let map_eval = MapEval {
            key_rules,
            value_rules,
        };

        if !map_eval.tautology() {
            val_eval.push_nested(Box::new(map_eval));
        }

        Ok(())
    }

    fn process_repeated_rules(
        &self,
        fdesc: &FieldDescriptor,
        rules: &FieldRules,
        field_rules_dynamic: Option<&DynamicMessage>,
        val_eval: &mut ValueEval,
        cache: &mut HashMap<String, Arc<MessageEval>>,
        nested: bool,
    ) -> Result<(), CompilationError> {
        if !fdesc.is_list() || nested {
            return Ok(());
        }

        let repeated_rules = match &rules.r#type {
            Some(field_rules::Type::Repeated(repeated_rules)) => Some(repeated_rules.as_ref()),
            _ => None,
        };
        let repeated_rules_dynamic = repeated_rules_dynamic(field_rules_dynamic);
        let item_rules_dynamic = repeated_rules_dynamic
            .as_ref()
            .and_then(|message| nested_field_rules_dynamic(message, "items"));

        let mut item_rules = ValueEval::new(fdesc.clone());
        let default_rules = FieldRules::default();
        if let Some(item_field_rules) = repeated_rules.and_then(|r| r.items.as_ref()) {
            self.build_value(
                fdesc,
                item_field_rules,
                item_rules_dynamic.as_ref(),
                &mut item_rules,
                cache,
                true,
            )?;
        } else {
            self.build_value(
                fdesc,
                &default_rules,
                item_rules_dynamic.as_ref(),
                &mut item_rules,
                cache,
                true,
            )?;
        }

        let list_eval = ListEval { item_rules };
        if !list_eval.tautology() {
            val_eval.push_nested(Box::new(list_eval));
        }

        Ok(())
    }
}

fn ignore_mode(ignore: Option<i32>) -> IgnoreMode {
    ignore
        .and_then(|i| Ignore::try_from(i).ok())
        .map(|i| match i {
            Ignore::Unspecified => IgnoreMode::Unspecified,
            Ignore::IfZeroValue => IgnoreMode::IfZeroValue,
            Ignore::Always => IgnoreMode::Always,
        })
        .unwrap_or_default()
}

fn nested_zero_value(fdesc: &FieldDescriptor, nested: bool) -> prost_reflect::Value {
    if nested && fdesc.is_list() {
        fdesc.kind().default_value()
    } else {
        fdesc.default_value()
    }
}

fn field_rule_variant_name(rules: &FieldRules) -> Option<&'static str> {
    use field_rules::Type;

    match &rules.r#type {
        Some(Type::Float(_)) => Some("float"),
        Some(Type::Double(_)) => Some("double"),
        Some(Type::Int32(_)) => Some("int32"),
        Some(Type::Int64(_)) => Some("int64"),
        Some(Type::Uint32(_)) => Some("uint32"),
        Some(Type::Uint64(_)) => Some("uint64"),
        Some(Type::Sint32(_)) => Some("sint32"),
        Some(Type::Sint64(_)) => Some("sint64"),
        Some(Type::Fixed32(_)) => Some("fixed32"),
        Some(Type::Fixed64(_)) => Some("fixed64"),
        Some(Type::Sfixed32(_)) => Some("sfixed32"),
        Some(Type::Sfixed64(_)) => Some("sfixed64"),
        Some(Type::Bool(_)) => Some("bool"),
        Some(Type::String(_)) => Some("string"),
        Some(Type::Bytes(_)) => Some("bytes"),
        Some(Type::Enum(_)) => Some("enum"),
        Some(Type::Repeated(_)) => Some("repeated"),
        Some(Type::Map(_)) => Some("map"),
        Some(Type::Any(_)) => Some("any"),
        Some(Type::Duration(_)) => Some("duration"),
        Some(Type::Timestamp(_)) => Some("timestamp"),
        Some(Type::FieldMask(_)) => Some("field_mask"),
        None => None,
    }
}

fn expected_rule_variant_name(field_desc: &FieldDescriptor, nested: bool) -> Option<&'static str> {
    if field_desc.is_map() && !nested {
        return Some("map");
    }
    if field_desc.is_list() && !nested {
        return Some("repeated");
    }

    if let Some(message_desc) = field_desc.kind().as_message() {
        if let Some(wrapper_rule) = lookups::expected_wrapper_rule(message_desc.full_name()) {
            return Some(wrapper_rule);
        }
        return lookups::expected_wkt_rule(message_desc.full_name());
    }

    lookups::expected_standard_rule(&field_desc.kind())
}

fn validate_rule_type_matches_field(
    field_desc: &FieldDescriptor,
    rules: &FieldRules,
    nested: bool,
) -> Result<(), CompilationError> {
    let Some(actual) = field_rule_variant_name(rules) else {
        return Ok(());
    };

    let expected = expected_rule_variant_name(field_desc, nested);
    match expected {
        Some(expected) if expected == actual => Ok(()),
        Some(expected) => Err(CompilationError {
            cause: format!(
                "expected rule `{expected}`, got `{actual}` on field `{}`",
                field_desc.full_name()
            ),
        }),
        None => Err(CompilationError {
            cause: format!(
                "mismatched message rules, `{actual}` is not a valid rule for field `{}`",
                field_desc.full_name()
            ),
        }),
    }
}

fn validate_repeated_unique_rule_type(
    field_desc: &FieldDescriptor,
    rules: &FieldRules,
    nested: bool,
) -> Result<(), CompilationError> {
    if nested {
        return Ok(());
    }

    let Some(field_rules::Type::Repeated(repeated)) = &rules.r#type else {
        return Ok(());
    };

    if !repeated.unique.unwrap_or(false) {
        return Ok(());
    }

    if field_desc.kind().as_message().is_some() {
        return Err(CompilationError {
            cause: format!(
                "repeated.unique is only supported for scalar and enum item types; `{}` has message items",
                field_desc.full_name()
            ),
        });
    }

    Ok(())
}

/// Check whether a field is part of a message-level oneof rule.
fn is_part_of_message_oneof(msg_rules: Option<&MessageRules>, field: &FieldDescriptor) -> bool {
    let Some(rules) = msg_rules else {
        return false;
    };

    let field_name = field.name();
    rules
        .oneof
        .iter()
        .any(|oneof| oneof.fields.iter().any(|f| f == field_name))
}

fn build_descriptor_pool(
    additional_descriptor_sets: &[Vec<u8>],
) -> (DescriptorPool, Option<CompilationError>) {
    let base_bytes = prost_protovalidate_types::DESCRIPTOR_POOL.encode_to_vec();
    let base_entries = match parse_file_descriptor_set_entries(base_bytes.as_slice()) {
        Ok(entries) => entries,
        Err(err) => {
            return (
                prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                Some(CompilationError {
                    cause: format!("failed to decode built-in descriptor set: {err}"),
                }),
            );
        }
    };

    let mut seen_names: HashSet<String> =
        base_entries.iter().map(|(name, _)| name.clone()).collect();
    let mut combined_files: Vec<Vec<u8>> =
        base_entries.into_iter().map(|(_, bytes)| bytes).collect();
    let mut parsed_additional: Vec<Vec<(String, Vec<u8>)>> =
        Vec::with_capacity(additional_descriptor_sets.len());

    for (idx, bytes) in additional_descriptor_sets.iter().enumerate() {
        let entries = match parse_file_descriptor_set_entries(bytes.as_slice()) {
            Ok(entries) => entries,
            Err(err) => {
                return (
                    prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                    Some(CompilationError {
                        cause: format!(
                            "failed to decode additional descriptor set at index {idx}: {err}"
                        ),
                    }),
                );
            }
        };

        for (name, file_bytes) in &entries {
            if seen_names.insert(name.clone()) {
                combined_files.push(file_bytes.clone());
            }
        }
        parsed_additional.push(entries);
    }

    let combined_bytes = encode_file_descriptor_set(&combined_files);
    let combined_bytes = super::editions::normalize_edition_descriptor_set(&combined_bytes);
    match decode_pool_from_bytes(combined_bytes.as_slice()) {
        Ok(pool) => (pool, None),
        Err(err) => {
            // Keep index-oriented diagnostics without decoding into a non-empty pool.
            let mut prefix_seen: HashSet<String> = HashSet::new();
            let mut prefix_files = Vec::new();
            for (name, file_bytes) in
                parse_file_descriptor_set_entries(base_bytes.as_slice()).unwrap_or_default()
            {
                if prefix_seen.insert(name) {
                    prefix_files.push(file_bytes);
                }
            }

            for (idx, entries) in parsed_additional.iter().enumerate() {
                for (name, file_bytes) in entries {
                    if prefix_seen.insert(name.clone()) {
                        prefix_files.push(file_bytes.clone());
                    }
                }
                let prefix_bytes = encode_file_descriptor_set(&prefix_files);
                if let Err(prefix_err) = decode_pool_from_bytes(prefix_bytes.as_slice()) {
                    return (
                        prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                        Some(CompilationError {
                            cause: format!(
                                "failed to decode additional descriptor set at index {idx}: {prefix_err}"
                            ),
                        }),
                    );
                }
            }

            (
                prost_protovalidate_types::DESCRIPTOR_POOL.clone(),
                Some(CompilationError {
                    cause: format!(
                        "failed to decode additional descriptor sets (indices 0..{}): {err}",
                        additional_descriptor_sets.len()
                    ),
                }),
            )
        }
    }
}

fn decode_pool_from_bytes(bytes: &[u8]) -> Result<DescriptorPool, String> {
    let mut pool = DescriptorPool::new();
    match catch_unwind(AssertUnwindSafe(|| pool.decode_file_descriptor_set(bytes))) {
        Ok(Ok(())) => Ok(pool),
        Ok(Err(err)) => Err(err.to_string()),
        Err(panic) => Err(format!(
            "panic during descriptor pool decode: {}",
            panic_message(&panic)
        )),
    }
}

fn parse_file_descriptor_set_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut cursor = bytes;
    let mut entries = Vec::new();

    while !cursor.is_empty() {
        let (tag, wire_type) = decode_key(&mut cursor).map_err(|err| err.to_string())?;
        match (tag, wire_type) {
            (1, WireType::LengthDelimited) => {
                let len = decode_len(&mut cursor)?;
                if cursor.len() < len {
                    return Err("truncated file descriptor entry".to_string());
                }

                let entry = cursor[..len].to_vec();
                cursor = &cursor[len..];
                let name = parse_file_descriptor_name(entry.as_slice())?;
                entries.push((name, entry));
            }
            _ => skip_wire_value(&mut cursor, wire_type)?,
        }
    }

    Ok(entries)
}

fn parse_file_descriptor_name(bytes: &[u8]) -> Result<String, String> {
    let mut cursor = bytes;
    while !cursor.is_empty() {
        let (tag, wire_type) = decode_key(&mut cursor).map_err(|err| err.to_string())?;
        match (tag, wire_type) {
            (1, WireType::LengthDelimited) => {
                let len = decode_len(&mut cursor)?;
                if cursor.len() < len {
                    return Err("truncated file descriptor name".to_string());
                }

                let name = std::str::from_utf8(&cursor[..len])
                    .map_err(|err| format!("invalid UTF-8 in file descriptor name: {err}"))?;
                return Ok(name.to_string());
            }
            _ => skip_wire_value(&mut cursor, wire_type)?,
        }
    }

    Err("missing file name in file descriptor".to_string())
}

fn encode_file_descriptor_set(files: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for file in files {
        encode_key(1, WireType::LengthDelimited, &mut out);
        encode_varint(file.len() as u64, &mut out);
        out.extend_from_slice(file);
    }
    out
}

fn decode_len(cursor: &mut &[u8]) -> Result<usize, String> {
    let len_u64 = decode_varint(cursor).map_err(|err| err.to_string())?;
    usize::try_from(len_u64).map_err(|_| "length does not fit in usize".to_string())
}

fn skip_wire_value(cursor: &mut &[u8], wire_type: WireType) -> Result<(), String> {
    match wire_type {
        WireType::Varint => {
            decode_varint(cursor).map_err(|err| err.to_string())?;
            Ok(())
        }
        WireType::LengthDelimited => {
            let len = decode_len(cursor)?;
            if cursor.len() < len {
                return Err("truncated length-delimited field".to_string());
            }
            *cursor = &cursor[len..];
            Ok(())
        }
        WireType::ThirtyTwoBit => {
            if cursor.len() < 4 {
                return Err("truncated 32-bit field".to_string());
            }
            *cursor = &cursor[4..];
            Ok(())
        }
        WireType::SixtyFourBit => {
            if cursor.len() < 8 {
                return Err("truncated 64-bit field".to_string());
            }
            *cursor = &cursor[8..];
            Ok(())
        }
        WireType::StartGroup | WireType::EndGroup => {
            Err("group wire types are not supported".to_string())
        }
    }
}

fn panic_message(panic: &(dyn Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn active_rule_message(
    field_rules_dynamic: Option<&DynamicMessage>,
) -> Option<(FieldDescriptor, DynamicMessage)> {
    let field_rules_dynamic = field_rules_dynamic?;
    let type_oneof = field_rules_dynamic
        .descriptor()
        .oneofs()
        .find(|oneof| oneof.name() == "type")?;
    for field in type_oneof.fields() {
        if !field_rules_dynamic.has_field(&field) {
            continue;
        }
        let value = field_rules_dynamic.get_field(&field);
        if let Some(message) = value.as_message() {
            return Some((field, message.clone()));
        }
    }
    None
}

fn map_rules_dynamic(field_rules_dynamic: Option<&DynamicMessage>) -> Option<DynamicMessage> {
    let (field, rules) = active_rule_message(field_rules_dynamic)?;
    if field.name() == "map" {
        Some(rules)
    } else {
        None
    }
}

fn repeated_rules_dynamic(field_rules_dynamic: Option<&DynamicMessage>) -> Option<DynamicMessage> {
    let (field, rules) = active_rule_message(field_rules_dynamic)?;
    if field.name() == "repeated" {
        Some(rules)
    } else {
        None
    }
}

fn nested_field_rules_dynamic(
    parent_rules: &DynamicMessage,
    field_name: &str,
) -> Option<DynamicMessage> {
    parent_rules
        .get_field_by_name(field_name)
        .and_then(|value| value.as_message().cloned())
}

fn collect_rule_metadata(
    field_rules_dynamic: Option<&DynamicMessage>,
) -> HashMap<String, (FieldDescriptor, Value)> {
    let mut metadata = HashMap::new();
    let Some((rule_type_field, rule_message)) = active_rule_message(field_rules_dynamic) else {
        return metadata;
    };
    let rule_prefix = rule_type_field.name().to_string();

    for field in rule_message.descriptor().fields() {
        if !rule_message.has_field(&field) {
            continue;
        }

        let value = rule_message.get_field(&field).into_owned();
        metadata.insert(
            format!("{rule_prefix}.{}", field.name()),
            (field.clone(), value.clone()),
        );

        let Some(nested_message) = value.as_message() else {
            continue;
        };
        let Some((nested_field, nested_value)) = first_set_oneof_field(nested_message) else {
            continue;
        };

        metadata
            .entry(format!("{rule_prefix}.{}", nested_field.name()))
            .or_insert((nested_field.clone(), nested_value.clone()));

        for alias in rule_id_aliases(&rule_prefix, nested_field.name()) {
            metadata
                .entry(alias)
                .or_insert((nested_field.clone(), nested_value.clone()));
        }
    }

    metadata
}

fn first_set_oneof_field(message: &DynamicMessage) -> Option<(FieldDescriptor, Value)> {
    for oneof in message.descriptor().oneofs() {
        for field in oneof.fields() {
            if message.has_field(&field) {
                return Some((field.clone(), message.get_field(&field).into_owned()));
            }
        }
    }
    None
}

fn rule_id_aliases(rule_prefix: &str, nested_field_name: &str) -> Vec<String> {
    let suffixes: &[&str] = match nested_field_name {
        "gt" => &[
            "gt",
            "gt_lt",
            "gt_lte",
            "gt_lt_exclusive",
            "gt_lte_exclusive",
        ],
        "gte" => &[
            "gte",
            "gte_lt",
            "gte_lte",
            "gte_lt_exclusive",
            "gte_lte_exclusive",
        ],
        "lt" => &[
            "lt",
            "gt_lt",
            "gte_lt",
            "gt_lt_exclusive",
            "gte_lt_exclusive",
        ],
        "lte" => &[
            "lte",
            "gt_lte",
            "gte_lte",
            "gt_lte_exclusive",
            "gte_lte_exclusive",
        ],
        _ => &[],
    };

    suffixes
        .iter()
        .map(|suffix| format!("{rule_prefix}.{suffix}"))
        .collect()
}

fn has_unknown_fields_recursive(message: &DynamicMessage) -> bool {
    if message.unknown_fields().next().is_some() {
        return true;
    }

    for (_, value) in message.fields() {
        if value_contains_unknown_fields(value) {
            return true;
        }
    }
    for (_, value) in message.extensions() {
        if value_contains_unknown_fields(value) {
            return true;
        }
    }

    false
}

fn value_contains_unknown_fields(value: &Value) -> bool {
    match value {
        Value::Message(message) => has_unknown_fields_recursive(message),
        Value::List(values) => values.iter().any(value_contains_unknown_fields),
        Value::Map(values) => values.values().any(value_contains_unknown_fields),
        _ => false,
    }
}

fn extension_path_element(
    ext: &ExtensionDescriptor,
) -> prost_protovalidate_types::FieldPathElement {
    let field_type = crate::violation::kind_to_descriptor_type(&ext.kind());
    prost_protovalidate_types::FieldPathElement {
        field_number: i32::try_from(ext.number()).ok(),
        field_name: Some(format!("[{}]", ext.full_name())),
        field_type: Some(field_type as i32),
        key_type: None,
        value_type: None,
        subscript: None,
    }
}

fn decode_predefined_from_extension(
    extension: &ExtensionDescriptor,
    predefined_extension: &ExtensionDescriptor,
) -> Result<prost_protovalidate_types::PredefinedRules, CompilationError> {
    let options = extension.options();
    let extension_value = options.get_extension(predefined_extension);
    let Some(message) = extension_value.as_message() else {
        return Ok(prost_protovalidate_types::PredefinedRules::default());
    };
    message
        .transcode_to::<prost_protovalidate_types::PredefinedRules>()
        .map_err(|err| CompilationError {
            cause: format!(
                "failed to decode predefined rules from extension descriptor `{}`: {err}",
                extension.full_name()
            ),
        })
}

#[allow(clippy::similar_names)]
fn compile_predefined_rule_programs(
    rules: &[prost_protovalidate_types::Rule],
    rule_type_name: &str,
    rule_field_name: &str,
    rule_binding: &cel::Value,
    rules_binding: &cel::Value,
    rule_descriptor: Option<&FieldDescriptor>,
    rule_value: Option<&Value>,
) -> Result<Vec<CelRuleProgram>, CompilationError> {
    // Use just the rule type name as the path prefix; the extension element
    // will be appended to the violation's proto path separately.
    let mut programs = Vec::with_capacity(rules.len());
    for rule in rules {
        let expr = rule.expression.clone().ok_or_else(|| CompilationError {
            cause: format!(
                "missing CEL expression in `{rule_type_name}.{rule_field_name}` predefined rule"
            ),
        })?;
        let program = cel::Program::compile(&expr).map_err(|e| CompilationError {
            cause: format!("failed to compile CEL rule `{expr}`: {e}"),
        })?;
        programs.push(CelRuleProgram {
            rule_id: rule.id.clone().unwrap_or_else(|| expr.clone()),
            message: rule.message.clone(),
            rule_path: rule_type_name.to_string(),
            program,
            rule_binding: Some(rule_binding.clone()),
            rules_binding: Some(rules_binding.clone()),
            rule_descriptor: rule_descriptor.cloned(),
            rule_value: rule_value.cloned(),
            extension_element: None,
            violation_mode: CelViolationMode::Field,
        });
    }
    Ok(programs)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn descriptor_field(message: &str, field: &str) -> FieldDescriptor {
        prost_protovalidate_types::DESCRIPTOR_POOL
            .get_message_by_name(message)
            .and_then(|m| m.get_field_by_name(field))
            .expect("descriptor field must exist")
    }

    #[test]
    fn nested_zero_value_uses_element_default_for_lists() {
        let field = descriptor_field("buf.validate.StringRules", "in");
        assert!(field.is_list());

        let top_level = nested_zero_value(&field, false);
        assert!(top_level.as_list().is_some());

        let nested = nested_zero_value(&field, true);
        assert_eq!(nested, field.kind().default_value());
        assert!(nested.as_str().is_some());
    }

    #[test]
    fn build_field_without_rules_still_builds_repeated_message_items() {
        let field = descriptor_field("buf.validate.FieldRules", "cel");
        assert!(field.is_list());
        assert!(lookups::is_message_field(&field));

        let builder = Builder::new();
        let mut cache = HashMap::new();
        let eval = builder.build_field(&field, None, None, None, &mut cache);

        assert!(eval.err.is_none());
        assert!(!eval.value.nested_rules.is_empty());
    }

    #[test]
    fn build_field_rejects_mismatched_any_rules_for_non_any_field() {
        let field = descriptor_field("buf.validate.FieldRules", "required");
        let builder = Builder::new();
        let mut cache = HashMap::new();
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Any(
                prost_protovalidate_types::AnyRules::default(),
            )),
            ..FieldRules::default()
        };

        let eval = builder.build_field(&field, Some(&rules), None, None, &mut cache);
        assert!(eval.err.is_some());
    }

    #[test]
    fn build_field_rejects_mismatched_map_rules_for_scalar_field() {
        let field = descriptor_field("buf.validate.FieldRules", "required");
        let builder = Builder::new();
        let mut cache = HashMap::new();
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Map(Box::default())),
            ..FieldRules::default()
        };

        let eval = builder.build_field(&field, Some(&rules), None, None, &mut cache);
        assert!(eval.err.is_some());
    }

    #[test]
    fn build_field_rejects_repeated_unique_for_message_items() {
        let field = descriptor_field("buf.validate.FieldRules", "cel");
        assert!(field.is_list());
        assert!(field.kind().as_message().is_some());

        let builder = Builder::new();
        let mut cache = HashMap::new();
        let rules = FieldRules {
            r#type: Some(field_rules::Type::Repeated(Box::new(
                prost_protovalidate_types::RepeatedRules {
                    unique: Some(true),
                    ..Default::default()
                },
            ))),
            ..FieldRules::default()
        };

        let eval = builder.build_field(&field, Some(&rules), None, None, &mut cache);
        let Some(err) = eval.err else {
            panic!("expected repeated.unique type mismatch");
        };
        assert!(err.cause.contains("repeated.unique is only supported"));
        assert!(err.cause.contains("buf.validate.FieldRules.cel"));
    }

    #[test]
    fn process_embedded_message_surfaces_nested_compilation_errors() {
        let field = descriptor_field("buf.validate.FieldRules", "string");
        assert!(lookups::is_message_field(&field));

        let nested_desc = field
            .kind()
            .as_message()
            .cloned()
            .expect("field should reference message descriptor");
        let nested_eval = Arc::new(MessageEval::new());
        nested_eval.set_err(CompilationError {
            cause: "nested compile failure".to_string(),
        });

        let mut cache = HashMap::new();
        cache.insert(nested_desc.full_name().to_string(), nested_eval);

        let builder = Builder::new();
        let mut value_eval = ValueEval::new(field.clone());
        let err = builder
            .process_embedded_message(&field, &mut value_eval, &mut cache, false)
            .expect_err("nested compilation error should be surfaced");

        assert!(err.cause.contains("failed to compile embedded type"));
        assert!(err.cause.contains("buf.validate.StringRules"));
        assert!(err.cause.contains("for buf.validate.FieldRules.string"));
        assert!(err.cause.contains("nested compile failure"));
    }
}
