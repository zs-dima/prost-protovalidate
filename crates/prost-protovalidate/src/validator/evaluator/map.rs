use prost_reflect::DynamicMessage;

use crate::config::ValidationConfig;
use crate::error::{self, Error};

use super::Evaluator;
use super::prepend_rule_prefix;
use super::value::ValueEval;

/// Evaluator for map fields.
/// Iterates key-value pairs and applies rules to keys and values.
pub(crate) struct MapEval {
    /// Rules for map keys.
    pub key_rules: ValueEval,
    /// Rules for map values.
    pub value_rules: ValueEval,
}

impl Evaluator for MapEval {
    fn tautology(&self) -> bool {
        self.key_rules.tautology() && self.value_rules.tautology()
    }

    fn evaluate(
        &self,
        msg: &DynamicMessage,
        val: &prost_reflect::Value,
        cfg: &ValidationConfig,
    ) -> Result<(), Error> {
        let Some(map) = val.as_map() else {
            return Ok(());
        };

        let mut acc: Option<Error> = None;

        for (key, value) in map {
            let key_str = map_key_to_string(key);

            // Validate key
            if !self.key_rules.tautology() {
                let key_path = format!("[{key_str}]");
                let key_value = key.clone().into();
                let (direct, nested) = self
                    .key_rules
                    .evaluate_value_split(msg, &key_value, cfg, &key_path);
                // Only direct (key-level) violations get "map.keys" rule prefix.
                let direct = mark_key_violations(direct);
                let direct = prepend_rule_prefix(direct, "map.keys");
                let nested = mark_key_violations(nested);
                let (cont, new_acc) = error::merge_violations(acc, direct, cfg.fail_fast);
                acc = new_acc;
                if !cont {
                    break;
                }
                let (cont, new_acc) = error::merge_violations(acc, nested, cfg.fail_fast);
                acc = new_acc;
                if !cont {
                    break;
                }
            }

            // Validate value
            if !self.value_rules.tautology() {
                let val_path = format!("[{key_str}]");
                let (direct, nested) = self
                    .value_rules
                    .evaluate_value_split(msg, value, cfg, &val_path);
                // Only direct (value-level) violations get "map.values" rule prefix.
                let direct = prepend_rule_prefix(direct, "map.values");
                let (cont, new_acc) = error::merge_violations(acc, direct, cfg.fail_fast);
                acc = new_acc;
                if !cont {
                    break;
                }
                let (cont, new_acc) = error::merge_violations(acc, nested, cfg.fail_fast);
                acc = new_acc;
                if !cont {
                    break;
                }
            }
        }

        match acc {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

fn map_key_to_string(key: &prost_reflect::MapKey) -> String {
    match key {
        prost_reflect::MapKey::Bool(b) => b.to_string(),
        prost_reflect::MapKey::I32(n) => n.to_string(),
        prost_reflect::MapKey::I64(n) => n.to_string(),
        prost_reflect::MapKey::U32(n) => n.to_string(),
        prost_reflect::MapKey::U64(n) => n.to_string(),
        prost_reflect::MapKey::String(s) => {
            serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
        }
    }
}

fn mark_key_violations(result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(Error::Validation(mut ve)) => {
            for violation in ve.violations_mut() {
                violation.mark_for_key();
            }
            Err(Error::Validation(ve))
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::map_key_to_string;

    #[test]
    fn map_key_to_string_round_trips_json_escaped_strings() {
        let raw = "line\n\t\"quote\"\\slash";
        let key = prost_reflect::MapKey::String(raw.to_string());
        let rendered = map_key_to_string(&key);
        let decoded: String =
            serde_json::from_str(&rendered).expect("rendered map key should be valid JSON");
        assert_eq!(decoded, raw);
    }
}
