use std::fmt;

use crate::violation::Violation;

/// Top-level error type returned by validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// One or more validation rules were violated.
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// A validation rule could not be compiled.
    #[error(transparent)]
    Compilation(#[from] CompilationError),

    /// A runtime failure occurred while executing a dynamic rule (e.g. CEL).
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
}

/// Returned when one or more validation rules are violated.
#[derive(Debug)]
pub struct ValidationError {
    /// The list of constraint violations found during validation.
    pub violations: Vec<Violation>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.violations.len() {
            0 => Ok(()),
            1 => write!(f, "validation error: {}", self.violations[0]),
            _ => {
                write!(f, "validation errors:")?;
                for v in &self.violations {
                    write!(f, "\n - {v}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl ValidationError {
    pub(crate) fn new(violations: Vec<Violation>) -> Self {
        Self { violations }
    }

    pub(crate) fn single(violation: Violation) -> Self {
        Self {
            violations: vec![violation],
        }
    }

    /// Convert to the wire-compatible `buf.validate.Violations` message.
    #[must_use]
    pub fn to_proto(&self) -> prost_protovalidate_types::Violations {
        prost_protovalidate_types::Violations {
            violations: self.violations.iter().map(|v| v.proto.clone()).collect(),
        }
    }
}

/// Returned when a validation rule cannot be compiled from its descriptor.
#[derive(Debug, thiserror::Error)]
#[error("compilation error: {cause}")]
pub struct CompilationError {
    /// Description of why the rule failed to compile.
    pub cause: String,
}

/// Returned when runtime evaluation of dynamic rules fails.
#[derive(Debug, thiserror::Error)]
#[error("runtime error: {cause}")]
pub struct RuntimeError {
    /// Description of the runtime failure.
    pub cause: String,
}

/// Merge violations from a sub-evaluation into an accumulator.
///
/// Returns `(should_continue, accumulated_error)`.
/// If `fail_fast` is true, stops on the first violation.
pub(crate) fn merge_violations(
    acc: Option<Error>,
    new_err: Result<(), Error>,
    fail_fast: bool,
) -> (bool, Option<Error>) {
    let new_err = match new_err {
        Ok(()) => return (true, acc),
        Err(e) => e,
    };

    match new_err {
        Error::Compilation(_) | Error::Runtime(_) => (false, Some(new_err)),
        Error::Validation(new_val) => {
            if fail_fast {
                return (false, Some(Error::Validation(new_val)));
            }
            match acc {
                Some(Error::Validation(mut existing)) => {
                    existing.violations.extend(new_val.violations);
                    (true, Some(Error::Validation(existing)))
                }
                _ => (true, Some(Error::Validation(new_val))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ValidationError, merge_violations};
    use crate::violation::Violation;

    fn validation_error(rule_id: &str) -> Error {
        Error::Validation(ValidationError::single(Violation::new("", rule_id, "")))
    }

    #[test]
    fn validation_error_display_matches_single_and_multiple_formats() {
        let single = ValidationError::new(vec![Violation::new("one.two", "bar", "foo")]);
        assert_eq!(single.to_string(), "validation error: one.two: foo");

        let multiple = ValidationError::new(vec![
            Violation::new("one.two", "bar", "foo"),
            Violation::new("one.three", "bar", ""),
        ]);
        assert_eq!(
            multiple.to_string(),
            "validation errors:\n - one.two: foo\n - one.three: [bar]"
        );
    }

    #[test]
    fn merge_violations_handles_non_validation_and_validation_paths() {
        let (cont, acc) = merge_violations(None, Ok(()), true);
        assert!(cont);
        assert!(acc.is_none());

        let runtime = Error::Runtime(super::RuntimeError {
            cause: "runtime failure".to_string(),
        });
        let (cont, acc) = merge_violations(None, Err(runtime), false);
        assert!(!cont);
        assert!(matches!(acc, Some(Error::Runtime(_))));

        let (cont, acc) = merge_violations(None, Err(validation_error("foo")), true);
        assert!(!cont);
        let Some(Error::Validation(err)) = acc else {
            panic!("expected validation error");
        };
        assert_eq!(err.violations.len(), 1);
        assert_eq!(err.violations[0].rule_id, "foo");

        let base = Some(validation_error("foo"));
        let (cont, acc) = merge_violations(base, Err(validation_error("bar")), false);
        assert!(cont);
        let Some(Error::Validation(err)) = acc else {
            panic!("expected merged validation error");
        };
        assert_eq!(err.violations.len(), 2);
        assert_eq!(err.violations[0].rule_id, "foo");
        assert_eq!(err.violations[1].rule_id, "bar");
    }
}
