use std::{collections::HashMap, hash::Hash};

use serde::{Deserialize, Serialize};

/// Marker trait for form field enum types, controlling which values to retain
/// (e.g. password fields should not be retained).
pub trait FormField: Copy + Hash + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> {
    /// Return false for fields where values should not be kept (e.g. password
    /// fields)
    fn keep(&self) -> bool;
}

/// Describes a single field-level validation error
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FieldError {
    /// A required field is missing
    Required,

    /// An unspecified error on the field
    Unspecified,

    /// Invalid value for this field
    Invalid,

    /// The password confirmation doesn't match the password
    PasswordMismatch,

    /// That value already exists
    Exists,

    /// Denied by the policy
    Policy {
        /// Well-known policy code
        code: Option<&'static str>,

        /// Message for this policy violation
        message: String,
    },
}

/// Describes a form-level validation error
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FormError {
    /// The given credentials are not valid
    InvalidCredentials,

    /// Password fields don't match
    PasswordMismatch,

    /// There was an internal error
    Internal,

    /// Rate limit exceeded
    RateLimitExceeded,

    /// Denied by the policy
    Policy {
        /// Well-known policy code
        code: Option<&'static str>,

        /// Message for this policy violation
        message: String,
    },

    /// Failed to validate CAPTCHA
    Captcha,
}

/// Internal representation of a single field's current state
#[derive(Debug, Default, Serialize)]
struct FieldState {
    value: Option<String>,
    errors: Vec<FieldError>,
}

/// Tracks state and validation errors for a form and its individual fields.
///
/// The type parameter `K` represents the field name enum.
#[derive(Debug, Serialize)]
pub struct FormState<K: Hash + Eq> {
    fields: HashMap<K, FieldState>,
    errors: Vec<FormError>,

    #[serde(skip)]
    has_errors: bool,
}

impl<K: Hash + Eq> Default for FormState<K> {
    fn default() -> Self {
        Self {
            fields: HashMap::new(),
            errors: Vec::new(),
            has_errors: false,
        }
    }
}

/// Intermediate enum used during deserialization to handle both known and
/// unknown field keys gracefully.
#[derive(Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
enum FieldKeyOrUnknown<K> {
    Known(K),
    Unknown(String),
}

impl<K> FieldKeyOrUnknown<K> {
    /// Extract the known key variant, discarding unknowns
    fn into_known(self) -> Option<K> {
        match self {
            Self::Known(k) => Some(k),
            Self::Unknown(_) => None,
        }
    }
}

impl<K: FormField> FormState<K> {
    /// Build a [`FormState`] from a serializable form struct.
    ///
    /// Field values are retained or cleared based on the [`FormField::keep`]
    /// implementation for each key.
    ///
    /// # Panics
    ///
    /// If the form fails to serialize, or the form field keys fail to
    /// deserialize
    pub fn from_form<F: Serialize>(form: &F) -> Self {
        // Serialize the form to a generic JSON value, then re-parse the keys
        let json_val = serde_json::to_value(form).expect("form serialization should not fail");
        let raw_fields: HashMap<FieldKeyOrUnknown<K>, Option<String>> =
            serde_json::from_value(json_val).expect("field key deserialization should not fail");

        let populated_fields = raw_fields
            .into_iter()
            .filter_map(|(maybe_key, val)| {
                let key = maybe_key.into_known()?;
                // Only preserve the value when the field type says to keep it
                let retained_value = if key.keep() { val } else { None };
                let state = FieldState {
                    value: retained_value,
                    errors: Vec::new(),
                };
                Some((key, state))
            })
            .collect();

        Self {
            fields: populated_fields,
            errors: Vec::new(),
            has_errors: false,
        }
    }

    /// Add an error on a form field
    pub fn add_error_on_field(&mut self, field: K, error: FieldError) {
        self.fields.entry(field).or_default().errors.push(error);
        self.has_errors = true;
    }

    /// Add an error on a form field
    #[must_use]
    pub fn with_error_on_field(mut self, field: K, error: FieldError) -> Self {
        self.add_error_on_field(field, error);
        self
    }

    /// Add an error on the form
    pub fn add_error_on_form(&mut self, error: FormError) {
        self.errors.push(error);
        self.has_errors = true;
    }

    /// Add an error on the form
    #[must_use]
    pub fn with_error_on_form(mut self, error: FormError) -> Self {
        self.add_error_on_form(error);
        self
    }

    /// Set a value on the form
    pub fn set_value(&mut self, field: K, value: Option<String>) {
        self.fields.entry(field).or_default().value = value;
    }

    /// Checks if a field contains a value
    pub fn has_value(&self, field: K) -> bool {
        self.fields
            .get(&field)
            .is_some_and(|state| state.value.is_some())
    }

    /// Returns `true` if the form has no error attached to it
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.has_errors
    }
}

/// Utility trait to help creating [`FormState`] out of a form
pub trait ToFormState: Serialize {
    /// The enum used for field names
    type Field: FormField;

    /// Generate a [`FormState`] out of [`Self`]
    ///
    /// # Panics
    ///
    /// If the form fails to serialize or [`Self::Field`] fails to deserialize
    fn to_form_state(&self) -> FormState<Self::Field> {
        FormState::from_form(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct SampleForm {
        foo: String,
        bar: String,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum SampleField {
        Foo,
        Bar,
    }

    impl FormField for SampleField {
        fn keep(&self) -> bool {
            matches!(self, Self::Foo)
        }
    }

    impl ToFormState for SampleForm {
        type Field = SampleField;
    }

    #[test]
    fn form_state_serialization() {
        let form = SampleForm {
            foo: "john".to_owned(),
            bar: "hunter2".to_owned(),
        };

        let state = form.to_form_state();
        let state = serde_json::to_value(state).unwrap();
        assert_eq!(
            state,
            serde_json::json!({
                "errors": [],
                "fields": {
                    "foo": {
                        "errors": [],
                        "value": "john",
                    },
                    "bar": {
                        "errors": [],
                        "value": null
                    },
                }
            })
        );

        let form = SampleForm {
            foo: String::new(),
            bar: String::new(),
        };
        let state = form
            .to_form_state()
            .with_error_on_field(SampleField::Foo, FieldError::Required)
            .with_error_on_field(SampleField::Bar, FieldError::Required)
            .with_error_on_form(FormError::InvalidCredentials);

        let state = serde_json::to_value(state).unwrap();
        assert_eq!(
            state,
            serde_json::json!({
                "errors": [{"kind": "invalid_credentials"}],
                "fields": {
                    "foo": {
                        "errors": [{"kind": "required"}],
                        "value": "",
                    },
                    "bar": {
                        "errors": [{"kind": "required"}],
                        "value": null
                    },
                }
            })
        );
    }
}
