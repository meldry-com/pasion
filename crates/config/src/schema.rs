//! Useful JSON Schema definitions

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

/// A network hostname
pub struct Hostname;

impl JsonSchema for Hostname {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Hostname")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "hostname",
        })
    }
}
