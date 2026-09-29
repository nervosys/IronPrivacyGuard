//! Strict control JSON: decoded object member names must be unique at every depth.
//! This preserves ambiguity checks before values reach typed dispatch or preflight.
use crate::error::{Error, Result};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::fmt;

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("JSON with unique object member names")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Unique, E> {
                Number::from_f64(value)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("Non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(value.into())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(value)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut object: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if values.contains_key(&key) {
                        // No untrusted keys or values in error diagnostics.
                        return Err(de::Error::custom("Duplicate JSON object member"));
                    }
                    let Unique(value) = object.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

/// Parse one bounded control value. Preserves serde_json's nesting, number and
/// trailing-data checks while rejecting duplicates before any map loses them.
pub fn parse(data: &[u8]) -> Result<Value> {
    if data.len() > crate::MAX_REQUEST_BYTES as usize {
        return Err(Error::new("limit_exceeded", "Request exceeds frame limit"));
    }
    Ok(serde_json::from_slice::<Unique>(data)?.0)
}
