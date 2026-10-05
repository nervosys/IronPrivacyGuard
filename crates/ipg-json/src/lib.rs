//! Native JSON contracts. No external parser, serializer or schema runtime.
//!
//! The derives deliberately support only IPG's contract vocabulary. Unknown
//! options, duplicate wire names and discriminator collisions fail compilation.
//! ```compile_fail
//! #[derive(ipg_json::Serialize)]
//! struct Ambiguous { first: String, #[serde(rename="first")] second: String }
//! ```
//! ```compile_fail
//! #[derive(ipg_json::Deserialize)]
//! struct Unsupported { #[serde(flatten)] fields: String }
//! ```
//! ```compile_fail
//! #[derive(ipg_json::Serialize)]
//! #[serde(tag="operation")]
//! enum Collision { Write { operation: String } }
//! ```
#![forbid(unsafe_code)]
pub use ipg_derive::{Deserialize, JsonSchema, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    ops::{Index, IndexMut},
};
mod parser;
mod schema;
pub use schema::{JsonSchema, Schema, SchemaGenerator, schema_for};
pub type Map<K, V> = BTreeMap<K, V>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Number {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
}
impl Number {
    pub fn from_f64(n: f64) -> Option<Self> {
        n.is_finite().then_some(Self::Float(n))
    }
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Unsigned(n) => Some(n),
            Self::Signed(n) => n.try_into().ok(),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Signed(n) => Some(n),
            Self::Unsigned(n) => n.try_into().ok(),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        Some(match *self {
            Self::Signed(n) => n as f64,
            Self::Unsigned(n) => n as f64,
            Self::Float(n) => n,
        })
    }
}
impl From<u64> for Number {
    fn from(n: u64) -> Self {
        Self::Unsigned(n)
    }
}
impl From<i64> for Number {
    fn from(n: i64) -> Self {
        if n >= 0 {
            Self::Unsigned(n as u64)
        } else {
            Self::Signed(n)
        }
    }
}
impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(n) => write!(f, "{n}"),
            Self::Signed(n) => write!(f, "{n}"),
            Self::Float(n) => {
                let s = n.to_string();
                f.write_str(&s)?;
                if !s.contains(['.', 'e', 'E']) {
                    f.write_str(".0")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Map<String, Value>),
}
impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_object(&self) -> Option<&Map<String, Value>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_object_mut(&mut self) -> Option<&mut Map<String, Value>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        if let Self::Number(n) = self {
            n.as_u64()
        } else {
            None
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        if let Self::Number(n) = self {
            n.as_i64()
        } else {
            None
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        if let Self::Number(n) = self {
            n.as_f64()
        } else {
            None
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    pub fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }
    pub fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }
    pub fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }
    pub fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }
    pub fn is_f64(&self) -> bool {
        matches!(self, Self::Number(Number::Float(_)))
    }
    pub fn get<I: ValueIndex>(&self, index: I) -> Option<&Value> {
        index.lookup(self)
    }
    pub fn get_mut<I: ValueIndex>(&mut self, index: I) -> Option<&mut Value> {
        index.lookup_mut(self)
    }
    pub fn take(&mut self) -> Value {
        std::mem::take(self)
    }
    pub fn pointer(&self, path: &str) -> Option<&Value> {
        if path.is_empty() {
            return Some(self);
        }
        let mut current = self;
        for part in path.strip_prefix('/')?.split('/') {
            let key = part.replace("~1", "/").replace("~0", "~");
            current = match current {
                Self::Object(m) => m.get(&key)?,
                Self::Array(a) => {
                    if key.starts_with('+') || (key.len() > 1 && key.starts_with('0')) {
                        return None;
                    }
                    a.get(key.parse::<usize>().ok()?)?
                }
                _ => return None,
            };
        }
        Some(current)
    }
}
pub trait ValueIndex {
    fn lookup(self, v: &Value) -> Option<&Value>;
    fn lookup_mut(self, v: &mut Value) -> Option<&mut Value>;
}
impl ValueIndex for &str {
    fn lookup(self, v: &Value) -> Option<&Value> {
        v.as_object()?.get(self)
    }
    fn lookup_mut(self, v: &mut Value) -> Option<&mut Value> {
        v.as_object_mut()?.get_mut(self)
    }
}
impl ValueIndex for &String {
    fn lookup(self, v: &Value) -> Option<&Value> {
        self.as_str().lookup(v)
    }
    fn lookup_mut(self, v: &mut Value) -> Option<&mut Value> {
        self.as_str().lookup_mut(v)
    }
}
impl ValueIndex for usize {
    fn lookup(self, v: &Value) -> Option<&Value> {
        v.as_array()?.get(self)
    }
    fn lookup_mut(self, v: &mut Value) -> Option<&mut Value> {
        v.as_array_mut()?.get_mut(self)
    }
}
static NULL: Value = Value::Null;
impl<I: ValueIndex> Index<I> for Value {
    type Output = Value;
    fn index(&self, i: I) -> &Value {
        i.lookup(self).unwrap_or(&NULL)
    }
}
impl IndexMut<&str> for Value {
    fn index_mut(&mut self, key: &str) -> &mut Value {
        if self.is_null() {
            *self = Self::Object(Map::new());
        }
        self.as_object_mut()
            .expect("JSON object required for insertion")
            .entry(key.into())
            .or_default()
    }
}
impl IndexMut<usize> for Value {
    fn index_mut(&mut self, i: usize) -> &mut Value {
        &mut self.as_array_mut().expect("JSON array required")[i]
    }
}
impl IndexMut<&String> for Value {
    fn index_mut(&mut self, k: &String) -> &mut Value {
        &mut self[k.as_str()]
    }
}
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_string(self).map_err(|_| fmt::Error)?)
    }
}
impl PartialEq<str> for Value {
    fn eq(&self, s: &str) -> bool {
        self.as_str() == Some(s)
    }
}
impl PartialEq<&str> for Value {
    fn eq(&self, s: &&str) -> bool {
        self.as_str() == Some(*s)
    }
}
impl PartialEq<String> for Value {
    fn eq(&self, s: &String) -> bool {
        self.as_str() == Some(s.as_str())
    }
}
impl PartialEq<Value> for String {
    fn eq(&self, v: &Value) -> bool {
        v == self
    }
}
impl PartialEq<bool> for Value {
    fn eq(&self, b: &bool) -> bool {
        self.as_bool() == Some(*b)
    }
}
macro_rules! compare_num { ($($t:ty),*)=>{$(impl PartialEq<$t> for Value {fn eq(&self,n:&$t)->bool{self==&to_value(n).expect("number")}})*}; }
compare_num!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

#[derive(Clone, Debug)]
pub struct Error;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid JSON or unsupported fields")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Ordered encoding preserves declaration order for protocol commitments.
pub enum Encoded {
    Invalid,
    Value(Value),
    Array(Vec<Encoded>),
    Object(Vec<(String, Encoded)>),
}
impl Encoded {
    fn value(self) -> Result<Value> {
        match self {
            Self::Invalid => Err(Error),
            Self::Value(v) => Ok(v),
            Self::Array(a) => Ok(Value::Array(
                a.into_iter().map(Self::value).collect::<Result<_>>()?,
            )),
            Self::Object(m) => Ok(Value::Object(
                m.into_iter()
                    .map(|(k, v)| Ok((k, v.value()?)))
                    .collect::<Result<_>>()?,
            )),
        }
    }
    fn write(&self, out: &mut String, pretty: bool, depth: usize) -> Result<()> {
        if depth > 128 {
            return Err(Error);
        }
        match self {
            Self::Invalid => return Err(Error),
            Self::Value(v) => write_value(v, out, pretty, depth)?,
            Self::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    indent(out, pretty, depth + 1);
                    v.write(out, pretty, depth + 1)?;
                }
                if !a.is_empty() {
                    indent(out, pretty, depth);
                }
                out.push(']');
            }
            Self::Object(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    indent(out, pretty, depth + 1);
                    quote(k, out);
                    out.push(':');
                    if pretty {
                        out.push(' ');
                    }
                    v.write(out, pretty, depth + 1)?;
                }
                if !m.is_empty() {
                    indent(out, pretty, depth);
                }
                out.push('}');
            }
        }
        Ok(())
    }
}
fn write_value(value: &Value, out: &mut String, pretty: bool, depth: usize) -> Result<()> {
    if depth > 128 {
        return Err(Error);
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::String(s) => quote(s, out),
        Value::Number(n) => {
            if n.as_f64().is_none_or(|n| !n.is_finite()) {
                return Err(Error);
            }
            out.push_str(&n.to_string());
        }
        Value::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(out, pretty, depth + 1);
                write_value(v, out, pretty, depth + 1)?;
            }
            if !a.is_empty() {
                indent(out, pretty, depth);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (key, value)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(out, pretty, depth + 1);
                quote(key, out);
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                write_value(value, out, pretty, depth + 1)?;
            }
            if !m.is_empty() {
                indent(out, pretty, depth);
            }
            out.push('}');
        }
    }
    Ok(())
}
fn indent(out: &mut String, pretty: bool, depth: usize) {
    if pretty {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', depth * 2));
    }
}
fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c < ' ' => {
                use fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
pub trait Serialize {
    fn encode(&self) -> Encoded;
}
pub trait Deserialize: Sized {
    fn decode(value: Value) -> Result<Self>;
}
pub mod de {
    pub trait DeserializeOwned: super::Deserialize {}
    impl<T: super::Deserialize> DeserializeOwned for T {}
}
pub fn to_value<T: Serialize>(v: T) -> Result<Value> {
    v.encode().value()
}
pub fn from_value<T: Deserialize>(v: Value) -> Result<T> {
    T::decode(v)
}
pub fn from_str<T: Deserialize>(s: &str) -> Result<T> {
    T::decode(parser::parse(s)?)
}
pub fn from_slice<T: Deserialize>(s: &[u8]) -> Result<T> {
    from_str(std::str::from_utf8(s).map_err(|_| Error)?)
}
pub fn to_string<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    let mut s = String::new();
    v.encode().write(&mut s, false, 0)?;
    Ok(s)
}
pub fn to_string_pretty<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    let mut s = String::new();
    v.encode().write(&mut s, true, 0)?;
    Ok(s)
}
pub fn to_vec<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>> {
    Ok(to_string(v)?.into_bytes())
}
pub fn to_vec_pretty<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>> {
    Ok(to_string_pretty(v)?.into_bytes())
}
pub fn to_writer<T: Serialize + ?Sized>(
    mut writer: impl std::io::Write,
    v: &T,
) -> std::io::Result<()> {
    writer.write_all(&to_vec(v).map_err(std::io::Error::other)?)
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}
impl Serialize for std::path::Path {
    fn encode(&self) -> Encoded {
        self.to_str().map_or(Encoded::Invalid, Serialize::encode)
    }
}
impl Serialize for std::path::PathBuf {
    fn encode(&self) -> Encoded {
        self.as_path().encode()
    }
}
impl Serialize for Value {
    fn encode(&self) -> Encoded {
        Encoded::Value(self.clone())
    }
}
impl Deserialize for Value {
    fn decode(v: Value) -> Result<Self> {
        Ok(v)
    }
}
impl<T: Serialize + ?Sized> Serialize for &T {
    fn encode(&self) -> Encoded {
        (**self).encode()
    }
}
impl<T: Serialize + ?Sized> Serialize for Box<T> {
    fn encode(&self) -> Encoded {
        (**self).encode()
    }
}
impl<T: Deserialize> Deserialize for Box<T> {
    fn decode(v: Value) -> Result<Self> {
        Ok(Box::new(T::decode(v)?))
    }
}
impl Serialize for str {
    fn encode(&self) -> Encoded {
        Encoded::Value(Value::String(self.into()))
    }
}
impl Serialize for String {
    fn encode(&self) -> Encoded {
        self.as_str().encode()
    }
}
impl Deserialize for String {
    fn decode(v: Value) -> Result<Self> {
        if let Value::String(s) = v {
            Ok(s)
        } else {
            Err(Error)
        }
    }
}
impl Serialize for bool {
    fn encode(&self) -> Encoded {
        Encoded::Value(Value::Bool(*self))
    }
}
impl Deserialize for bool {
    fn decode(v: Value) -> Result<Self> {
        v.as_bool().ok_or(Error)
    }
}
impl<T: Serialize> Serialize for Option<T> {
    fn encode(&self) -> Encoded {
        self.as_ref()
            .map_or(Encoded::Value(Value::Null), Serialize::encode)
    }
}
impl<T: Deserialize> Deserialize for Option<T> {
    fn decode(v: Value) -> Result<Self> {
        if v.is_null() {
            Ok(None)
        } else {
            Ok(Some(T::decode(v)?))
        }
    }
}
impl<T: Serialize> Serialize for [T] {
    fn encode(&self) -> Encoded {
        Encoded::Array(self.iter().map(Serialize::encode).collect())
    }
}
impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn encode(&self) -> Encoded {
        self.as_slice().encode()
    }
}
impl<T: Serialize> Serialize for Vec<T> {
    fn encode(&self) -> Encoded {
        self.as_slice().encode()
    }
}
impl<T: Deserialize> Deserialize for Vec<T> {
    fn decode(v: Value) -> Result<Self> {
        if let Value::Array(v) = v {
            v.into_iter().map(T::decode).collect()
        } else {
            Err(Error)
        }
    }
}
impl<T: Serialize> Serialize for Map<String, T> {
    fn encode(&self) -> Encoded {
        Encoded::Object(self.iter().map(|(k, v)| (k.clone(), v.encode())).collect())
    }
}
impl<T: Deserialize> Deserialize for Map<String, T> {
    fn decode(v: Value) -> Result<Self> {
        if let Value::Object(v) = v {
            v.into_iter().map(|(k, v)| Ok((k, T::decode(v)?))).collect()
        } else {
            Err(Error)
        }
    }
}
macro_rules! integers {($($t:ty => $variant:ident, $access:ident),*)=>{$(
    impl Serialize for $t{fn encode(&self)->Encoded{let n=Number::$variant(*self as _); Encoded::Value(Value::Number(match n {Number::Signed(n) if n>=0=>Number::Unsigned(n as u64),n=>n}))}}
    impl Deserialize for $t{fn decode(v:Value)->Result<Self>{v.$access().and_then(|n|n.try_into().ok()).ok_or(Error)}}
)*};}
integers!(u8=>Unsigned,as_u64,u16=>Unsigned,as_u64,u32=>Unsigned,as_u64,u64=>Unsigned,as_u64,usize=>Unsigned,as_u64,i8=>Signed,as_i64,i16=>Signed,as_i64,i32=>Signed,as_i64,i64=>Signed,as_i64,isize=>Signed,as_i64);
impl Serialize for f64 {
    fn encode(&self) -> Encoded {
        Encoded::Value(Number::from_f64(*self).map_or(Value::Null, Value::Number))
    }
}
impl Deserialize for f64 {
    fn decode(v: Value) -> Result<Self> {
        v.as_f64().ok_or(Error)
    }
}

#[macro_export]
macro_rules! json {
    ({})=>{$crate::Value::Object($crate::Map::new())};
    ([])=>{$crate::Value::Array(Vec::new())};
    (null)=>{$crate::Value::Null};
    ([$($v:tt)*])=>{{let mut a=Vec::new();$crate::json!(@array a; $($v)*);$crate::Value::Array(a)}};
    ({$($v:tt)*})=>{{let mut m=$crate::Map::new();$crate::json!(@object m; $($v)*);$crate::Value::Object(m)}};
    (@array $a:ident;)=>{};
    (@array $a:ident; null $(,$($rest:tt)*)?)=>{{$a.push($crate::Value::Null);$crate::json!(@array $a; $($($rest)*)?);}};
    (@array $a:ident; [$($v:tt)*] $(,$($rest:tt)*)?)=>{{$a.push($crate::json!([$($v)*]));$crate::json!(@array $a; $($($rest)*)?);}};
    (@array $a:ident; {$($v:tt)*} $(,$($rest:tt)*)?)=>{{$a.push($crate::json!({$($v)*}));$crate::json!(@array $a; $($($rest)*)?);}};
    (@array $a:ident; $v:expr $(,$($rest:tt)*)?)=>{{$a.push($crate::to_value(&$v).expect("JSON encoding"));$crate::json!(@array $a; $($($rest)*)?);}};
    (@object $m:ident;)=>{};
    (@object $m:ident; $k:tt : null $(,$($rest:tt)*)?)=>{{$m.insert(($k).to_string(),$crate::Value::Null);$crate::json!(@object $m; $($($rest)*)?);}};
    (@object $m:ident; $k:tt : [$($v:tt)*] $(,$($rest:tt)*)?)=>{{$m.insert(($k).to_string(),$crate::json!([$($v)*]));$crate::json!(@object $m; $($($rest)*)?);}};
    (@object $m:ident; $k:tt : {$($v:tt)*} $(,$($rest:tt)*)?)=>{{$m.insert(($k).to_string(),$crate::json!({$($v)*}));$crate::json!(@object $m; $($($rest)*)?);}};
    (@object $m:ident; $k:tt : $v:expr $(,$($rest:tt)*)?)=>{{$m.insert(($k).to_string(),$crate::to_value(&$v).expect("JSON encoding"));$crate::json!(@object $m; $($($rest)*)?);}};
    ($v:expr)=>{$crate::to_value(&$v).expect("JSON encoding")};
}
