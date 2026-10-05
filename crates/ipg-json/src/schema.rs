use crate::{Map, Value, json};
pub type Schema = Value;
pub trait JsonSchema {
    fn schema_name() -> String {
        std::any::type_name::<Self>().into()
    }
    fn inline() -> bool {
        true
    }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema;
}
#[derive(Default)]
pub struct SchemaGenerator {
    root: String,
    definitions: Map<String, Value>,
}
impl SchemaGenerator {
    pub fn subschema_for<T: JsonSchema + ?Sized>(&mut self) -> Schema {
        if T::inline() {
            return T::json_schema(self);
        }
        let name = T::schema_name();
        if name == self.root {
            return json!({"$ref":"#"});
        }
        if !self.definitions.contains_key(&name) {
            self.definitions.insert(name.clone(), Value::Null);
            let schema = T::json_schema(self);
            self.definitions.insert(name.clone(), schema);
        }
        json!({"$ref":format!("#/$defs/{name}")})
    }
}
pub fn schema_for<T: JsonSchema + ?Sized>() -> Schema {
    let mut generator = SchemaGenerator {
        root: T::schema_name(),
        definitions: Map::new(),
    };
    let mut schema = T::json_schema(&mut generator);
    schema["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    schema["title"] = json!(T::schema_name());
    if !generator.definitions.is_empty() {
        schema["$defs"] = Value::Object(generator.definitions);
    }
    schema
}
impl Value {
    pub fn insert(&mut self, key: String, value: Value) -> Option<Value> {
        if self.is_null() {
            *self = Value::Object(Map::new());
        }
        self.as_object_mut()
            .expect("schema object")
            .insert(key, value)
    }
}
impl JsonSchema for str {
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json!({"type":"string"})
    }
}
impl JsonSchema for String {
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        str::json_schema(g)
    }
}
impl JsonSchema for bool {
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json!({"type":"boolean"})
    }
}
impl JsonSchema for Value {
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json!(true)
    }
}
impl<T: JsonSchema + ?Sized> JsonSchema for &T {
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        g.subschema_for::<T>()
    }
}
impl<T: JsonSchema + ?Sized> JsonSchema for Box<T> {
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        g.subschema_for::<T>()
    }
}
impl<T: JsonSchema> JsonSchema for Option<T> {
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        let mut schema = g.subschema_for::<T>();
        if let Some(Value::String(kind)) = schema.get("type") {
            let kind = kind.clone();
            schema["type"] = json!([kind, "null"]);
            schema
        } else {
            json!({"anyOf":[schema,{"type":"null"}]})
        }
    }
}
impl<T: JsonSchema> JsonSchema for Vec<T> {
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        json!({"type":"array","items":g.subschema_for::<T>()})
    }
}
macro_rules! unsigned{($($t:ty),*)=>{$(impl JsonSchema for $t{fn json_schema(_: &mut SchemaGenerator)->Schema{json!({"type":"integer","format":if stringify!($t)=="usize" { "uint".to_string() } else {format!("uint{}",&stringify!($t)[1..])},"minimum":0})}})*};}
unsigned!(u8, u16, u32, u64, usize);
macro_rules! signed{($($t:ty),*)=>{$(impl JsonSchema for $t{fn json_schema(_: &mut SchemaGenerator)->Schema{json!({"type":"integer","format":if stringify!($t)=="isize" { "int".to_string() } else {format!("int{}",&stringify!($t)[1..])}})}})*};}
signed!(i8, i16, i32, i64, isize);
#[macro_export]
macro_rules! json_schema{($($t:tt)*)=>{$crate::json!($($t)*)};}
#[macro_export]
macro_rules! schema_for {
    ($t:ty) => {
        $crate::schema_for::<$t>()
    };
}
