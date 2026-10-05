//! Narrow native derives for IPG's named structs and tagged/unit enums.
//! Unsupported serialization annotations fail compilation rather than being ignored.
#![forbid(unsafe_code)]
use proc_macro::{Delimiter, TokenStream, TokenTree};
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T, String>;
#[derive(Default)]
struct Attrs {
    serde: BTreeMap<String, String>,
    schema: BTreeMap<String, String>,
    docs: Vec<String>,
}
struct Field {
    name: String,
    ty: String,
    attrs: Attrs,
}
struct Variant {
    name: String,
    fields: Option<Vec<Field>>,
    attrs: Attrs,
}
struct Item {
    name: String,
    fields: Option<Vec<Field>>,
    variants: Vec<Variant>,
    attrs: Attrs,
}
fn tokens(s: TokenStream) -> Vec<TokenTree> {
    s.into_iter().collect()
}
fn text(t: &[TokenTree]) -> String {
    t.iter().cloned().collect::<TokenStream>().to_string()
}
fn split(t: Vec<TokenTree>) -> Vec<Vec<TokenTree>> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0;
    for token in t {
        if let TokenTree::Punct(p) = &token {
            match p.as_char() {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => {
                    if !current.is_empty() {
                        out.push(std::mem::take(&mut current));
                    }
                    continue;
                }
                _ => {}
            }
        }
        current.push(token);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
fn unquote(s: &str) -> Result<String> {
    if s.contains('\\') {
        return Err("Escaped contract names are unsupported".into());
    }
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(str::to_string)
        .ok_or_else(|| "Expected string annotation".into())
}
fn validate_attrs(a: &Attrs, allowed: &[&str], schema: &[&str]) -> Result<()> {
    if a.serde.keys().any(|k| !allowed.contains(&k.as_str()))
        || a.schema.keys().any(|k| !schema.contains(&k.as_str()))
    {
        return Err("Contract annotation is not supported in this position".into());
    }
    for key in ["default", "deny_unknown_fields"] {
        if a.serde.get(key).is_some_and(|s| !s.is_empty()) {
            return Err("Contract flag cannot have an argument".into());
        }
    }
    Ok(())
}
fn unique_fields(fields: &[Field], tag: Option<&str>) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    if let Some(tag) = tag {
        names.insert(tag.to_string());
    }
    for field in fields {
        if !names.insert(wire_name(field)?) {
            return Err("Duplicate JSON field or discriminator".into());
        }
    }
    Ok(())
}
fn parse_attrs(t: &mut Vec<TokenTree>) -> Result<Attrs> {
    let mut out = Attrs::default();
    while t.first().is_some_and(|t| t.to_string() == "#") {
        t.remove(0);
        let Some(TokenTree::Group(g)) = t.first() else {
            return Err("Malformed attribute".into());
        };
        let a = tokens(g.stream());
        let name = a.first().ok_or("Empty attribute")?.to_string();
        if name == "doc" {
            if a.len() != 3 {
                return Err("Malformed documentation".into());
            }
            out.docs.push(a[2].to_string());
        } else if name == "serde" || name == "schemars" {
            let Some(TokenTree::Group(args)) = a.get(1) else {
                return Err("Malformed contract annotation".into());
            };
            for part in split(tokens(args.stream())) {
                let key = part[0].to_string();
                let value = if part.len() == 1 {
                    String::new()
                } else if part.get(1).is_some_and(|t| t.to_string() == "=") {
                    text(&part[2..])
                } else if let TokenTree::Group(g) = &part[1] {
                    g.stream().to_string()
                } else {
                    return Err("Unsupported annotation".into());
                };
                let allowed = if name == "serde" {
                    [
                        "rename",
                        "rename_all",
                        "tag",
                        "deny_unknown_fields",
                        "default",
                        "skip_serializing_if",
                    ]
                    .contains(&key.as_str())
                } else {
                    ["schema_with", "transform", "length"].contains(&key.as_str())
                };
                if !allowed {
                    return Err(format!("Unsupported {name} annotation: {key}"));
                }
                let map = if name == "serde" {
                    &mut out.serde
                } else {
                    &mut out.schema
                };
                if map.insert(key, value).is_some() {
                    return Err("Duplicate contract annotation".into());
                }
            }
        }
        t.remove(0);
    }
    Ok(out)
}
fn fields(stream: TokenStream) -> Result<Vec<Field>> {
    split(tokens(stream))
        .into_iter()
        .map(|mut t| {
            let attrs = parse_attrs(&mut t)?;
            validate_attrs(
                &attrs,
                &["rename", "default", "skip_serializing_if"],
                &["schema_with", "length"],
            )?;
            if t.first().is_some_and(|t| t.to_string() == "pub") {
                t.remove(0);
                if matches!(t.first(), Some(TokenTree::Group(_))) {
                    t.remove(0);
                }
            }
            if t.len() < 3 || t[1].to_string() != ":" {
                return Err("Native codec needs named fields".into());
            }
            Ok(Field {
                name: t[0].to_string(),
                ty: text(&t[2..]),
                attrs,
            })
        })
        .collect()
}
fn parse(stream: TokenStream) -> Result<Item> {
    let mut t = tokens(stream);
    let attrs = parse_attrs(&mut t)?;
    if t.first().is_some_and(|t| t.to_string() == "pub") {
        t.remove(0);
        if matches!(t.first(), Some(TokenTree::Group(_))) {
            t.remove(0);
        }
    }
    let kind = t.first().ok_or("Missing type")?.to_string();
    let name = t.get(1).ok_or("Missing type name")?.to_string();
    let Some(TokenTree::Group(body)) = t.get(2) else {
        return Err("Generic/tuple types are not supported by native derives".into());
    };
    if body.delimiter() != Delimiter::Brace || t.len() != 3 {
        return Err("Unsupported type declaration".into());
    }
    if kind == "struct" {
        validate_attrs(&attrs, &["deny_unknown_fields"], &["transform"])?;
        let fields = fields(body.stream())?;
        unique_fields(&fields, None)?;
        return Ok(Item {
            name,
            fields: Some(fields),
            variants: Vec::new(),
            attrs,
        });
    }
    if kind != "enum" {
        return Err("Only structs and enums have native JSON contracts".into());
    }
    validate_attrs(
        &attrs,
        &["tag", "rename_all", "deny_unknown_fields"],
        &["transform"],
    )?;
    let variants = split(tokens(body.stream()))
        .into_iter()
        .map(|mut t| {
            let attrs = parse_attrs(&mut t)?;
            validate_attrs(&attrs, &["rename"], &[])?;
            let name = t.first().ok_or("Missing variant")?.to_string();
            let fields = if t.len() == 1 {
                None
            } else if t.len() == 2 {
                if let TokenTree::Group(g) = &t[1] {
                    if g.delimiter() != Delimiter::Brace {
                        return Err("Tuple variant unsupported".into());
                    }
                    Some(fields(g.stream())?)
                } else {
                    return Err("Variant discriminants unsupported".into());
                }
            } else {
                return Err("Unsupported variant".into());
            };
            Ok(Variant {
                name,
                fields,
                attrs,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if variants.iter().any(|v| v.fields.is_some()) && !attrs.serde.contains_key("tag") {
        return Err("Data enum must be explicitly tagged".into());
    }
    let tag = attrs.serde.get("tag").map(|s| unquote(s)).transpose()?;
    let mut names = std::collections::BTreeSet::new();
    for variant in &variants {
        if !names.insert(renamed(&variant.name, &variant.attrs, &attrs)?) {
            return Err("Duplicate JSON variant discriminator".into());
        }
        if let Some(fields) = &variant.fields {
            unique_fields(fields, tag.as_deref())?;
        } else if tag.is_some() {
            return Err("Tagged variants require named fields (possibly empty)".into());
        }
    }
    Ok(Item {
        name,
        fields: None,
        variants,
        attrs,
    })
}
fn renamed(name: &str, attrs: &Attrs, parent: &Attrs) -> Result<String> {
    if let Some(s) = attrs.serde.get("rename") {
        return unquote(s);
    }
    match parent
        .serde
        .get("rename_all")
        .map(|s| unquote(s))
        .transpose()?
        .as_deref()
    {
        None => Ok(name.into()),
        Some("lowercase") => Ok(name.to_lowercase()),
        Some("snake_case") => {
            let mut out = String::new();
            for (i, c) in name.chars().enumerate() {
                if c.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.extend(c.to_lowercase());
            }
            Ok(out)
        }
        _ => Err("Unsupported rename_all".into()),
    }
}
fn optional(f: &Field) -> bool {
    f.ty.replace(' ', "").starts_with("Option<")
}
fn wire_name(f: &Field) -> Result<String> {
    renamed(&f.name, &f.attrs, &Attrs::default())
}
fn serialize_fields(fs: &[Field], prefix: &str, tag: Option<(&str, &str)>) -> Result<String> {
    let mut body = "let mut fields=Vec::new();".to_string();
    if let Some((key, value)) = tag {
        body += &format!("fields.push(({key:?}.into(),ipg_json::Serialize::encode({value:?}))); ");
    }
    for f in fs {
        let key = wire_name(f)?;
        let value = format!("{prefix}{}", f.name);
        let statement =
            format!("fields.push(({key:?}.into(),ipg_json::Serialize::encode(&{value}))); ");
        if let Some(skip) = f.attrs.serde.get("skip_serializing_if") {
            if unquote(skip)? != "Option::is_none" || !optional(f) {
                return Err("Only Option::is_none omission is supported".into());
            }
            body += &format!("if !{value}.is_none(){{{statement}}}");
        } else {
            body += &statement;
        }
    }
    body += "ipg_json::Encoded::Object(fields)";
    Ok(body)
}
fn serialize(item: &Item) -> Result<String> {
    let body = if let Some(fs) = &item.fields {
        serialize_fields(fs, "self.", None)?
    } else {
        let tag = item
            .attrs
            .serde
            .get("tag")
            .map(|s| unquote(s))
            .transpose()?;
        let mut body = "match self {".to_string();
        for v in &item.variants {
            let wire = renamed(&v.name, &v.attrs, &item.attrs)?;
            if let Some(fs) = &v.fields {
                let names = fs
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                let content = serialize_fields(fs, "", tag.as_deref().map(|t| (t, wire.as_str())))?;
                body += &format!("Self::{}{{{names}}}=>{{{content}}},", v.name);
            } else {
                body += &format!("Self::{}=>ipg_json::Serialize::encode({wire:?}),", v.name);
            }
        }
        body += "}";
        body
    };
    Ok(format!(
        "#[allow(unused_mut,unused_variables)] impl ipg_json::Serialize for {}{{fn encode(&self)->ipg_json::Encoded{{{body}}}}}",
        item.name
    ))
}
fn deserialize_fields(fs: &[Field], ctor: &str, deny: bool) -> Result<String> {
    let mut body = String::new();
    for f in fs {
        let key = wire_name(f)?;
        let missing = if f.attrs.serde.contains_key("default") {
            let default = &f.attrs.serde["default"];
            if !default.is_empty() {
                return Err("Custom default functions unsupported".into());
            }
            "Default::default()"
        } else if optional(f) {
            "None"
        } else {
            "return Err(ipg_json::Error)"
        };
        body += &format!(
            "let {}: {}=match fields.remove({key:?}){{Some(v)=>ipg_json::Deserialize::decode(v)?,None=>{missing}}};",
            f.name, f.ty
        );
    }
    if deny {
        body += "if !fields.is_empty(){return Err(ipg_json::Error);}";
    }
    let names = fs
        .iter()
        .map(|f| f.name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    body += &format!("Ok({ctor}{{{names}}})");
    Ok(body)
}
fn deserialize(item: &Item) -> Result<String> {
    let deny = item.attrs.serde.contains_key("deny_unknown_fields");
    let body = if let Some(fs) = &item.fields {
        format!(
            "let ipg_json::Value::Object(mut fields)=value else{{return Err(ipg_json::Error);}};{}",
            deserialize_fields(fs, "Self", deny)?
        )
    } else {
        let tag = item
            .attrs
            .serde
            .get("tag")
            .map(|s| unquote(s))
            .transpose()?;
        let mut body = if let Some(tag) = &tag {
            format!(
                "let ipg_json::Value::Object(mut fields)=value else{{return Err(ipg_json::Error);}};let discriminator:String=ipg_json::Deserialize::decode(fields.remove({tag:?}).ok_or(ipg_json::Error)?)?;match discriminator.as_str(){{"
            )
        } else {
            "let discriminator:String=ipg_json::Deserialize::decode(value)?;match discriminator.as_str(){".into()
        };
        for v in &item.variants {
            let wire = renamed(&v.name, &v.attrs, &item.attrs)?;
            let arm = if let Some(fs) = &v.fields {
                deserialize_fields(fs, &format!("Self::{}", v.name), deny)?
            } else {
                format!("Ok(Self::{})", v.name)
            };
            body += &format!("{wire:?}=>{{{arm}}},");
        }
        body += "_=>Err(ipg_json::Error)}";
        body
    };
    Ok(format!(
        "#[allow(unused_mut,unused_variables)] impl ipg_json::Deserialize for {}{{fn decode(value:ipg_json::Value)->ipg_json::Result<Self>{{{body}}}}}",
        item.name
    ))
}
fn docs(attrs: &Attrs, var: &str) -> String {
    if attrs.docs.is_empty() {
        return String::new();
    }
    let docs = attrs
        .docs
        .iter()
        .map(|s| format!("({s}).trim()"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{var}[\"description\"]=ipg_json::json!([{docs}].join(\"\\n\"));")
}
fn field_schema(f: &Field) -> Result<String> {
    let mut out = if let Some(path) = f.attrs.schema.get("schema_with") {
        format!("let mut field={} (generator);", unquote(path)?)
    } else {
        format!("let mut field=generator.subschema_for::<{}>();", f.ty)
    };
    if let Some(bounds) = f.attrs.schema.get("length") {
        for part in split(tokens(bounds.parse().map_err(|_| "Invalid length bounds")?)) {
            if part.len() < 3 || part[1].to_string() != "=" {
                return Err("Malformed length bound".into());
            }
            let array = f.ty.replace(' ', "").starts_with("Vec<");
            let name = match (part[0].to_string().as_str(), array) {
                ("min", false) => "minLength",
                ("max", false) => "maxLength",
                ("min", true) => "minItems",
                ("max", true) => "maxItems",
                _ => return Err("Unknown length bound".into()),
            };
            out += &format!("field[{name:?}]=ipg_json::json!({});", text(&part[2..]));
        }
    }
    if f.attrs.serde.contains_key("default") && !f.attrs.serde.contains_key("skip_serializing_if") {
        out += &format!(
            "field[\"default\"]=ipg_json::to_value(<{} as Default>::default()).expect(\"default JSON\");",
            f.ty
        );
    }
    out += &docs(&f.attrs, "field");
    out += "field";
    Ok(out)
}
fn object_schema(fs: &[Field], tag: Option<(&str, &str)>, deny: bool) -> Result<String> {
    let mut body =
        "let mut properties=ipg_json::Map::new();let mut required:Vec<String>=Vec::new();"
            .to_string();
    if let Some((tag, wire)) = tag {
        body += &format!(
            "properties.insert({tag:?}.into(),ipg_json::json!({{\"type\":\"string\",\"const\":{wire:?}}}));required.push({tag:?}.into());"
        );
    }
    for f in fs {
        let name = wire_name(f)?;
        body += &format!(
            "properties.insert({name:?}.into(),{{{}}});",
            field_schema(f)?
        );
        if !optional(f) && !f.attrs.serde.contains_key("default") {
            body += &format!("required.push({name:?}.into());");
        }
    }
    body += "let mut schema=ipg_json::json!({\"type\":\"object\"});if !properties.is_empty(){schema[\"properties\"]=ipg_json::Value::Object(properties);}if !required.is_empty(){schema[\"required\"]=ipg_json::json!(required);}";
    if deny {
        body += "schema[\"additionalProperties\"]=ipg_json::json!(false);";
    }
    body += "schema";
    Ok(body)
}
fn schema(item: &Item) -> Result<String> {
    let deny = item.attrs.serde.contains_key("deny_unknown_fields");
    let body = if let Some(fs) = &item.fields {
        object_schema(fs, None, deny)?
    } else {
        let tag = item
            .attrs
            .serde
            .get("tag")
            .map(|s| unquote(s))
            .transpose()?;
        if tag.is_none() && item.variants.iter().all(|v| v.attrs.docs.is_empty()) {
            let names = item
                .variants
                .iter()
                .map(|v| renamed(&v.name, &v.attrs, &item.attrs).map(|s| format!("{s:?}")))
                .collect::<Result<Vec<_>>>()?
                .join(",");
            format!("ipg_json::json!({{\"type\":\"string\",\"enum\":[{names}]}})")
        } else {
            let mut arms = Vec::new();
            for v in &item.variants {
                let wire = renamed(&v.name, &v.attrs, &item.attrs)?;
                let content = if let Some(fs) = &v.fields {
                    object_schema(fs, tag.as_deref().map(|t| (t, wire.as_str())), deny)?
                } else if v.attrs.docs.is_empty() {
                    format!("ipg_json::json!({{\"type\":\"string\",\"enum\":[{wire:?}]}})")
                } else {
                    format!("ipg_json::json!({{\"type\":\"string\",\"const\":{wire:?}}})")
                };
                arms.push(format!(
                    "({{let mut variant={{{content}}};{}variant}})",
                    docs(&v.attrs, "variant")
                ));
            }
            format!("ipg_json::json!({{\"oneOf\":[{}]}})", arms.join(","))
        }
    };
    let transform = item
        .attrs
        .schema
        .get("transform")
        .map(|path| format!("{path}(&mut schema);"))
        .unwrap_or_default();
    Ok(format!(
        "#[allow(unused_mut,unused_variables)] impl ipg_json::JsonSchema for {}{{fn schema_name()->String{{{:?}.into()}}fn inline()->bool{{false}}fn json_schema(generator:&mut ipg_json::SchemaGenerator)->ipg_json::Schema{{let mut schema={{{body}}};{}{transform}schema}}}}",
        item.name,
        item.name,
        docs(&item.attrs, "schema")
    ))
}
fn derive(input: TokenStream, emit: fn(&Item) -> Result<String>) -> TokenStream {
    match parse(input).and_then(|i| emit(&i)).and_then(|s| {
        s.parse()
            .map_err(|_| "Native derive generated invalid Rust".into())
    }) {
        Ok(output) => output,
        Err(error) => format!("compile_error!({error:?});")
            .parse()
            .expect("compile error literal"),
    }
}
#[proc_macro_derive(Serialize, attributes(serde, schemars))]
pub fn serialize_derive(input: TokenStream) -> TokenStream {
    derive(input, serialize)
}
#[proc_macro_derive(Deserialize, attributes(serde, schemars))]
pub fn deserialize_derive(input: TokenStream) -> TokenStream {
    derive(input, deserialize)
}
#[proc_macro_derive(JsonSchema, attributes(serde, schemars))]
pub fn schema_derive(input: TokenStream) -> TokenStream {
    derive(input, schema)
}
