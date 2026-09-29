//! Regenerate the checked-in contracts from the executable Rust definitions.
use std::{fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::create_dir_all(root.join("ontology"))?;
    fs::create_dir_all(root.join("schemas"))?;
    fs::write(
        root.join("schemas/mcp-tools.json"),
        serde_json::to_vec_pretty(&iron_privacy_guardian::mcp::tool_catalog(
            &iron_privacy_guardian::mcp::Config::default(),
        ))?,
    )?;
    fs::write(
        root.join("ontology/knowledge.jsonld"),
        serde_json::to_vec_pretty(&iron_privacy_guardian::knowledge::export())?,
    )?;
    fs::write(
        root.join("ontology/apg.jsonld"),
        serde_json::to_vec_pretty(&iron_privacy_guardian::ontology::export())?,
    )?;
    for (name, schema) in iron_privacy_guardian::schemas()
        .as_object()
        .expect("schema map")
    {
        fs::write(
            root.join(format!("schemas/{name}.json")),
            serde_json::to_vec_pretty(schema)?,
        )?;
    }
    Ok(())
}
