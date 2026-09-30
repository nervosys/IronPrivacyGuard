//! Offline, curated application guidance. Selection never executes a tool.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const VERSION: &str = "1.16.0";

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub id: String,
    pub label: String,
    pub keywords: Vec<String>,
    pub goals: Vec<String>,
    pub support: Support,
    pub operations: Vec<String>,
    pub prerequisites: Vec<String>,
    pub limitations: Vec<String>,
    pub guidance: String,
    pub sources: Vec<String>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    Implemented,
    ExternalRequired,
}

pub fn applications() -> Vec<Application> {
    serde_json::from_str(include_str!("../knowledge/applications.json"))
        .expect("checked-in knowledgebase must satisfy its typed contract")
}

pub fn context() -> Value {
    json!({"@vocab":"urn:apg:v1:","apg":"urn:apg:v1:","ic":"urn:ironcrypto:algorithm:",
        "inputs":{"@type":"@id"},"optional_inputs":{"@type":"@id"},
        "outputs":{"@type":"@id"},"constraints":{"@type":"@id"},
        "algorithms":{"@type":"@id"},"tools":{"@type":"@id"},
        "goals":{"@type":"@id"},"sources":{"@type":"@id"}})
}

pub fn nodes() -> Vec<Value> {
    let mut nodes: Vec<Value> = serde_json::from_str(include_str!("../knowledge/primitives.json"))
        .expect("checked-in primitive knowledge must be valid JSON");
    let mut goals = BTreeSet::new();
    for app in applications() {
        goals.extend(app.goals.clone());
        nodes.push(json!({"@id":format!("apg:application/{}",app.id),
            "@type":"apg:CryptographicApplication", "id":app.id,"label":app.label,
            "keywords":app.keywords,"support":app.support,
            "goals":app.goals.iter().map(|s|format!("apg:goal/{s}")).collect::<Vec<_>>(),
            "tools":app.operations.iter().map(|s|format!("apg:operation/{s}")).collect::<Vec<_>>(),
            "prerequisites":app.prerequisites,"limitations":app.limitations,
            "guidance":app.guidance,"sources":app.sources}));
    }
    for goal in goals {
        nodes.push(
            json!({"@id":format!("apg:goal/{goal}"),"@type":"apg:SecurityGoal","label":goal}),
        );
    }
    nodes
}

pub fn export() -> Value {
    let mut graph = nodes();
    // Embed executable contracts so the standalone graph can resolve tool links.
    graph.extend(
        crate::ontology::OPERATIONS
            .iter()
            .map(|op| crate::ontology::operation(op.0)),
    );
    json!({"@context":context(),"@id":"apg:knowledgebase","version":VERSION,
        "reviewed":"2026-09-28","scope":"Curated APG application guidance, not exhaustive cryptography coverage",
        "advisory":true,"execution":false,
        "upstream_algorithms":{"operation":"algorithms","meaning":"Primitive availability does not imply APG protocol support"},
        "search":{"operation":"knowledge.search","query":"1..256 Unicode characters, at least one alphanumeric token; case-insensitive AND substring matching over IDs, labels, keywords, goals and operation names","ordering":"catalog order; no suitability ranking","no_match":"No recommendation; consult catalog or refine keywords"},
        "@graph":graph})
}

pub fn validate_query(query: &str) -> Result<()> {
    if !(1..=256).contains(&query.chars().count()) || !query.chars().any(char::is_alphanumeric) {
        return Err(Error::new(
            "invalid_request",
            "Knowledge query must contain 1..256 characters and at least one alphanumeric token",
        ));
    }
    Ok(())
}

pub fn search(query: &str) -> Result<Value> {
    validate_query(query)?;
    let lower = query.to_lowercase();
    let tokens: Vec<_> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let matches: Vec<_> = applications()
        .into_iter()
        .filter(|app| {
            // Exclude negative limitations and prerequisites from positive matching.
            let haystack = format!(
                "{} {} {} {} {}",
                app.id,
                app.label,
                app.keywords.join(" "),
                app.goals.join(" "),
                app.operations.join(" ")
            )
            .to_lowercase();
            tokens.iter().all(|token| haystack.contains(token))
        })
        .map(|app| {
            let tools: Vec<_> = app
                .operations
                .iter()
                .map(|id| crate::ontology::operation(id))
                .collect();
            json!({"application":app,"tools":tools})
        })
        .collect();
    Ok(
        json!({"knowledge_version":VERSION,"advisory":true,"execution":false,
        "status":if matches.is_empty(){"no_match"}else{"matches"},
        "matches":matches,"next_steps":["Check support, prerequisites and limitations for each match",
        "Read the selected operation schema; obtain required trusted pins and policy",
        "Use request.validate and plan before explicitly executing a request"],
        "authorization":"A match is not authorization, cryptographic validation, or proof of suitability"}),
    )
}
