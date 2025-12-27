use sentinel_policy::{Policy, PolicyInput, policy_digest, input_digest};
use sentinel_policy::policy::{Statement, Condition, Effect, Op};
use serde_json::json;
fn main() {
    let p = Policy { id: "policy-x".to_string(), version: "v0".to_string(), statements: vec![] };
    println!("policy-empty: {}", policy_digest(&p));

    let p2 = Policy {
        id: "pid".to_string(),
        version: "v0".to_string(),
        statements: vec![Statement {
            when: vec![Condition { field: "action".to_string(), op: Op::Eq, value: "read".to_string() }],
            effect: Effect::Allow,
            rationale: "allow reads".to_string(),
        }],
    };
    println!("policy-allow-read: {}", policy_digest(&p2));

    let inp = PolicyInput { subject: "alice".to_string(), action: "read".to_string(), resource: "r".to_string(), context: json!({}), envelope_digest: None };
    println!("input-alice-read: {}", input_digest(&inp));
}
