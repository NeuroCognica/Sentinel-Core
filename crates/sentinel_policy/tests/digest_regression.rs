use sentinel_policy::{Policy, PolicyInput, policy_digest, input_digest};
use sentinel_policy::policy::{Statement, Condition, Effect, Op};
use serde_json::json;

#[test]
fn policy_and_input_digest_regression() {
    // Expected golden digests computed and frozen
    let expected_empty = "3d36383422149070fba884c607abac59784fe78be419f3f52bad6ed4e577cac5";
    let expected_allow_read = "3e92e9b14f0071c1a125faece0e57fe6912d9de835f57d522d0ef881de1fbc6c";
    let expected_input = "10c05cc658a92bec384fd5fcd5634bd07201cdaf8f22a223e8bed886cec1895a";

    let p_empty = Policy { id: "policy-x".to_string(), version: "v0".to_string(), statements: vec![] };
    assert_eq!(policy_digest(&p_empty), expected_empty);

    let p2 = Policy {
        id: "pid".to_string(),
        version: "v0".to_string(),
        statements: vec![Statement {
            when: vec![Condition { field: "action".to_string(), op: Op::Eq, value: "read".to_string() }],
            effect: Effect::Allow,
            rationale: "allow reads".to_string(),
        }],
    };
    assert_eq!(policy_digest(&p2), expected_allow_read);

    // Re-serialize with pretty whitespace and parse back -> digest must remain the same
    let pretty = serde_json::to_string_pretty(&p2).unwrap();
    let reparsed: Policy = serde_json::from_str(&pretty).unwrap();
    assert_eq!(policy_digest(&reparsed), expected_allow_read);

    // YAML equivalence: parse YAML then canonicalize
    let yaml = r#"
id: pid
version: v0
statements:
  - when:
      - field: action
        op: Eq
        value: read
    effect: Allow
    rationale: "allow reads"
"#;
    let from_yaml: Policy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(policy_digest(&from_yaml), expected_allow_read);

    // Input digest regression
    let inp = PolicyInput { subject: "alice".to_string(), action: "read".to_string(), resource: "r".to_string(), context: json!({}), envelope_digest: None };
    assert_eq!(input_digest(&inp), expected_input);

    // Different JSON formatting of input must not change digest
    let pretty_inp = serde_json::to_string_pretty(&inp).unwrap();
    let reparsed_inp: PolicyInput = serde_json::from_str(&pretty_inp).unwrap();
    assert_eq!(input_digest(&reparsed_inp), expected_input);
}
