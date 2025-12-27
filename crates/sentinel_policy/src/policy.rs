use serde::{Deserialize, Serialize};

/// Minimal v0 policy schema (canonical): intentionally explicit and ordered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    /// Human label, non-authoritative
    pub id: String,
    /// Semantic version string
    pub version: String,
    /// Ordered statements
    pub statements: Vec<Statement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Statement {
    /// Conditions evaluated in order (all must match)
    pub when: Vec<Condition>,
    /// Effect: allow or deny
    pub effect: Effect,
    /// Rationale recorded verbatim
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Op {
    Eq,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Condition {
    /// Input field name (must be simple dot-free identifier for v0)
    pub field: String,
    /// Operator
    pub op: Op,
    /// String value to compare against
    pub value: String,
}

/// Policy input presented to the evaluator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyInput {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub context: serde_json::Value,
    /// Optional canonical envelope digest (H1).
    #[serde(default)]
    pub envelope_digest: Option<String>,
}

/// Deterministic decision returned by evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allow: bool,
    pub rationale: String,
    pub policy_id: String,
    pub policy_version: String,
}

/// Pure/effect-free evaluator over the canonical policy schema.
pub fn evaluate(policy: &Policy, input: &PolicyInput) -> PolicyDecision {
    for stmt in &policy.statements {
        let mut all = true;
        for cond in &stmt.when {
            // derive an owned string for the field value to make comparisons consistent
            let field_val: String = match cond.field.as_str() {
                "subject" => input.subject.clone(),
                "action" => input.action.clone(),
                "resource" => input.resource.clone(),
                other => match input.context.get(other) {
                    Some(v) => match v.as_str() {
                        Some(s) => s.to_string(),
                        None => v.to_string(),
                    },
                    None => {
                        all = false;
                        break;
                    }
                },
            };
            match cond.op {
                Op::Eq => {
                    if field_val != cond.value {
                        all = false;
                        break;
                    }
                }
                Op::Contains => {
                    if !field_val.contains(&cond.value) {
                        all = false;
                        break;
                    }
                }
            }
        }
        if all {
            let allow = matches!(stmt.effect, Effect::Allow);
            return PolicyDecision {
                allow,
                rationale: stmt.rationale.clone(),
                policy_id: policy.id.clone(),
                policy_version: policy.version.clone(),
            };
        }
    }
    // Default deny with deterministic rationale
    PolicyDecision {
        allow: false,
        rationale: "no statements matched; default deny".to_string(),
        policy_id: policy.id.clone(),
        policy_version: policy.version.clone(),
    }
}
