use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Minimal policy representation for Phase 4 scaffolding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub version: String,
    pub rules: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allow: bool,
    pub rationale: String,
    pub policy_id: Uuid,
    pub policy_version: String,
}

/// Deterministic stub evaluator: for now, allow if `action` == "read", else deny.
pub fn evaluate(policy: &Policy, input: &PolicyInput) -> PolicyDecision {
    let allow = input.action == "read";
    let rationale = if allow {
        "action is read; allowed by default stub".to_string()
    } else {
        "action not allowed by default stub".to_string()
    };
    PolicyDecision {
        allow,
        rationale,
        policy_id: policy.id,
        policy_version: policy.version.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evaluate_read_allowed() {
        let p = Policy {
            id: Uuid::new_v4(),
            version: "v1".to_string(),
            rules: json!({}),
        };
        let input = PolicyInput {
            subject: "alice".to_string(),
            action: "read".to_string(),
            resource: "artifact:foo".to_string(),
            context: json!({}),
        };
        let dec = evaluate(&p, &input);
        assert!(dec.allow, "read should be allowed by stub");
    }
}
