pub mod policy;
pub mod digest;
pub mod event;

pub use policy::{evaluate, Policy, PolicyDecision, PolicyInput};
pub use digest::{canonical_bytes, policy_digest};
pub use event::{make_policy_evaluated, PolicyEvaluated, Decision as PolicyDecisionEnum};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn same_policy_same_digest() {
        let p = Policy {
            id: "example-policy".to_string(),
            version: "1.0.0".to_string(),
            statements: vec![],
        };
        let d1 = policy_digest(&p);
        let d2 = policy_digest(&p);
        assert_eq!(d1, d2, "digest must be stable for same policy");
    }

    #[test]
    fn tiny_change_changes_digest() {
        let mut p1 = Policy {
            id: "example-policy".to_string(),
            version: "1.0.0".to_string(),
            statements: vec![],
        };
        let mut p2 = p1.clone();
        p2.version = "1.0.1".to_string();
        let d1 = policy_digest(&p1);
        let d2 = policy_digest(&p2);
        assert_ne!(d1, d2, "version change must change digest");
    }

    #[test]
    fn evaluation_is_deterministic() {
        let p = Policy {
            id: "pid".to_string(),
            version: "v0".to_string(),
            statements: vec![policy::Statement {
                when: vec![policy::Condition {
                    field: "action".to_string(),
                    op: policy::Op::Eq,
                    value: "read".to_string(),
                }],
                effect: policy::Effect::Allow,
                rationale: "allow reads".to_string(),
            }],
        };
        let inp = PolicyInput {
            subject: "alice".to_string(),
            action: "read".to_string(),
            resource: "r".to_string(),
            context: json!({}),
        };
        let a = evaluate(&p, &inp);
        let b = evaluate(&p, &inp);
        assert_eq!(a, b, "evaluation must be deterministic and pure");
    }

    #[test]
    fn make_policy_evaluated_determinism_and_digests() {
        use chrono::TimeZone;
        let p = Policy {
            id: "pid".to_string(),
            version: "v0".to_string(),
            statements: vec![policy::Statement {
                when: vec![policy::Condition {
                    field: "action".to_string(),
                    op: policy::Op::Eq,
                    value: "read".to_string(),
                }],
                effect: policy::Effect::Allow,
                rationale: "allow reads".to_string(),
            }],
        };
        let inp = PolicyInput {
            subject: "alice".to_string(),
            action: "read".to_string(),
            resource: "r".to_string(),
            context: serde_json::json!({}),
        };
        let ts = chrono::Utc.datetime_from_str("2025-12-25T12:00:00Z", "%Y-%m-%dT%H:%M:%SZ").unwrap();
        let ev1 = make_policy_evaluated(&p, &inp, "v0", ts);
        let ev2 = make_policy_evaluated(&p, &inp, "v0", ts);
        // byte-identical payloads when timestamp is fixed
        let b1 = serde_json::to_vec(&ev1).unwrap();
        let b2 = serde_json::to_vec(&ev2).unwrap();
        assert_eq!(b1, b2, "events should be byte-identical with fixed timestamp");

        // digest coherence
        assert_eq!(ev1.policy_digest, policy_digest(&p));
        assert_eq!(ev1.input_digest, crate::digest::input_digest(&inp));

        // rationale integrity
        assert_eq!(ev1.rationale, "allow reads");

        // no side effects: originals unchanged
        let p_clone = p.clone();
        let inp_clone = inp.clone();
        let _ = make_policy_evaluated(&p, &inp, "v0", ts);
        assert_eq!(p, p_clone);
        assert_eq!(inp, inp_clone);
    }
}
