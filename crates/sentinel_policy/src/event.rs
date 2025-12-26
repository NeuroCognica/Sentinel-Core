use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::policy::{Policy, PolicyInput};
use crate::digest::{policy_digest, input_digest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvaluated {
    pub policy_digest: String,
    pub policy_version: String,
    pub input_digest: String,
    pub decision: Decision,
    pub matched_statement_index: Option<usize>,
    pub rationale: String,
    pub evaluated_at_utc: DateTime<Utc>,
    pub evaluator_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentDecision {
    Granted,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentEvent {
    pub actor: String,
    pub policy_digest: String,
    pub input_digest: String,
    pub decision: ConsentDecision,
    pub reason: String,
    pub occurred_at_utc: DateTime<Utc>,
}

/// Construct a PolicyEvaluated event payload from a policy and input.
/// Pure: performs no IO and does not mutate inputs.
pub fn make_policy_evaluated(
    policy: &Policy,
    input: &PolicyInput,
    evaluator_version: &str,
    evaluated_at_utc: DateTime<Utc>,
) -> PolicyEvaluated {
    // compute digests
    let p_digest = policy_digest(policy);
    let i_digest = input_digest(input);

    // determine matched statement index and rationale
    let mut matched: Option<usize> = None;
    let mut rationale = String::from("no statements matched; default deny");
    let mut decision = Decision::Deny;
    'outer: for (idx, stmt) in policy.statements.iter().enumerate() {
        let mut all = true;
        for cond in &stmt.when {
            let field_val: String = match cond.field.as_str() {
                "subject" => input.subject.clone(),
                "action" => input.action.clone(),
                "resource" => input.resource.clone(),
                other => match input.context.get(other) {
                    Some(v) => match v.as_str() {
                        Some(s) => s.to_string(),
                        None => v.to_string(),
                    },
                    None => { all = false; break; }
                },
            };
            match cond.op {
                crate::policy::Op::Eq => {
                    if field_val != cond.value { all = false; break; }
                }
                crate::policy::Op::Contains => {
                    if !field_val.contains(&cond.value) { all = false; break; }
                }
            }
        }
        if all {
            matched = Some(idx);
            rationale = stmt.rationale.clone();
            decision = match stmt.effect {
                crate::policy::Effect::Allow => Decision::Allow,
                crate::policy::Effect::Deny => Decision::Deny,
            };
            break 'outer;
        }
    }

    PolicyEvaluated {
        policy_digest: p_digest,
        policy_version: policy.version.clone(),
        input_digest: i_digest,
        decision,
        matched_statement_index: matched,
        rationale,
        evaluated_at_utc,
        evaluator_version: evaluator_version.to_string(),
    }
}

/// Construct a ConsentEvent payload from a policy evaluation and input.
pub fn make_consent_event(
    actor: &str,
    policy_digest: &str,
    input_digest: &str,
    granted: bool,
    reason: &str,
    occurred_at_utc: DateTime<Utc>,
) -> ConsentEvent {
    ConsentEvent {
        actor: actor.to_string(),
        policy_digest: policy_digest.to_string(),
        input_digest: input_digest.to_string(),
        decision: if granted { ConsentDecision::Granted } else { ConsentDecision::Denied },
        reason: reason.to_string(),
        occurred_at_utc,
    }
}
