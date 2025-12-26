use proptest::prelude::*;
use sentinel_policy::policy::*;
use sentinel_policy::{evaluate, PolicyInput};
use serde_json::json;

fn arb_field() -> impl Strategy<Value = String> {
    prop_oneof![Just("subject".to_string()), Just("action".to_string()), Just("resource".to_string()), Just("ctx_a".to_string()), Just("ctx_b".to_string())]
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![Just(Op::Eq), Just(Op::Contains)]
}

fn arb_condition() -> impl Strategy<Value = Condition> {
    (arb_field(), arb_op(), prop::string::string_regex("[a-zA-Z0-9_]{1,8}").unwrap())
        .prop_map(|(field, op, value)| Condition { field, op, value })
}

fn arb_statement() -> impl Strategy<Value = Statement> {
    (prop::collection::vec(arb_condition(), 1..3), prop_oneof![Just(Effect::Allow), Just(Effect::Deny)], prop::string::string_regex("[a-zA-Z0-9 _]{1,32}").unwrap())
        .prop_map(|(when, effect, rationale)| Statement { when, effect, rationale })
}

fn arb_policy() -> impl Strategy<Value = Policy> {
    (prop::string::string_regex("[a-zA-Z0-9_]{1,8}").unwrap(), prop::string::string_regex(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}").unwrap(), prop::collection::vec(arb_statement(), 0..3))
        .prop_map(|(id, version, statements)| Policy { id, version, statements })
}

fn arb_input() -> impl Strategy<Value = PolicyInput> {
    (prop::string::string_regex("[a-zA-Z0-9_]{1,8}").unwrap(), prop::string::string_regex("[a-zA-Z0-9_]{1,8}").unwrap(), prop::string::string_regex("[a-zA-Z0-9_]{1,8}").unwrap())
        .prop_map(|(subject, action, resource)| PolicyInput { subject, action, resource, context: json!({}) })
}

proptest! {
    #[test]
    fn evaluate_is_pure(policy in arb_policy(), input in arb_input()) {
        let a = evaluate(&policy, &input);
        let b = evaluate(&policy, &input);
        prop_assert_eq!(a, b);
    }
}
