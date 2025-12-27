use chrono::Utc;
use serde_json::to_value;
use sentinel_policy::{make_policy_evaluated, PolicyInput, Policy};
use sentinel_store::{EventRecord, EventKind, FileEventStore, EventStore};
use uuid::Uuid;

#[test]
fn append_policy_evaluated_and_verify_chain() {
    // prepare policy + input
    let p = Policy {
        id: "pid".to_string(),
        version: "v0".to_string(),
        statements: vec![],
    };
    let inp = PolicyInput {
        subject: "alice".to_string(),
        action: "read".to_string(),
        resource: "artifact:foo".to_string(),
        context: serde_json::json!({}),
        envelope_digest: None,
    };

    let ts = Utc::now();
    let ev = make_policy_evaluated(&p, &inp, "evaluator-v0", ts);

    // temp file path
    let tmp = std::env::temp_dir().join(format!("policy_eval_test_{}.log", Uuid::new_v4()));
    let path = tmp.as_path();

    // append event
    let mut store = FileEventStore::open(path).expect("open store");
    let rec = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: "policy_engine".to_string(),
        kind: EventKind::PolicyEvaluated,
        payload: to_value(&ev).expect("serialize ev"),
        prev_hash: None,
        hash: String::new(),
    };
    store.append_with_sync(rec, false).expect("append");

    // read back and validate
    let events = store.iter().expect("iter");
    assert_eq!(events.len(), 1);
    let stored = &events[0];
    // verify payload digest coherence
    let stored_ev: sentinel_policy::PolicyEvaluated = serde_json::from_value(stored.payload.clone()).expect("deserialize");
    assert_eq!(stored_ev.policy_digest, ev.policy_digest);
    assert_eq!(stored_ev.input_digest, ev.input_digest);
    assert_eq!(stored_ev.rationale, ev.rationale);

    // Append a second event and check chaining
    let rec2 = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: "policy_engine".to_string(),
        kind: EventKind::PolicyEvaluated,
        payload: to_value(&ev).expect("serialize ev"),
        prev_hash: None,
        hash: String::new(),
    };
    store.append_with_sync(rec2, false).expect("append2");
    let events2 = store.iter().expect("iter2");
    assert_eq!(events2.len(), 2);
    // verify prev_hash links
    assert!(events2[1].prev_hash.is_some());
    assert_eq!(events2[1].prev_hash.as_ref().unwrap(), &events2[0].hash);
}
