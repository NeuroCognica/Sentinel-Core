use crate::*;
use std::collections::HashSet;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Lightweight in-memory nonce registry built by replaying `NonceConsumed` events.
#[derive(Debug, Clone)]
pub struct NonceRegistry {
    /// set of (actor_id, nonce)
    consumed: HashSet<(Uuid, Uuid)>,
    /// store additional envelope digests if callers need provenance lookups
    pub envelope_digests: Vec<(Uuid, Uuid, String, DateTime<Utc>)>,
}

impl NonceRegistry {
    /// Build from an iterator of `IdentityEvent` values (typically obtained by reading the event log)
    pub fn from_events<I: IntoIterator<Item = IdentityEvent>>(events: I) -> Self {
        let mut consumed = HashSet::new();
        let mut envelope_digests = Vec::new();
        for ev in events {
            if let IdentityEvent::NonceConsumed(nc) = ev {
                consumed.insert((nc.actor_id, nc.nonce));
                envelope_digests.push((nc.actor_id, nc.nonce, nc.envelope_digest, nc.consumed_at));
            }
        }
        NonceRegistry { consumed, envelope_digests }
    }

    /// Return true if the given (actor, nonce) was consumed according to the replayed events
    pub fn is_consumed(&self, actor_id: Uuid, nonce: Uuid) -> bool {
        self.consumed.contains(&(actor_id, nonce))
    }

    /// Merge another registry into this one (useful when streaming additional events)
    pub fn merge(&mut self, other: &NonceRegistry) {
        for k in other.consumed.iter() {
            self.consumed.insert(*k);
        }
        self.envelope_digests.extend_from_slice(&other.envelope_digests);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn registry_detects_consumed_nonce() {
        let actor = Uuid::new_v4();
        let key = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let now = Utc::now();
        let evs = vec![IdentityEvent::NonceConsumed(NonceConsumed {
            actor_id: actor,
            key_id: key,
            nonce,
            envelope_digest: "abc".to_string(),
            consumed_at: now,
        })];
        let reg = NonceRegistry::from_events(evs);
        assert!(reg.is_consumed(actor, nonce));
    }
}
