use crate::*;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;

/// Metadata stored in the registry for a consumed nonce.
#[derive(Debug, Clone)]
pub struct NonceMeta {
    pub envelope_digest: String,
    pub consumed_at: DateTime<Utc>,
    /// TTL in seconds for in-memory cache housekeeping only (ledger remains immutable)
    pub ttl_seconds: i64,
    /// Optional event offset (useful for debugging / provenance)
    pub event_offset: Option<usize>,
}

/// Index-backed NonceRegistry: in-memory, read-optimized cache populated from ledger replay
/// and updated on each successful `NonceConsumed` append. The ledger is the source-of-truth;
/// this cache is a read-through optimization only and may be rebuilt from the ledger on startup.
#[derive(Debug)]
pub struct NonceRegistry {
    map: RwLock<HashMap<(Uuid, Uuid), NonceMeta>>,
}

impl NonceRegistry {
    /// Create an empty registry
    pub fn new_empty() -> Self {
        NonceRegistry {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Build the registry from replayed `IdentityEvent` values (deterministic startup replay).
    pub fn from_events<I: IntoIterator<Item = IdentityEvent>>(events: I) -> Self {
        let reg = NonceRegistry::new_empty();
        for (idx, ev) in events.into_iter().enumerate() {
            if let IdentityEvent::NonceConsumed(nc) = ev {
                let meta = NonceMeta {
                    envelope_digest: nc.envelope_digest.clone(),
                    consumed_at: nc.consumed_at,
                    ttl_seconds: NONCE_EXPIRATION_SECS,
                    event_offset: Some(idx),
                };
                reg.insert_cached(nc.actor_id, nc.nonce, meta);
            }
        }
        reg
    }

    /// Insert into the in-memory cache. Intended to be called only from startup replay
    /// or immediately after a successful append observation.
    pub fn insert_cached(&self, actor_id: Uuid, nonce: Uuid, meta: NonceMeta) {
        let mut w = self.map.write().expect("nonce registry write lock");
        w.insert((actor_id, nonce), meta);
    }

    /// Observe a `NonceConsumed` that was just appended to the ledger and update cache.
    pub fn observe_consumed(&self, nc: &NonceConsumed, offset: Option<usize>) {
        let meta = NonceMeta {
            envelope_digest: nc.envelope_digest.clone(),
            consumed_at: nc.consumed_at,
            ttl_seconds: NONCE_EXPIRATION_SECS,
            event_offset: offset,
        };
        self.insert_cached(nc.actor_id, nc.nonce, meta);
    }

    /// Return true if the given (actor, nonce) was consumed according to the in-memory cache.
    /// This is a performance shortcut — the canonical truth remains the ledger which can
    /// be deterministically replayed to rebuild the cache.
    pub fn is_consumed(&self, actor_id: Uuid, nonce: Uuid) -> bool {
        let r = self.map.read().expect("nonce registry read lock");
        r.contains_key(&(actor_id, nonce))
    }

    /// Periodic in-memory pruning of expired cache entries. This does NOT delete ledger events.
    pub fn prune_expired(&self) {
        let now = Utc::now();
        let mut w = self.map.write().expect("nonce registry write lock");
        w.retain(|_, meta| {
            let age = now.signed_duration_since(meta.consumed_at).num_seconds();
            age < meta.ttl_seconds
        });
    }

    /// Merge another registry into this one (useful if streaming events incrementally).
    pub fn merge(&self, other: &NonceRegistry) {
        let mut w = self.map.write().expect("nonce registry write lock");
        let r = other.map.read().expect("other registry read lock");
        for (k, v) in r.iter() {
            w.insert(*k, v.clone());
        }
    }
}

/// Global registry instance (lazy-initialized). This is an optional convenience for
/// callers that want a shared, process-local cache that mirrors ledger-derived authority.
/// A background thread periodically prunes expired entries from this in-memory cache.
pub static GLOBAL_NONCE_REGISTRY: Lazy<Arc<NonceRegistry>> = Lazy::new(|| {
    let reg = Arc::new(NonceRegistry::new_empty());
    // Spawn a background thread to prune expired cached nonces every 60 seconds.
    let reg_clone = Arc::clone(&reg);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        reg_clone.prune_expired();
    });
    reg
});

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
