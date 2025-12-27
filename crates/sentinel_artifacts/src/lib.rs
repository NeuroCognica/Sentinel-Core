use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use time::OffsetDateTime;

/// Stable identifier for an artifact (NOT the content hash)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtifactId(pub Uuid);

/// What kind of thing this artifact is
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactType {
    Executable,
    ModelWeights,
    PromptTemplate,
    ToolDefinition,
    Config,
}

/// Immutable artifact record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub artifact_id: ArtifactId,

    /// Hash of the artifact contents (canonical, hex)
    pub artifact_digest: String,

    pub artifact_type: ArtifactType,

    /// Human + system metadata (never authoritative)
    pub metadata: BTreeMap<String, String>,

    /// Dependency digests (other artifacts, models, tools)
    pub dependencies: Vec<String>,

    pub created_at: OffsetDateTime,
    pub created_by: String, // actor_id
}

/// Event variants for artifact lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactEvent {
    ArtifactRegistered {
        artifact_id: ArtifactId,
        artifact_digest: String,
        artifact_type: ArtifactType,
        dependencies: Vec<String>,
        metadata: BTreeMap<String, String>,
        created_by: String,
        created_at: OffsetDateTime,
    },

    ArtifactValidated {
        artifact_id: ArtifactId,
        artifact_digest: String,
        validator: String,
        validated_at: OffsetDateTime,
    },

    ArtifactRevoked {
        artifact_id: ArtifactId,
        reason: String,
        revoked_by: String,
        revoked_at: OffsetDateTime,
    },
}
/// In-memory registry rebuilt from events
#[derive(Debug, Default, Clone)]
pub struct ArtifactRegistry {
    pub by_id: BTreeMap<ArtifactId, Artifact>,
    pub revoked: BTreeMap<ArtifactId, String>,
}

impl ArtifactRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: &ArtifactEvent) {
        match event {
            ArtifactEvent::ArtifactRegistered { artifact_id, artifact_digest, artifact_type, dependencies, metadata, created_by, created_at } => {
                let artifact = Artifact {
                    artifact_id: artifact_id.clone(),
                    artifact_digest: artifact_digest.clone(),
                    artifact_type: artifact_type.clone(),
                    metadata: metadata.clone(),
                    dependencies: dependencies.clone(),
                    created_at: *created_at,
                    created_by: created_by.clone(),
                };

                self.by_id.insert(artifact_id.clone(), artifact);
            }

            ArtifactEvent::ArtifactRevoked { artifact_id, reason, .. } => {
                self.revoked.insert(artifact_id.clone(), reason.clone());
            }

            ArtifactEvent::ArtifactValidated { .. } => {
                // Validations are append-only annotations; no state mutation needed for basic registry
            }
        }
    }

    pub fn replay_from(&mut self, events: &[ArtifactEvent]) {
        for e in events {
            self.apply(e);
        }
    }

    pub fn is_active(&self, id: &ArtifactId) -> bool {
        self.by_id.contains_key(id) && !self.revoked.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registered_event(id: Uuid, digest: &str) -> ArtifactEvent {
        ArtifactEvent::ArtifactRegistered {
            artifact_id: ArtifactId(id),
            artifact_digest: digest.to_string(),
            artifact_type: ArtifactType::Executable,
            dependencies: vec![],
            metadata: BTreeMap::new(),
            created_by: "actor-1".to_string(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn register_and_replay_produces_identical_state() {
        let id = Uuid::new_v4();
        let ev = make_registered_event(id, "deadbeef");
        let events = vec![ev.clone()];

        let mut r1 = ArtifactRegistry::new();
        r1.apply(&ev);

        let mut r2 = ArtifactRegistry::new();
        r2.replay_from(&events);

        assert_eq!(r1.by_id.len(), r2.by_id.len());
        assert_eq!(r1.is_active(&ArtifactId(id)), r2.is_active(&ArtifactId(id)));
    }

    #[test]
    fn duplicate_registration_deterministic() {
        let id = Uuid::new_v4();
        let ev1 = make_registered_event(id, "deadbeef");
        let ev2 = make_registered_event(id, "deadbeef");

        let mut r = ArtifactRegistry::new();
        r.apply(&ev1);
        r.apply(&ev2);

        // duplicate registration should leave single entry for id
        assert!(r.by_id.contains_key(&ArtifactId(id)));
        assert_eq!(r.by_id.len(), 1);
    }
}
