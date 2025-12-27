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

    /// A cryptographic provenance binding that ties artifact -> policy/input -> consent
    CodexSealCreated {
        seal: CodexSeal,
    },
}
/// In-memory registry rebuilt from events
#[derive(Debug, Default, Clone)]
pub struct ArtifactRegistry {
    pub by_id: BTreeMap<ArtifactId, Artifact>,
    pub revoked: BTreeMap<ArtifactId, String>,
}

/// CodexSeal binds what ran to why it was allowed and who caused it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexSeal {
    pub seal_id: Uuid,

    /// What ran (artifact content digest)
    pub artifact_digest: String,

    /// Policy provenance
    pub policy_digest: String,
    pub input_digest: String,

    /// Proof of consent (event id)
    pub consent_event_id: Uuid,

    /// Actor who caused the sealed action
    pub actor_id: String,

    /// When this binding was created
    pub sealed_at: OffsetDateTime,
}

impl CodexSeal {
    /// Constructor that requires the canonical provenances — makes illegal states unrepresentable.
    pub fn new(
        artifact_digest: String,
        policy_digest: String,
        input_digest: String,
        consent_event_id: Uuid,
        actor_id: String,
        sealed_at: OffsetDateTime,
    ) -> Self {
        // Minimal validation: required strings must not be empty
        assert!(!artifact_digest.is_empty(), "artifact_digest required");
        assert!(!policy_digest.is_empty(), "policy_digest required");
        assert!(!input_digest.is_empty(), "input_digest required");

        CodexSeal {
            seal_id: Uuid::new_v4(),
            artifact_digest,
            policy_digest,
            input_digest,
            consent_event_id,
            actor_id,
            sealed_at,
        }
    }
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

            ArtifactEvent::CodexSealCreated { .. } => {
                // Codex seals are provenance bindings; they do not modify the artifact registry state.
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
    use serde_json;
    use std::collections::HashSet;

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

    #[test]
    fn codex_seal_roundtrip_and_determinism() {
        let consent_id = Uuid::new_v4();
        let seal = CodexSeal::new(
            "ad:deadbeef".to_string(),
            "pd:abc123".to_string(),
            "id:xyz789".to_string(),
            consent_id,
            "actor-1".to_string(),
            OffsetDateTime::now_utc(),
        );

        // serialize / deserialize round-trip
        let ser = serde_json::to_string(&seal).expect("serialize");
        let de: CodexSeal = serde_json::from_str(&ser).expect("deserialize");
        assert_eq!(seal.artifact_digest, de.artifact_digest);
        assert_eq!(seal.policy_digest, de.policy_digest);

        // replay determinism: serializing twice yields same string (canonical key ordering via serde)
        let ser2 = serde_json::to_string(&de).expect("serialize2");
        assert_eq!(ser, ser2);

        // uniqueness by (artifact_digest, consent_event_id)
        let mut set: HashSet<(String, Uuid)> = HashSet::new();
        assert!(set.insert((seal.artifact_digest.clone(), seal.consent_event_id)));
        // inserting same combination should be rejected (set returns false)
        assert!(!set.insert((seal.artifact_digest.clone(), seal.consent_event_id)));
    }
}
