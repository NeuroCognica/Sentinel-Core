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
// Registry and tests will be added in a follow-up commit.
