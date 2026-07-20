use rand::{seq::SliceRandom, thread_rng};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
// Append-only, file-backed EventStore implementation
pub struct FileEventStore {
    path: PathBuf,
}

impl FileEventStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, EventStoreError> {
        let pathbuf = path.as_ref().to_path_buf();
        // Create file if it doesn't exist, open for append otherwise
        if let Err(e) = OpenOptions::new().create(true).append(true).open(&pathbuf) {
            return Err(EventStoreError::IoError(format!(
                "Failed to open or create file: {e}"
            )));
        }
        // Themed error messages for corruption
        const ERROR_MESSAGES: &[&str] = &[
            "ERROR DETECTED - SENTINEL CLOSING PORTAL!",
            "INTEGRITY BREACH - SHUTTING DOWN THE GATE!",
            "ALERT: CHRONICLE TAMPERED - SYSTEM LOCKDOWN!",
            "SENTINEL WARNING: EVENT LOG CORRUPTION!",
            "FATAL: HASH CHAIN BROKEN - ACCESS DENIED!",
            "SECURITY FAILURE - THE PORTAL IS SEALED!",
            "CRITICAL ERROR - AUDIT TRAIL COMPROMISED!",
            "DANGER: UNAUTHORIZED ALTERATION DETECTED!",
            "SENTINEL PANIC - CHAIN OF TRUST VIOLATED!",
            "EMERGENCY: LOG INTEGRITY FAILURE!",
        ];
        let store = FileEventStore { path: pathbuf };
        // Only check if file is non-empty
        let file = File::open(&store.path);
        if let Ok(file) = file {
            let reader = BufReader::new(file);
            let mut prev_hash: Option<String> = None;
            let mut rng = thread_rng();
            for (idx, line) in reader.lines().enumerate() {
                let line = line.map_err(|e| {
                    EventStoreError::IoError(format!("Failed to read line {idx}: {e}"))
                })?;
                let event: EventRecord = serde_json::from_str(&line).map_err(|e| {
                    EventStoreError::Corruption(format!("Corrupt event at line {idx}: {e}"))
                })?;
                // Check prev_hash matches
                if event.prev_hash != prev_hash {
                    let msg = ERROR_MESSAGES
                        .choose(&mut rng)
                        .unwrap_or(&ERROR_MESSAGES[0]);
                    eprintln!("\n==============================\n{msg}\nHash chain broken at line {idx}: prev_hash mismatch\n==============================\n");
                    return Err(EventStoreError::Corruption(format!(
                        "Hash chain broken at line {idx}: prev_hash mismatch"
                    )));
                }
                // Check hash is correct
                let expected_hash = compute_event_hash(&event);
                if event.hash != expected_hash {
                    let msg = ERROR_MESSAGES
                        .choose(&mut rng)
                        .unwrap_or(&ERROR_MESSAGES[0]);
                    eprintln!("\n==============================\n{msg}\nHash mismatch at line {idx}: expected {expected_hash}, found {}\n==============================\n", event.hash);
                    return Err(EventStoreError::Corruption(format!(
                        "Hash mismatch at line {idx}: expected {expected_hash}, found {}",
                        event.hash
                    )));
                }
                prev_hash = Some(event.hash.clone());
            }
        }
        Ok(store)
    }

    /// Append an event and return the finalized hash-chained record.
    pub fn append_record_with_sync(
        &mut self,
        mut event: EventRecord,
        fsync: bool,
    ) -> Result<EventRecord, EventStoreError> {
        let prev_hash = {
            let file = File::open(&self.path);
            if let Ok(file) = file {
                let reader = BufReader::new(file);
                reader.lines().last().and_then(|line| {
                    line.ok()
                        .and_then(|l| serde_json::from_str::<EventRecord>(&l).ok().map(|e| e.hash))
                })
            } else {
                None
            }
        };
        event.prev_hash = prev_hash.clone();
        event.hash = compute_event_hash(&event);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                EventStoreError::IoError(format!("Failed to open file for append: {e}"))
            })?;
        let json = serde_json::to_string(&event).map_err(|e| {
            EventStoreError::SerializationError(format!("Failed to serialize event: {e}"))
        })?;
        file.write_all(json.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.flush())
            .map_err(|e| EventStoreError::IoError(format!("Failed to write/flush event: {e}")))?;
        if fsync {
            file.sync_all()
                .map_err(|e| EventStoreError::IoError(format!("Failed to sync event: {e}")))?;
        }
        Ok(event)
    }

    /// Append an event with optional fsync. Returns number of bytes written to the file on success.
    pub fn append_with_sync(
        &mut self,
        mut event: EventRecord,
        fsync: bool,
    ) -> Result<usize, EventStoreError> {
        // Read last event to get prev_hash
        let prev_hash = {
            let file = File::open(&self.path);
            if let Ok(file) = file {
                let reader = BufReader::new(file);
                reader.lines().last().and_then(|line| {
                    line.ok()
                        .and_then(|l| serde_json::from_str::<EventRecord>(&l).ok().map(|e| e.hash))
                })
            } else {
                None
            }
        };
        event.prev_hash = prev_hash.clone();
        event.hash = compute_event_hash(&event);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                EventStoreError::IoError(format!("Failed to open file for append: {e}"))
            })?;
        let json = serde_json::to_string(&event).map_err(|e| {
            EventStoreError::SerializationError(format!("Failed to serialize event: {e}"))
        })?;
        let bytes = json.as_bytes();
        file.write_all(bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.flush())
            .map_err(|e| EventStoreError::IoError(format!("Failed to write/flush event: {e}")))?;
        if fsync {
            file.sync_all()
                .map_err(|e| EventStoreError::IoError(format!("Failed to sync event: {e}")))?;
        }
        Ok(bytes.len() + 1) // include newline
    }
}

impl EventStore for FileEventStore {
    fn append(&mut self, mut event: EventRecord) -> Result<(), EventStoreError> {
        // Read last event to get prev_hash
        let prev_hash = {
            let file = File::open(&self.path);
            if let Ok(file) = file {
                let reader = BufReader::new(file);
                reader.lines().last().and_then(|line| {
                    line.ok()
                        .and_then(|l| serde_json::from_str::<EventRecord>(&l).ok().map(|e| e.hash))
                })
            } else {
                None
            }
        };
        event.prev_hash = prev_hash.clone();
        event.hash = compute_event_hash(&event);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                EventStoreError::IoError(format!("Failed to open file for append: {e}"))
            })?;
        let json = serde_json::to_string(&event).map_err(|e| {
            EventStoreError::SerializationError(format!("Failed to serialize event: {e}"))
        })?;
        file.write_all(json.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.flush())
            .map_err(|e| EventStoreError::IoError(format!("Failed to write/flush event: {e}")))?;
        Ok(())
    }

    fn iter(&self) -> Result<Vec<EventRecord>, EventStoreError> {
        let file = File::open(&self.path)
            .map_err(|e| EventStoreError::IoError(format!("Failed to open file for read: {e}")))?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        let mut prev_hash: Option<String> = None;
        for (idx, line) in reader.lines().enumerate() {
            let line = line
                .map_err(|e| EventStoreError::IoError(format!("Failed to read line {idx}: {e}")))?;
            let event: EventRecord = serde_json::from_str(&line).map_err(|e| {
                EventStoreError::Corruption(format!("Corrupt event at line {idx}: {e}"))
            })?;
            // Check prev_hash matches
            if event.prev_hash != prev_hash {
                return Err(EventStoreError::Corruption(format!(
                    "Hash chain broken at line {idx}: prev_hash mismatch"
                )));
            }
            // Check hash is correct
            let expected_hash = compute_event_hash(&event);
            if event.hash != expected_hash {
                return Err(EventStoreError::Corruption(format!(
                    "Hash mismatch at line {idx}: expected {expected_hash}, found {}",
                    event.hash
                )));
            }
            prev_hash = Some(event.hash.clone());
            events.push(event);
        }
        Ok(events)
    }
}

fn compute_event_hash(event: &EventRecord) -> String {
    let mut hasher = Sha256::new();
    if let Some(ref prev) = event.prev_hash {
        hasher.update(prev.as_bytes());
    }
    hasher.update(event.event_id.as_bytes());
    hasher.update(event.timestamp_utc.to_rfc3339().as_bytes());
    hasher.update(event.actor.as_bytes());
    hasher.update(format!("{:?}", event.kind).as_bytes());
    // Canonical JSON for payload
    let payload = serde_json::to_string(&event.payload).unwrap_or_default();
    hasher.update(payload.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
// Canonical event model and append-only EventStore trait for Sentinel

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    HealthCheck,
    Identity,
    AuthorizationRequestReceived,
    AuthChallengeIssued,
    AuthChallengeConsumed,
    NonceConsumed,
    PolicyEvaluated,
    ConsentGranted,
    ConsentDenied,
    SentinelGuardDecision,
    EffectExecuted,
    CapabilityIssued,
    CapabilityConsumed,
    ArtifactRegistered,
    ArtifactValidated,
    ArtifactRevoked,
    CodexSealCreated,
    // Add more event kinds as needed in future steps
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: Uuid,
    pub timestamp_utc: DateTime<Utc>,
    pub actor: String,
    pub kind: EventKind,
    pub payload: Value,
    pub prev_hash: Option<String>,
    pub hash: String,
}

#[derive(Debug)]
pub enum EventStoreError {
    IoError(String),
    SerializationError(String),
    Corruption(String),
}

pub trait EventStore {
    fn append(&mut self, event: EventRecord) -> Result<(), EventStoreError>;
    fn iter(&self) -> Result<Vec<EventRecord>, EventStoreError>;
}
