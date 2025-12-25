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
            return Err(EventStoreError::IoError(format!("Failed to open or create file: {e}")));
        }
        Ok(FileEventStore { path: pathbuf })
    }
}

impl EventStore for FileEventStore {
    fn append(&mut self, event: EventRecord) -> Result<(), EventStoreError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| EventStoreError::IoError(format!("Failed to open file for append: {e}")))?;
        let json = serde_json::to_string(&event)
            .map_err(|e| EventStoreError::SerializationError(format!("Failed to serialize event: {e}")))?;
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
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| EventStoreError::IoError(format!("Failed to read line {idx}: {e}")))?;
            let event: EventRecord = serde_json::from_str(&line)
                .map_err(|e| EventStoreError::Corruption(format!("Corrupt event at line {idx}: {e}")))?;
            events.push(event);
        }
        Ok(events)
    }
}
// Canonical event model and append-only EventStore trait for Sentinel

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    HealthCheck,
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
