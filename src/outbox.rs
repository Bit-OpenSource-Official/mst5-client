//! Persistent, transport-independent send queue.
//!
//! The queue deliberately contains no platform types.  Android can persist the
//! JSON snapshot in SQLite/SharedPreferences and web can persist it in
//! IndexedDB; retry and state transitions stay identical in both clients.

use serde::{Deserialize, Serialize};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    #[default]
    Queued,
    Sending,
    Delivered,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueItem {
    pub id: String,
    pub payload: String,
    #[serde(default)]
    pub state: DeliveryState,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_attempt_at_ms: u64,
    #[serde(default)]
    pub progress_percent: u8,
    #[serde(default)]
    pub error: Option<String>,
}

impl QueueItem {
    pub fn new(id: impl Into<String>, payload: impl Into<String>) -> io::Result<Self> {
        let id = id.into();
        if id.trim().is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(invalid_input("queue item id is invalid"));
        }
        Ok(Self {
            id,
            payload: payload.into(),
            state: DeliveryState::Queued,
            attempts: 0,
            next_attempt_at_ms: 0,
            progress_percent: 0,
            error: None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            initial_delay_ms: 1_000,
            max_delay_ms: 5 * 60 * 1_000,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Outbox {
    #[serde(default)]
    items: Vec<QueueItem>,
}

impl Outbox {
    pub fn from_json(raw: &str) -> io::Result<Self> {
        let queue: Self = serde_json::from_str(raw)
            .map_err(|error| invalid_input(format!("invalid outbox JSON: {error}")))?;
        queue.validate()?;
        Ok(queue)
    }

    pub fn to_json(&self) -> io::Result<String> {
        serde_json::to_string(self)
            .map_err(|error| io::Error::other(format!("cannot encode outbox: {error}")))
    }

    pub fn items(&self) -> &[QueueItem] {
        &self.items
    }

    pub fn enqueue(&mut self, item: QueueItem) -> io::Result<()> {
        if self.items.iter().any(|existing| existing.id == item.id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "queue item already exists",
            ));
        }
        self.items.push(item);
        Ok(())
    }

    pub fn claim_ready(&mut self, now_ms: u64) -> Option<String> {
        let item = self.items.iter_mut().find(|item| {
            item.state == DeliveryState::Queued && item.next_attempt_at_ms <= now_ms
        })?;
        item.state = DeliveryState::Sending;
        item.progress_percent = item.progress_percent.min(99);
        item.error = None;
        Some(item.id.clone())
    }

    pub fn update_progress(&mut self, id: &str, percent: u8) -> bool {
        let Some(item) = self.items.iter_mut().find(|item| item.id == id) else {
            return false;
        };
        if item.state != DeliveryState::Sending {
            return false;
        }
        item.progress_percent = percent.min(99);
        true
    }

    pub fn mark_delivered(&mut self, id: &str) -> bool {
        let Some(item) = self.items.iter_mut().find(|item| item.id == id) else {
            return false;
        };
        item.state = DeliveryState::Delivered;
        item.progress_percent = 100;
        item.error = None;
        true
    }

    pub fn mark_failed(&mut self, id: &str, error: impl Into<String>, policy: RetryPolicy) -> bool {
        let Some(item) = self.items.iter_mut().find(|item| item.id == id) else {
            return false;
        };
        item.attempts = item.attempts.saturating_add(1);
        item.error = Some(error.into());
        if item.attempts >= policy.max_attempts {
            item.state = DeliveryState::Failed;
            item.next_attempt_at_ms = 0;
        } else {
            item.state = DeliveryState::Queued;
            let exponent = item.attempts.saturating_sub(1).min(31);
            let delay = policy
                .initial_delay_ms
                .saturating_mul(1_u64 << exponent)
                .min(policy.max_delay_ms);
            item.next_attempt_at_ms = unix_now_ms().saturating_add(delay);
        }
        true
    }

    pub fn retry_failed(&mut self, id: &str) -> bool {
        let Some(item) = self.items.iter_mut().find(|item| item.id == id) else {
            return false;
        };
        if item.state != DeliveryState::Failed {
            return false;
        }
        item.state = DeliveryState::Queued;
        item.next_attempt_at_ms = 0;
        item.error = None;
        true
    }

    pub fn remove_delivered(&mut self) {
        self.items
            .retain(|item| item.state != DeliveryState::Delivered);
    }

    fn validate(&self) -> io::Result<()> {
        for item in &self.items {
            if item.id.trim().is_empty() || item.id.len() > 256 {
                return Err(invalid_input("outbox contains invalid item id"));
            }
            if item.progress_percent > 100 {
                return Err(invalid_input("outbox contains invalid progress"));
            }
        }
        Ok(())
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_transitions_and_round_trips() {
        let mut outbox = Outbox::default();
        outbox
            .enqueue(QueueItem::new("m1", "payload").unwrap())
            .unwrap();
        assert_eq!(outbox.claim_ready(u64::MAX).as_deref(), Some("m1"));
        assert!(outbox.update_progress("m1", 42));
        assert!(outbox.mark_failed(
            "m1",
            "offline",
            RetryPolicy {
                max_attempts: 2,
                ..Default::default()
            }
        ));
        assert_eq!(outbox.items()[0].state, DeliveryState::Queued);
        let restored = Outbox::from_json(&outbox.to_json().unwrap()).unwrap();
        assert_eq!(restored.items(), outbox.items());
        assert_eq!(outbox.claim_ready(u64::MAX).as_deref(), Some("m1"));
    }

    #[test]
    fn exhausted_item_becomes_failed_and_can_be_retried_manually() {
        let mut outbox = Outbox::default();
        outbox
            .enqueue(QueueItem::new("m2", "payload").unwrap())
            .unwrap();
        outbox.claim_ready(u64::MAX);
        let policy = RetryPolicy {
            max_attempts: 1,
            ..Default::default()
        };
        outbox.mark_failed("m2", "bad", policy);
        assert_eq!(outbox.items()[0].state, DeliveryState::Failed);
        assert!(outbox.retry_failed("m2"));
        assert_eq!(outbox.items()[0].state, DeliveryState::Queued);
    }
}
