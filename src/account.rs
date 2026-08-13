use crate::{kind, Client, ClientOptions, RequestOptions, Response};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex};

#[derive(Clone, Debug)]
pub struct AccountConfig {
    pub endpoint: String,
    pub pinned_public_key_b64: String,
    pub token: String,
    pub client_name: String,
    pub options: ClientOptions,
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
}

impl AccountConfig {
    pub fn new(
        endpoint: impl Into<String>,
        pinned_public_key_b64: impl Into<String>,
        token: impl Into<String>,
        client_name: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            pinned_public_key_b64: pinned_public_key_b64.into(),
            token: token.into(),
            client_name: client_name.into(),
            options: ClientOptions::default(),
            reconnect_min: Duration::from_millis(500),
            reconnect_max: Duration::from_secs(60),
        }
    }

    /// Create an account reactor configuration using the pin embedded in the
    /// mst5-client build.
    pub fn with_compiled_key(
        endpoint: impl Into<String>,
        token: impl Into<String>,
        client_name: impl Into<String>,
    ) -> io::Result<Self> {
        Ok(Self::new(
            endpoint,
            crate::compiled_server_public_key_b64()?,
            token,
            client_name,
        ))
    }
}

#[derive(Clone, Debug)]
pub enum AccountEvent {
    Connected { generation: u64 },
    Disconnected { message: String, retry_in: Duration },
    AuthenticationInvalid { message: String },
    EventBatch { payload: Vec<u8> },
    ResyncRequired,
    Closed,
}

pub struct AccountEventReceiver {
    receiver: broadcast::Receiver<AccountEvent>,
}

impl AccountEventReceiver {
    pub async fn recv(&mut self) -> io::Result<AccountEvent> {
        match self.receiver.recv().await {
            Ok(event) => Ok(event),
            Err(broadcast::error::RecvError::Lagged(_)) => Ok(AccountEvent::ResyncRequired),
            Err(broadcast::error::RecvError::Closed) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MST5 account event queue closed",
            )),
        }
    }
}

#[derive(Clone)]
pub struct AccountClient {
    inner: Arc<AccountInner>,
}

struct AccountInner {
    config: AccountConfig,
    credentials: RwLock<(String, String)>,
    current: RwLock<Option<(u64, Client)>>,
    connect_lock: Mutex<()>,
    generation: AtomicU32,
    closed: AtomicBool,
    events: broadcast::Sender<AccountEvent>,
}

impl AccountClient {
    pub fn new(config: AccountConfig) -> io::Result<Self> {
        if config.endpoint.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MST5 endpoint is empty",
            ));
        }
        if config.client_name.chars().count() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client_name must contain at most 64 characters",
            ));
        }
        let credentials = (config.token.clone(), config.client_name.clone());
        let (events, _) = broadcast::channel(128);
        Ok(Self {
            inner: Arc::new(AccountInner {
                config,
                credentials: RwLock::new(credentials),
                current: RwLock::new(None),
                connect_lock: Mutex::new(()),
                generation: AtomicU32::new(0),
                closed: AtomicBool::new(false),
                events,
            }),
        })
    }

    pub fn subscribe(&self) -> AccountEventReceiver {
        AccountEventReceiver {
            receiver: self.inner.events.subscribe(),
        }
    }

    pub async fn set_credentials(&self, token: &str, client_name: &str) -> io::Result<()> {
        if client_name.chars().count() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client_name must contain at most 64 characters",
            ));
        }
        let changed = {
            let mut credentials = self
                .inner
                .credentials
                .write()
                .map_err(|_| io::Error::other("MST5 account credentials lock poisoned"))?;
            let changed = credentials.0 != token || credentials.1 != client_name.trim();
            if changed {
                *credentials = (token.to_string(), client_name.trim().to_string());
            }
            changed
        };
        if changed {
            self.invalidate(None).await;
        }
        Ok(())
    }

    pub async fn request_cbor(
        &self,
        frame_kind: u8,
        opcode: u16,
        payload: &[u8],
        mut options: RequestOptions,
    ) -> io::Result<Response> {
        if frame_kind == kind::COMMAND && options.request_nonce.is_none() {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce)
                .map_err(|error| io::Error::other(format!("OS CSPRNG failed: {error}")))?;
            if nonce == [0; 16] {
                nonce[0] = 1;
            }
            options.request_nonce = Some(nonce);
        }
        let started = Instant::now();
        let max_elapsed = self.inner.config.reconnect_max;
        let mut attempt = 0_u32;
        loop {
            if self.inner.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "MST5 account is closed",
                ));
            }
            let (generation, client) = match self.connected().await {
                Ok(value) => value,
                Err(error) if is_authentication_error(&error) => {
                    let _ = self.inner.events.send(AccountEvent::AuthenticationInvalid {
                        message: error.to_string(),
                    });
                    return Err(error);
                }
                Err(error) => {
                    if started.elapsed() >= max_elapsed {
                        return Err(error);
                    }
                    let delay = self.backoff(attempt);
                    attempt = attempt.saturating_add(1);
                    let _ = self.inner.events.send(AccountEvent::Disconnected {
                        message: error.to_string(),
                        retry_in: delay,
                    });
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
            match client
                .request_cbor_with_options(frame_kind, opcode, payload, options.clone())
                .await
            {
                Ok(response) => {
                    if response.kind == kind::EVENT_BATCH {
                        let _ = self.inner.events.send(AccountEvent::EventBatch {
                            payload: response.payload.clone(),
                        });
                    }
                    return Ok(response);
                }
                Err(error) if is_authentication_error(&error) => {
                    let _ = self.inner.events.send(AccountEvent::AuthenticationInvalid {
                        message: error.to_string(),
                    });
                    return Err(error);
                }
                Err(error) => {
                    self.invalidate(Some(generation)).await;
                    if started.elapsed() >= max_elapsed {
                        return Err(error);
                    }
                    let delay = self.backoff(attempt);
                    attempt = attempt.saturating_add(1);
                    let _ = self.inner.events.send(AccountEvent::Disconnected {
                        message: error.to_string(),
                        retry_in: delay,
                    });
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    pub async fn close(&self) -> io::Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        let client = self.take_current(None)?;
        let _ = self.inner.events.send(AccountEvent::Closed);
        if let Some(client) = client {
            client.close().await
        } else {
            Ok(())
        }
    }

    async fn connected(&self) -> io::Result<(u64, Client)> {
        if let Some(value) = self.current()? {
            if !value.1.is_closed() {
                return Ok(value);
            }
        }
        let _guard = self.inner.connect_lock.lock().await;
        if let Some(value) = self.current()? {
            if !value.1.is_closed() {
                return Ok(value);
            }
        }
        let client = Client::connect_with_options(
            &self.inner.config.endpoint,
            &self.inner.config.pinned_public_key_b64,
            self.inner.config.options.clone(),
        )
        .await?;
        let (token, client_name) = self
            .inner
            .credentials
            .read()
            .map_err(|_| io::Error::other("MST5 account credentials lock poisoned"))?
            .clone();
        client
            .authenticate_info_with_client_name(&token, &client_name)
            .await?;
        let generation = u64::from(self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1);
        *self
            .inner
            .current
            .write()
            .map_err(|_| io::Error::other("MST5 account connection lock poisoned"))? =
            Some((generation, client.clone()));
        let _ = self
            .inner
            .events
            .send(AccountEvent::Connected { generation });
        Ok((generation, client))
    }

    async fn invalidate(&self, generation: Option<u64>) {
        if let Ok(Some(client)) = self.take_current(generation) {
            let _ = client.close().await;
        }
    }

    fn current(&self) -> io::Result<Option<(u64, Client)>> {
        self.inner
            .current
            .read()
            .map(|value| value.clone())
            .map_err(|_| io::Error::other("MST5 account connection lock poisoned"))
    }

    fn take_current(&self, generation: Option<u64>) -> io::Result<Option<Client>> {
        let mut current = self
            .inner
            .current
            .write()
            .map_err(|_| io::Error::other("MST5 account connection lock poisoned"))?;
        if generation.is_some() && current.as_ref().map(|value| value.0) != generation {
            return Ok(None);
        }
        Ok(current.take().map(|value| value.1))
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let min = self.inner.config.reconnect_min.as_millis().max(1) as u64;
        let max = self.inner.config.reconnect_max.as_millis().max(min as u128) as u64;
        let cap = min.saturating_mul(1_u64 << attempt.min(16)).min(max);
        let mut random = [0_u8; 8];
        let value = if getrandom::fill(&mut random).is_ok() {
            u64::from_le_bytes(random)
        } else {
            0
        };
        Duration::from_millis(value % cap.saturating_add(1))
    }
}

fn is_authentication_error(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::PermissionDenied)
        || error.to_string().contains("UNAUTHENTICATED")
        || error.to_string().contains("invalid credentials")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_jitter_backoff_stays_inside_configured_cap() {
        let mut config = AccountConfig::new("127.0.0.1:1", "pin", "token", "Android");
        config.reconnect_min = Duration::from_millis(500);
        config.reconnect_max = Duration::from_secs(60);
        let account = AccountClient::new(config).unwrap();
        for attempt in 0..32 {
            assert!(account.backoff(attempt) <= Duration::from_secs(60));
        }
    }

    #[test]
    fn account_rejects_oversized_client_name() {
        let config = AccountConfig::new("127.0.0.1:1", "pin", "token", "x".repeat(65));
        assert!(AccountClient::new(config).is_err());
    }
}
