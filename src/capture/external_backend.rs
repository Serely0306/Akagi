//! Authenticated LAN WebSocket capture source for externally captured
//! Mahjong Soul frames.

use super::{flow::slugify, ShutdownToken};
use super::{flow::FlowBridges, CaptureBackend, CaptureCtx, CaptureDescriptor, CaptureKind};
use crate::bridge::{BridgeHooks, Direction};
use crate::config::{ExternalCaptureConfig, Platform};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::StreamExt as _;
use hudsucker::tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        protocol::WebSocketConfig,
        Message,
    },
};
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

const PROTOCOL_VERSION: u8 = 1;
const CAPTURE_PATH: &str = "/capture";
const MAX_SESSIONS: usize = 64;
const MIN_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub struct ExternalBackend {
    cfg: ExternalCaptureConfig,
}

impl ExternalBackend {
    pub fn new(cfg: ExternalCaptureConfig) -> Self {
        Self { cfg }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireDirection {
    ClientToServer,
    ServerToClient,
}

impl From<WireDirection> for Direction {
    fn from(value: WireDirection) -> Self {
        match value {
            WireDirection::ClientToServer => Direction::Up,
            WireDirection::ServerToClient => Direction::Down,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireMessage {
    Frame {
        version: u8,
        session_id: String,
        sequence: u64,
        timestamp_ms: i64,
        direction: WireDirection,
        uri: String,
        payload_base64: String,
    },
    SessionClose {
        version: u8,
        session_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceDecision {
    Accept,
    Duplicate,
    Gap { expected: u64, got: u64 },
    Poisoned,
}

#[derive(Debug, Default)]
struct SessionSequence {
    last: Option<u64>,
    poisoned: bool,
}

impl SessionSequence {
    fn observe(&mut self, sequence: u64) -> SequenceDecision {
        if self.poisoned {
            return SequenceDecision::Poisoned;
        }
        let expected = self.last.and_then(|last| last.checked_add(1)).unwrap_or(1);
        if self.last.is_some_and(|last| sequence <= last) {
            return SequenceDecision::Duplicate;
        }
        if sequence != expected {
            self.poisoned = true;
            return SequenceDecision::Gap {
                expected,
                got: sequence,
            };
        }
        self.last = Some(sequence);
        SequenceDecision::Accept
    }
}

struct ExternalState {
    bridges: Arc<FlowBridges<String>>,
    sequences: HashMap<String, SessionSequence>,
    mjai_bus: crate::event_bus::MjaiBus,
    max_message_bytes: usize,
}

impl ExternalState {
    fn process(&mut self, message: WireMessage) -> Result<()> {
        match message {
            WireMessage::Frame {
                version,
                session_id,
                sequence,
                timestamp_ms,
                direction,
                uri,
                payload_base64,
            } => {
                validate_version(version)?;
                validate_session_id(&session_id)?;
                if uri.len() > 2048 {
                    bail!("external capture URI is too long");
                }
                if !self.sequences.contains_key(&session_id) && self.sequences.len() >= MAX_SESSIONS
                {
                    bail!("external capture session limit exceeded");
                }

                let payload = BASE64
                    .decode(payload_base64.as_bytes())
                    .context("external capture payload is not valid base64")?;
                if payload.len() > self.max_message_bytes {
                    bail!("external capture decoded payload exceeds configured limit");
                }

                let decision = self
                    .sequences
                    .entry(session_id.clone())
                    .or_default()
                    .observe(sequence);
                match decision {
                    SequenceDecision::Duplicate => {
                        debug!(session = %session_id, sequence, "external capture duplicate dropped");
                        return Ok(());
                    }
                    SequenceDecision::Poisoned => {
                        debug!(session = %session_id, sequence, "external capture poisoned session dropped");
                        return Ok(());
                    }
                    SequenceDecision::Gap { expected, got } => {
                        warn!(
                            session = %session_id,
                            expected,
                            got,
                            "external capture sequence gap; session retired"
                        );
                        self.retire_bridge(&session_id, &uri);
                        return Ok(());
                    }
                    SequenceDecision::Accept => {}
                }

                let label = format!("external ws {uri}");
                let bridge =
                    self.bridges
                        .acquire(session_id.clone(), &slugify(&session_id), &label);
                let result = {
                    let mut bridge = bridge.lock().expect("bridge mutex poisoned");
                    bridge.parse(direction.into(), &payload)
                };
                let emitted = result.events.len();
                for event in result.events {
                    let _ = self.mjai_bus.send(event);
                }
                debug!(
                    session = %session_id,
                    sequence,
                    timestamp_ms,
                    bytes = payload.len(),
                    emitted,
                    "external capture packet accepted"
                );
                Ok(())
            }
            WireMessage::SessionClose {
                version,
                session_id,
            } => {
                validate_version(version)?;
                validate_session_id(&session_id)?;
                self.sequences.remove(&session_id);
                self.retire_bridge(&session_id, "session-close");
                info!(session = %session_id, "external capture session closed");
                Ok(())
            }
        }
    }

    fn retire_bridge(&self, session_id: &str, label: &str) {
        let key = session_id.to_string();
        let bridge = self
            .bridges
            .acquire(key.clone(), &slugify(session_id), label);
        self.bridges.release(&key, bridge);
    }
}

#[async_trait]
impl CaptureBackend for ExternalBackend {
    async fn run(self: Box<Self>, ctx: CaptureCtx, shutdown: ShutdownToken) -> Result<()> {
        if !self.cfg.enabled {
            bail!("external capture is selected but capture.external.enabled is false");
        }
        if self.cfg.auth_token.trim().is_empty() {
            bail!("external capture requires a non-empty auth token");
        }
        if ctx.platform != Platform::Majsoul {
            bail!("external capture currently accepts Majsoul frames only");
        }

        let max_message_bytes = self
            .cfg
            .max_message_bytes
            .clamp(MIN_MESSAGE_BYTES, MAX_MESSAGE_BYTES);
        let listener = TcpListener::bind(&self.cfg.bind_addr)
            .await
            .with_context(|| format!("binding external capture at {}", self.cfg.bind_addr))?;
        let local_addr = listener
            .local_addr()
            .context("reading external capture address")?;
        info!("external capture listening on ws://{local_addr}{CAPTURE_PATH}");

        let bridges = Arc::new(FlowBridges::<String>::new(
            ctx.session,
            ctx.platform,
            BridgeHooks::default(),
        ));
        let mut state = ExternalState {
            bridges,
            sequences: HashMap::new(),
            mjai_bus: ctx.mjai_bus,
            max_message_bytes,
        };
        let shutdown_wait = shutdown.wait();
        tokio::pin!(shutdown_wait);

        loop {
            tokio::select! {
                _ = &mut shutdown_wait => {
                    info!("external capture shutdown requested");
                    return Ok(());
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.context("accepting external capture connection")?;
                    info!(%peer, "external capture client connected");
                    let result = handle_connection(
                        stream,
                        &self.cfg.auth_token,
                        max_message_bytes,
                        &shutdown,
                        &mut state,
                    ).await;
                    match result {
                        Ok(()) => info!(%peer, "external capture client disconnected"),
                        Err(error) => warn!(%peer, %error, "external capture client rejected/disconnected"),
                    }
                }
            }
        }
    }

    fn descriptor(&self) -> CaptureDescriptor {
        CaptureDescriptor {
            kind: CaptureKind::External,
            label: self.cfg.bind_addr.clone(),
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    expected_token: &str,
    max_message_bytes: usize,
    shutdown: &ShutdownToken,
    state: &mut ExternalState,
) -> Result<()> {
    let token = expected_token.to_string();
    let callback = move |request: &Request, response: Response| {
        authorize_upgrade(request, &token).map(|()| response)
    };
    let config = WebSocketConfig {
        max_message_size: Some(max_message_bytes),
        max_frame_size: Some(max_message_bytes),
        ..Default::default()
    };
    let mut socket = accept_hdr_async_with_config(stream, callback, Some(config))
        .await
        .context("external capture WebSocket upgrade failed")?;
    let shutdown_wait = shutdown.wait();
    tokio::pin!(shutdown_wait);

    loop {
        tokio::select! {
            _ = &mut shutdown_wait => return Ok(()),
            next = socket.next() => {
                let Some(message) = next else { return Ok(()) };
                match message.context("reading external capture WebSocket message")? {
                    Message::Text(text) => {
                        let message: WireMessage = serde_json::from_str(text.as_str())
                            .context("invalid external capture JSON message")?;
                        state.process(message)?;
                    }
                    Message::Close(_) => return Ok(()),
                    Message::Ping(_) | Message::Pong(_) => {}
                    Message::Binary(_) => bail!("external capture protocol v1 requires JSON text messages"),
                    Message::Frame(_) => bail!("unexpected raw WebSocket frame"),
                }
            }
        }
    }
}

fn authorize_upgrade(request: &Request, expected_token: &str) -> Result<(), ErrorResponse> {
    if request.uri().path() != CAPTURE_PATH {
        return Err(rejection(http::StatusCode::NOT_FOUND, "not found"));
    }
    let supplied = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if supplied.is_some_and(|value| constant_time_eq(expected_token, value)) {
        Ok(())
    } else {
        Err(rejection(http::StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

fn rejection(status: http::StatusCode, body: &str) -> ErrorResponse {
    http::Response::builder()
        .status(status)
        .body(Some(body.to_string()))
        .expect("static WebSocket rejection response must build")
}

fn constant_time_eq(expected: &str, supplied: &str) -> bool {
    let expected = expected.as_bytes();
    let supplied = supplied.as_bytes();
    let mut diff = expected.len() ^ supplied.len();
    for index in 0..expected.len().max(supplied.len()) {
        let a = expected.get(index).copied().unwrap_or(0);
        let b = supplied.get(index).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

fn validate_version(version: u8) -> Result<()> {
    if version != PROTOCOL_VERSION {
        bail!("unsupported external capture protocol version {version}");
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty() || session_id.len() > 128 {
        bail!("external capture session id length is invalid");
    }
    if !session_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        bail!("external capture session id contains invalid characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bridge::{Bridge, MajsoulBridge},
        schema::MjaiEvent,
    };
    use prost::Message as _;
    use prost_reflect::{DynamicMessage, Value};

    #[derive(prost::Message)]
    struct TestWrapper {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(bytes = "vec", tag = "2")]
        data: Vec<u8>,
    }

    fn liqi_frame(kind: u8, id: u16, name: &str, data: Vec<u8>) -> Vec<u8> {
        let wrapper = TestWrapper {
            name: name.to_string(),
            data,
        };
        let mut frame = vec![kind];
        if kind != 1 {
            frame.extend(id.to_le_bytes());
        }
        frame.extend(wrapper.encode_to_vec());
        frame
    }

    fn wire_frame(sequence: u64, direction: &str, payload: &[u8]) -> WireMessage {
        serde_json::from_value(serde_json::json!({
            "type": "frame",
            "version": 1,
            "session_id": "boot/ws-1",
            "sequence": sequence,
            "timestamp_ms": 1_700_000_000_000_i64 + sequence as i64,
            "direction": direction,
            "uri": "wss://example.invalid/gateway",
            "payload_base64": BASE64.encode(payload),
        }))
        .unwrap()
    }

    fn frame_parts(message: WireMessage) -> (Direction, Vec<u8>) {
        match message {
            WireMessage::Frame {
                direction,
                payload_base64,
                ..
            } => (direction.into(), BASE64.decode(payload_base64).unwrap()),
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn sequence_starts_at_one_deduplicates_and_poison_on_gap() {
        let mut state = SessionSequence::default();
        assert_eq!(state.observe(1), SequenceDecision::Accept);
        assert_eq!(state.observe(1), SequenceDecision::Duplicate);
        assert_eq!(state.observe(2), SequenceDecision::Accept);
        assert_eq!(
            state.observe(4),
            SequenceDecision::Gap {
                expected: 3,
                got: 4
            }
        );
        assert_eq!(state.observe(3), SequenceDecision::Poisoned);
    }

    #[test]
    fn sequence_rejects_partial_session_prefix() {
        let mut state = SessionSequence::default();
        assert_eq!(
            state.observe(42),
            SequenceDecision::Gap {
                expected: 1,
                got: 42
            }
        );
    }

    #[test]
    fn authorization_requires_path_and_bearer_token() {
        let ok = Request::builder()
            .uri(CAPTURE_PATH)
            .header(http::header::AUTHORIZATION, "Bearer correct")
            .body(())
            .unwrap();
        assert!(authorize_upgrade(&ok, "correct").is_ok());

        let wrong = Request::builder()
            .uri(CAPTURE_PATH)
            .header(http::header::AUTHORIZATION, "Bearer wrong")
            .body(())
            .unwrap();
        assert_eq!(
            authorize_upgrade(&wrong, "correct").unwrap_err().status(),
            http::StatusCode::UNAUTHORIZED
        );

        let path = Request::builder()
            .uri("/other")
            .header(http::header::AUTHORIZATION, "Bearer correct")
            .body(())
            .unwrap();
        assert_eq!(
            authorize_upgrade(&path, "correct").unwrap_err().status(),
            http::StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn wire_frame_deserializes_without_exposing_payload_in_debug_logs() {
        let json = r#"{
            "type":"frame","version":1,"session_id":"boot/ws-1",
            "sequence":1,"timestamp_ms":1700000000000,
            "direction":"server_to_client","uri":"wss://example.invalid/gateway",
            "payload_base64":"AQID"
        }"#;
        let message: WireMessage = serde_json::from_str(json).unwrap();
        match message {
            WireMessage::Frame {
                session_id,
                sequence,
                payload_base64,
                ..
            } => {
                assert_eq!(session_id, "boot/ws-1");
                assert_eq!(sequence, 1);
                assert_eq!(BASE64.decode(payload_base64).unwrap(), [1, 2, 3]);
            }
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn session_id_is_bounded_and_filename_safe() {
        assert!(validate_session_id("boot-id/ws_1.2").is_ok());
        assert!(validate_session_id("").is_err());
        assert!(validate_session_id("../bad:session").is_err());
        assert!(validate_session_id(&"x".repeat(129)).is_err());
    }

    #[test]
    fn external_envelopes_feed_existing_bridge_and_preserve_three_player_seat() {
        let mut request = DynamicMessage::new(
            crate::bridge::majsoul::parser::POOL
                .get_message_by_name("lq.ReqAuthGame")
                .unwrap(),
        );
        request.set_field_by_name("account_id", Value::U32(12_345));
        request.set_field_by_name("game_uuid", Value::String("test-game".into()));

        let mut response = DynamicMessage::new(
            crate::bridge::majsoul::parser::POOL
                .get_message_by_name("lq.ResAuthGame")
                .unwrap(),
        );
        response.set_field_by_name(
            "seat_list",
            Value::List(vec![Value::U32(10), Value::U32(12_345), Value::U32(20)]),
        );

        let request = liqi_frame(2, 7, ".lq.FastTest.authGame", request.encode_to_vec());
        let response = liqi_frame(3, 7, "", response.encode_to_vec());
        let mut bridge = MajsoulBridge::new(None, None);

        let (direction, payload) = frame_parts(wire_frame(1, "client_to_server", &request));
        assert!(bridge.parse(direction, &payload).events.is_empty());

        let (direction, payload) = frame_parts(wire_frame(2, "server_to_client", &response));
        let events = bridge.parse(direction, &payload).events;
        assert!(matches!(
            events.as_slice(),
            [MjaiEvent::StartGame {
                id: Some(1),
                num_players: 3,
                names,
                ..
            }] if names.len() == 3
        ));
    }
}
