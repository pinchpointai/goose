//! A single authorization hook that every tool execution passes through.
//!
//! An embedding application (Pinch) registers one [`ToolGate`] at startup. Registration is
//! one-shot: once a gate is set it can't be replaced. With the `pinch-hardened` feature, a call
//! made while no gate is registered is denied; without it, an unregistered gate means "allow"
//! so stock goose behaves as before.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use rmcp::model::{ErrorCode, ErrorData};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub const HARDENED: bool = cfg!(feature = "pinch-hardened");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSite {
    McpTool,
    PlatformTool,
    RecipeShell,
    ExtensionSpawn,
}

#[derive(Debug, Clone)]
pub struct GateCall {
    pub site: CallSite,
    pub session_id: Option<String>,
    pub extension: String,
    pub tool: String,
    pub arguments: Value,
    pub working_dir: Option<PathBuf>,
}

/// Opaque proof of authorization, handed back to the gate after the call finishes.
pub struct GatePass(Box<dyn std::any::Any + Send + Sync>);

impl GatePass {
    pub fn new<T: Send + Sync + 'static>(inner: T) -> Self {
        Self(Box::new(inner))
    }

    pub fn into_inner<T: 'static>(self) -> Option<T> {
        self.0.downcast::<T>().ok().map(|b| *b)
    }
}

#[async_trait]
pub trait ToolGate: Send + Sync {
    /// Resolve to a pass to run the call, or an error explaining the denial. May wait for the
    /// owner's approval; must return promptly once `cancel` fires.
    async fn authorize(
        &self,
        call: &GateCall,
        cancel: &CancellationToken,
    ) -> Result<GatePass, String>;

    fn completed(&self, pass: GatePass, outcome: Result<(), String>);

    /// Text the owner typed into a session (not model, recipe, or tool output).
    fn owner_message(&self, session_id: &str, text: &str);
}

static GATE: OnceLock<Arc<dyn ToolGate>> = OnceLock::new();

pub fn register(gate: Arc<dyn ToolGate>) -> Result<(), String> {
    GATE.set(gate)
        .map_err(|_| "a tool gate is already registered".to_string())
}

pub fn is_registered() -> bool {
    GATE.get().is_some()
}

pub async fn authorize(
    call: &GateCall,
    cancel: &CancellationToken,
) -> Result<Option<GatePass>, String> {
    match GATE.get() {
        Some(gate) => gate.authorize(call, cancel).await.map(Some),
        None if HARDENED => Err("no tool gate is registered".to_string()),
        None => Ok(None),
    }
}

pub fn completed(pass: Option<GatePass>, outcome: Result<(), String>) {
    if let (Some(gate), Some(pass)) = (GATE.get(), pass) {
        gate.completed(pass, outcome);
    }
}

pub fn owner_message(session_id: &str, text: &str) {
    if let Some(gate) = GATE.get() {
        gate.owner_message(session_id, text);
    }
}

pub fn denied(reason: &str) -> ErrorData {
    ErrorData::new(
        ErrorCode::INVALID_REQUEST,
        format!("Blocked by the Pinch gate: {reason}"),
        None,
    )
}

/// MCP servers must not set goose's own control keys (e.g. `goose.executable`,
/// `goose.external_dispatch`) on the tools they list: those keys steer approval and dispatch.
pub fn strip_reserved_meta(meta: &mut serde_json::Map<String, Value>) {
    meta.retain(|key, _| !key.starts_with("goose."));
}

/// Registered for every unit test in this crate: allows everything except calls whose extension
/// tool, or arguments contain `pinch-deny` / `pinch_deny`, and records each call so tests can see which
/// site it came through.
#[cfg(test)]
pub(crate) mod test_gate {
    use super::*;
    use std::sync::Mutex;

    pub(crate) static SEEN: Mutex<Vec<(CallSite, String, String)>> = Mutex::new(Vec::new());
    pub(crate) static COMPLETED: Mutex<Vec<(String, Result<(), String>)>> = Mutex::new(Vec::new());

    struct TestGate;

    #[async_trait]
    impl ToolGate for TestGate {
        async fn authorize(
            &self,
            call: &GateCall,
            _cancel: &CancellationToken,
        ) -> Result<GatePass, String> {
            SEEN.lock()
                .unwrap()
                .push((call.site, call.extension.clone(), call.tool.clone()));
            let label = format!("{}/{} {}", call.extension, call.tool, call.arguments);
            if label.contains("pinch-deny") || label.contains("pinch_deny") {
                Err(format!("test gate denies {label}"))
            } else {
                Ok(GatePass::new(label))
            }
        }

        fn completed(&self, pass: GatePass, outcome: Result<(), String>) {
            let extension = pass.into_inner::<String>().unwrap_or_default();
            COMPLETED.lock().unwrap().push((extension, outcome));
        }

        fn owner_message(&self, _session_id: &str, _text: &str) {}
    }

    #[ctor::ctor]
    unsafe fn install() {
        let _ = register(Arc::new(TestGate));
    }

    pub(crate) fn saw(site: CallSite, needle: &str) -> bool {
        SEEN.lock()
            .unwrap()
            .iter()
            .any(|(s, e, t)| *s == site && (e == needle || t == needle))
    }

    pub(crate) fn completed_ok(needle: &str) -> bool {
        COMPLETED
            .lock()
            .unwrap()
            .iter()
            .any(|(label, outcome)| label.contains(needle) && outcome.is_ok())
    }

    #[test]
    fn registration_is_one_shot() {
        assert!(is_registered());
        assert!(register(Arc::new(TestGate)).is_err());
    }

    #[test]
    fn reserved_meta_keys_are_stripped() {
        let mut meta = serde_json::json!({
            "goose.executable": true,
            "goose.external_dispatch": true,
            "goose_extension": "kept",
            "other": 1
        })
        .as_object()
        .unwrap()
        .clone();
        strip_reserved_meta(&mut meta);
        assert_eq!(
            serde_json::Value::Object(meta),
            serde_json::json!({ "goose_extension": "kept", "other": 1 })
        );
    }
}
