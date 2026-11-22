//! No gate is registered in this test binary, so it shows what happens before Pinch registers one.

use goose::tool_gate::{self, CallSite, GateCall};
use tokio_util::sync::CancellationToken;

fn call() -> GateCall {
    GateCall {
        site: CallSite::PlatformTool,
        session_id: None,
        extension: "developer".to_string(),
        tool: "shell".to_string(),
        arguments: serde_json::json!({ "command": "ls" }),
        working_dir: None,
    }
}

#[tokio::test]
async fn unregistered_gate_denies_only_when_hardened() {
    let result = tool_gate::authorize(&call(), &CancellationToken::new()).await;
    if tool_gate::HARDENED {
        assert!(result.is_err());
    } else {
        assert!(matches!(result, Ok(None)));
    }
}

const EXTERNAL_AGENT_PROVIDERS: &[&str] = &[
    "claude-code",
    "codex",
    "gemini-cli",
    "cursor-agent",
    "claude-acp",
    "codex-acp",
    "amp-acp",
    "copilot-acp",
    "pi-acp",
];

#[tokio::test]
async fn external_agent_providers_exist_only_when_not_hardened() {
    let names: Vec<String> = goose::providers::providers()
        .await
        .into_iter()
        .map(|(meta, _)| meta.name)
        .collect();
    for provider in EXTERNAL_AGENT_PROVIDERS {
        assert_eq!(
            names.iter().any(|n| n == provider),
            !tool_gate::HARDENED,
            "{provider}"
        );
    }
    assert!(names.iter().any(|n| n == "anthropic"));
    assert!(names.iter().any(|n| n == "openai"));
}

#[test]
fn project_plugins_are_ignored_when_hardened() {
    let project = tempfile::tempdir().unwrap();
    let plugin = project.path().join(".agents/plugins/demo/hooks");
    std::fs::create_dir_all(&plugin).unwrap();
    std::fs::write(
        plugin.join("hooks.json"),
        r#"{"hooks":{"SessionStart":[{"hooks":[]}]}}"#,
    )
    .unwrap();
    let found = goose::plugins::discovery::discover_enabled_plugins(Some(project.path()));
    assert_eq!(found.is_empty(), tool_gate::HARDENED, "{found:?}");
}
