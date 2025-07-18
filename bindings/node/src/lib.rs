use neon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

// PolicyEngine types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Principal {
    id: String,
    attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Scope {
    #[serde(rename = "type")]
    scope_type: String,
    name: String,
    path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Permission {
    resource: String,
    actions: Vec<String>,
    conditions: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Role {
    name: String,
    description: String,
    permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Policy {
    id: String,
    name: String,
    version: String,
    roles: Vec<Role>,
    permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvaluationResult {
    allowed: bool,
    reason: String,
    conditions: Option<HashMap<String, serde_json::Value>>,
    metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    wasm_path: Option<String>,
    log_level: Option<String>,
    max_memory: Option<i64>,
    timeout: Option<i64>,
    environment: Option<HashMap<String, String>>,
}

// PolicyEngine wrapper for Node.js
struct PolicyEngineNode {
    engine: Arc<policyengine::PolicyEngine>,
    runtime: Arc<Runtime>,
}

impl PolicyEngineNode {
    fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = Arc::new(Runtime::new()?);
        let engine_config = policyengine::config::Config {
            wasm: policyengine::config::WasmConfig {
                path: config.wasm_path.unwrap_or_else(|| "policy.wasm".to_string()),
                max_memory: config.max_memory.unwrap_or(1024 * 1024 * 100), // 100MB
                timeout: std::time::Duration::from_millis(config.timeout.unwrap_or(5000) as u64),
            },
            log: policyengine::config::LogConfig {
                level: config.log_level.unwrap_or_else(|| "info".to_string()),
            },
            ..Default::default()
        };

        let engine = runtime.block_on(async {
            policyengine::PolicyEngine::new(engine_config).await
        })?;

        Ok(Self {
            engine: Arc::new(engine),
            runtime: runtime,
        })
    }

    fn load_policy(&self, policy_data: &str) -> Result<(), Box<dyn std::error::Error>> {
        let engine = Arc::clone(&self.engine);
        self.runtime.block_on(async {
            engine.load_policy(policy_data.as_bytes()).await
        })?;
        Ok(())
    }

    fn evaluate(
        &self,
        principal: Principal,
        scope: Scope,
        context: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        let engine = Arc::clone(&self.engine);
        let principal_inner = policyengine::policy::Principal {
            id: principal.id,
            attributes: principal.attributes,
        };
        let scope_inner = policyengine::policy::Scope::Resource {
            name: scope.name,
            path: scope.path,
        };

        let result = self.runtime.block_on(async {
            engine.evaluate(&principal_inner, &scope_inner, context.as_ref()).await
        })?;

        Ok(EvaluationResult {
            allowed: result.allowed,
            reason: result.reason.unwrap_or_else(|| "No reason provided".to_string()),
            conditions: result.conditions,
            metadata: result.metadata,
        })
    }

    fn can_access(&self, principal: Principal, resource: &str, action: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let scope = Scope {
            scope_type: "resource".to_string(),
            name: resource.to_string(),
            path: vec![action.to_string()],
        };

        let result = self.evaluate(principal, scope, None)?;
        Ok(result.allowed)
    }

    fn get_stats(&self) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
        let engine = Arc::clone(&self.engine);
        let stats = self.runtime.block_on(async {
            engine.get_stats().await
        })?;
        Ok(stats)
    }

    fn validate_policy(&self, policy_data: &str) -> Result<(), Box<dyn std::error::Error>> {
        let engine = Arc::clone(&self.engine);
        self.runtime.block_on(async {
            engine.validate_policy(policy_data.as_bytes()).await
        })?;
        Ok(())
    }
}

// Node.js bindings
impl Finalize for PolicyEngineNode {}

fn create_policy_engine(mut cx: FunctionContext) -> JsResult<JsBox<PolicyEngineNode>> {
    let config_obj = cx.argument::<JsObject>(0)?;
    let config = neon_serde::from_value(&mut cx, config_obj)?;

    let engine = PolicyEngineNode::new(config)
        .map_err(|e| cx.throw_error(&format!("Failed to create PolicyEngine: {}", e)))?;

    Ok(cx.boxed(engine))
}

fn load_policy(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let engine = cx.this::<JsBox<PolicyEngineNode>>()?;
    let policy_data = cx.argument::<JsString>(0)?.value(&mut cx);

    engine.load_policy(&policy_data)
        .map_err(|e| cx.throw_error(&format!("Failed to load policy: {}", e)))?;

    Ok(cx.undefined())
}

fn evaluate(mut cx: FunctionContext) -> JsResult<JsValue> {
    let engine = cx.this::<JsBox<PolicyEngineNode>>()?;
    let principal_obj = cx.argument::<JsObject>(0)?;
    let scope_obj = cx.argument::<JsObject>(1)?;
    let context_obj = cx.argument_opt(2);

    let principal: Principal = neon_serde::from_value(&mut cx, principal_obj)?;
    let scope: Scope = neon_serde::from_value(&mut cx, scope_obj)?;
    let context: Option<HashMap<String, serde_json::Value>> = if let Some(obj) = context_obj {
        Some(neon_serde::from_value(&mut cx, obj)?)
    } else {
        None
    };

    let result = engine.evaluate(principal, scope, context)
        .map_err(|e| cx.throw_error(&format!("Evaluation failed: {}", e)))?;

    neon_serde::to_value(&mut cx, &result)
        .map_err(|e| cx.throw_error(&format!("Failed to serialize result: {}", e)))
}

fn can_access(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let engine = cx.this::<JsBox<PolicyEngineNode>>()?;
    let principal_obj = cx.argument::<JsObject>(0)?;
    let resource = cx.argument::<JsString>(1)?.value(&mut cx);
    let action = cx.argument::<JsString>(2)?.value(&mut cx);

    let principal: Principal = neon_serde::from_value(&mut cx, principal_obj)?;

    let result = engine.can_access(principal, &resource, &action)
        .map_err(|e| cx.throw_error(&format!("Access check failed: {}", e)))?;

    Ok(cx.boolean(result))
}

fn get_stats(mut cx: FunctionContext) -> JsResult<JsValue> {
    let engine = cx.this::<JsBox<PolicyEngineNode>>()?;

    let stats = engine.get_stats()
        .map_err(|e| cx.throw_error(&format!("Failed to get stats: {}", e)))?;

    neon_serde::to_value(&mut cx, &stats)
        .map_err(|e| cx.throw_error(&format!("Failed to serialize stats: {}", e)))
}

fn validate_policy(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let engine = cx.this::<JsBox<PolicyEngineNode>>()?;
    let policy_data = cx.argument::<JsString>(0)?.value(&mut cx);

    engine.validate_policy(&policy_data)
        .map_err(|e| cx.throw_error(&format!("Policy validation failed: {}", e)))?;

    Ok(cx.undefined())
}

fn get_version(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(env!("CARGO_PKG_VERSION")))
}

// Module registration
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("createPolicyEngine", create_policy_engine)?;
    cx.export_function("getVersion", get_version)?;

    // Add methods to PolicyEngine prototype
    let policy_engine_class = cx.class::<JsBox<PolicyEngineNode>>()?;
    policy_engine_class.method("loadPolicy", load_policy)?;
    policy_engine_class.method("evaluate", evaluate)?;
    policy_engine_class.method("canAccess", can_access)?;
    policy_engine_class.method("getStats", get_stats)?;
    policy_engine_class.method("validatePolicy", validate_policy)?;

    cx.export_class::<JsBox<PolicyEngineNode>>("PolicyEngine")?;

    Ok(())
} 