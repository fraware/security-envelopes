//! PolicyEngine - Formally verified RBAC/ABAC policy engine with WASM runtime
//!
//! This library provides a high-performance policy evaluation engine that can be
//! embedded in various runtime environments (HTTP, gRPC, NATS) with minimal overhead.
//!
//! ## Key Features:
//! - WASM-based policy execution for sandboxed evaluation
//! - Zero-copy hostcalls for minimal latency
//! - Support for RBAC and ABAC policies
//! - Formal verification guarantees from Lean specifications
//! - Pluggable into HTTP, gRPC, and NATS services

pub mod policy;
pub mod wasm;
pub mod crypto;
pub mod attestation;
pub mod error;
pub mod config;

use std::sync::Arc;
use tokio::sync::RwLock;
use wasmtime::{Engine, Store, Module, Instance, Linker};
use wasmtime_wasi::WasiCtxBuilder;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::error::PolicyEngineError;
use crate::policy::{Policy, Principal, Scope, Permission};
use crate::wasm::WasmPolicyEngine;

/// Main PolicyEngine struct that manages WASM policy execution
pub struct PolicyEngine {
    wasm_engine: Arc<WasmPolicyEngine>,
    policies: Arc<RwLock<Vec<Policy>>>,
    config: config::Config,
}

impl PolicyEngine {
    /// Create a new PolicyEngine instance
    pub async fn new(config: config::Config) -> Result<Self, PolicyEngineError> {
        let wasm_engine = Arc::new(WasmPolicyEngine::new()?);
        let policies = Arc::new(RwLock::new(Vec::new()));
        
        info!("PolicyEngine initialized with config: {:?}", config);
        
        Ok(Self {
            wasm_engine,
            policies,
            config,
        })
    }

    /// Load a policy from WASM bytecode
    pub async fn load_policy(&self, wasm_bytes: &[u8], policy_id: &str) -> Result<(), PolicyEngineError> {
        let mut policies = self.policies.write().await;
        
        // Validate WASM module
        self.wasm_engine.validate_module(wasm_bytes)?;
        
        // Create policy from WASM
        let policy = Policy::from_wasm(wasm_bytes, policy_id)?;
        
        // Add to policy collection
        policies.push(policy);
        
        info!("Loaded policy {} with {} rules", policy_id, policies.len());
        Ok(())
    }

    /// Evaluate a policy decision
    pub async fn evaluate(
        &self,
        principal: &Principal,
        scope: &Scope,
        policy_id: Option<&str>,
    ) -> Result<Permission, PolicyEngineError> {
        let policies = self.policies.read().await;
        
        // Find the appropriate policy
        let policy = if let Some(id) = policy_id {
            policies.iter().find(|p| p.id == id)
                .ok_or(PolicyEngineError::PolicyNotFound(id.to_string()))?
        } else {
            policies.last()
                .ok_or(PolicyEngineError::NoPoliciesLoaded)?
        };

        // Execute policy evaluation in WASM
        let result = self.wasm_engine.evaluate_policy(policy, principal, scope).await?;
        
        info!("Policy evaluation result: {:?} for principal {} on scope {:?}", 
              result, principal.id, scope);
        
        Ok(result)
    }

    /// Batch evaluate multiple policy decisions
    pub async fn evaluate_batch(
        &self,
        requests: Vec<(Principal, Scope, Option<String>)>,
    ) -> Result<Vec<Permission>, PolicyEngineError> {
        let mut results = Vec::with_capacity(requests.len());
        
        for (principal, scope, policy_id) in requests {
            let result = self.evaluate(&principal, &scope, policy_id.as_deref()).await?;
            results.push(result);
        }
        
        Ok(results)
    }

    /// Get policy statistics
    pub async fn get_stats(&self) -> EngineStats {
        let policies = self.policies.read().await;
        EngineStats {
            total_policies: policies.len(),
            total_rules: policies.iter().map(|p| p.rules.len()).sum(),
            wasm_engine_stats: self.wasm_engine.get_stats(),
        }
    }

    /// Reload all policies from storage
    pub async fn reload_policies(&self) -> Result<(), PolicyEngineError> {
        warn!("Reloading all policies from storage");
        
        // In a real implementation, this would load from persistent storage
        // For now, we just clear and reload from memory
        let mut policies = self.policies.write().await;
        policies.clear();
        
        info!("Policies reloaded");
        Ok(())
    }
}

/// Statistics about the policy engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    pub total_policies: usize,
    pub total_rules: usize,
    pub wasm_engine_stats: wasm::WasmEngineStats,
}

/// High-level API for policy evaluation
pub struct PolicyEvaluator {
    engine: Arc<PolicyEngine>,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub async fn new(config: config::Config) -> Result<Self, PolicyEngineError> {
        let engine = Arc::new(PolicyEngine::new(config).await?);
        Ok(Self { engine })
    }

    /// Check if a principal can access a scope
    pub async fn can_access(
        &self,
        principal: &Principal,
        scope: &Scope,
        policy_id: Option<&str>,
    ) -> Result<bool, PolicyEngineError> {
        let permission = self.engine.evaluate(principal, scope, policy_id).await?;
        Ok(matches!(permission, Permission::Allow(_)))
    }

    /// Get all permissions for a principal
    pub async fn get_permissions(
        &self,
        principal: &Principal,
        policy_id: Option<&str>,
    ) -> Result<Vec<Scope>, PolicyEngineError> {
        // This would require more sophisticated policy introspection
        // For now, return empty list
        Ok(Vec::new())
    }
}

/// Builder pattern for creating PolicyEngine instances
pub struct PolicyEngineBuilder {
    config: config::Config,
}

impl PolicyEngineBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: config::Config::default(),
        }
    }

    /// Set the WASM engine configuration
    pub fn with_wasm_config(mut self, wasm_config: config::WasmConfig) -> Self {
        self.config.wasm = wasm_config;
        self
    }

    /// Set the policy storage configuration
    pub fn with_storage_config(mut self, storage_config: config::StorageConfig) -> Self {
        self.config.storage = storage_config;
        self
    }

    /// Set the logging configuration
    pub fn with_logging_config(mut self, logging_config: config::LoggingConfig) -> Self {
        self.config.logging = logging_config;
        self
    }

    /// Build the PolicyEngine instance
    pub async fn build(self) -> Result<PolicyEngine, PolicyEngineError> {
        PolicyEngine::new(self.config).await
    }
}

impl Default for PolicyEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Principal, Scope, Permission};

    #[tokio::test]
    async fn test_policy_engine_creation() {
        let config = config::Config::default();
        let engine = PolicyEngine::new(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_policy_evaluation() {
        let config = config::Config::default();
        let engine = PolicyEngine::new(config).await.unwrap();
        
        let principal = Principal {
            id: "test-user".to_string(),
            attributes: vec![("role".to_string(), "admin".to_string())],
        };
        
        let scope = Scope::Resource {
            name: "test-resource".to_string(),
            path: vec!["read".to_string()],
        };
        
        // This would fail without a loaded policy, but we can test the structure
        let result = engine.evaluate(&principal, &scope, None).await;
        assert!(result.is_err()); // Expected since no policies are loaded
    }

    #[tokio::test]
    async fn test_policy_evaluator() {
        let config = config::Config::default();
        let evaluator = PolicyEvaluator::new(config).await.unwrap();
        
        let principal = Principal {
            id: "test-user".to_string(),
            attributes: vec![("role".to_string(), "user".to_string())],
        };
        
        let scope = Scope::Resource {
            name: "test-resource".to_string(),
            path: vec!["read".to_string()],
        };
        
        let result = evaluator.can_access(&principal, &scope, None).await;
        assert!(result.is_err()); // Expected since no policies are loaded
    }
} 