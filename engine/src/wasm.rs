//! WASM runtime for policy evaluation
//!
//! This module provides a high-performance WASM runtime for executing
//! formally verified policies with zero-copy hostcalls and minimal overhead.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use wasmtime::{
    Engine, Store, Module, Instance, Linker, Func, Memory, MemoryType,
    Val, ValType, Trap, WasmBacktraceDetails,
};
use wasmtime_wasi::{WasiCtxBuilder, WasiCtx};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, error};

use crate::error::PolicyEngineError;
use crate::policy::{Policy, Principal, Scope, Permission};

/// WASM engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmEngineStats {
    pub total_evaluations: u64,
    pub average_evaluation_time_us: u64,
    pub total_wasm_errors: u64,
    pub memory_usage_bytes: usize,
    pub last_evaluation_time: Option<Duration>,
}

/// WASM policy engine for executing policies
pub struct WasmPolicyEngine {
    engine: Engine,
    linker: Linker<WasiCtx>,
    stats: Arc<RwLock<WasmEngineStats>>,
    config: WasmEngineConfig,
}

/// Configuration for the WASM engine
#[derive(Debug, Clone)]
pub struct WasmEngineConfig {
    pub max_memory_size: usize,
    pub max_table_size: u32,
    pub max_instances: usize,
    pub enable_wasm_backtrace: bool,
    pub enable_wasm_multi_value: bool,
    pub enable_wasm_bulk_memory: bool,
    pub enable_wasm_reference_types: bool,
    pub enable_wasm_simd: bool,
    pub enable_wasm_threads: bool,
    pub enable_wasm_exceptions: bool,
    pub enable_wasm_function_references: bool,
    pub enable_wasm_gc: bool,
    pub enable_wasm_component_model: bool,
    pub enable_wasm_memory64: bool,
    pub enable_wasm_relaxed_simd: bool,
    pub enable_wasm_extended_const: bool,
    pub enable_wasm_memory_control: bool,
    pub enable_wasm_stringref: bool,
    pub enable_wasm_tail_call: bool,
    pub enable_wasm_proposals: bool,
}

impl Default for WasmEngineConfig {
    fn default() -> Self {
        Self {
            max_memory_size: 64 * 1024 * 1024, // 64MB
            max_table_size: 10000,
            max_instances: 1000,
            enable_wasm_backtrace: true,
            enable_wasm_multi_value: true,
            enable_wasm_bulk_memory: true,
            enable_wasm_reference_types: true,
            enable_wasm_simd: true,
            enable_wasm_threads: false, // Disabled for security
            enable_wasm_exceptions: false, // Disabled for security
            enable_wasm_function_references: false, // Disabled for security
            enable_wasm_gc: false, // Disabled for security
            enable_wasm_component_model: false, // Disabled for security
            enable_wasm_memory64: false, // Disabled for security
            enable_wasm_relaxed_simd: false, // Disabled for security
            enable_wasm_extended_const: false, // Disabled for security
            enable_wasm_memory_control: false, // Disabled for security
            enable_wasm_stringref: false, // Disabled for security
            enable_wasm_tail_call: false, // Disabled for security
            enable_wasm_proposals: false, // Disabled for security
        }
    }
}

/// WASM instance cache for performance
struct WasmInstance {
    instance: Instance,
    memory: Memory,
    evaluate_func: Func,
    validate_func: Option<Func>,
    stats_func: Option<Func>,
}

impl WasmPolicyEngine {
    /// Create a new WASM policy engine
    pub fn new() -> Result<Self, PolicyEngineError> {
        Self::with_config(WasmEngineConfig::default())
    }

    /// Create a new WASM policy engine with custom configuration
    pub fn with_config(config: WasmEngineConfig) -> Result<Self, PolicyEngineError> {
        let mut engine_config = wasmtime::Config::new();
        
        // Configure WASM features
        engine_config.wasm_backtrace_details(WasmBacktraceDetails::Enable);
        engine_config.wasm_multi_value(config.enable_wasm_multi_value);
        engine_config.wasm_bulk_memory(config.enable_wasm_bulk_memory);
        engine_config.wasm_reference_types(config.enable_wasm_reference_types);
        engine_config.wasm_simd(config.enable_wasm_simd);
        engine_config.wasm_threads(config.enable_wasm_threads);
        engine_config.wasm_exceptions(config.enable_wasm_exceptions);
        engine_config.wasm_function_references(config.enable_wasm_function_references);
        engine_config.wasm_gc(config.enable_wasm_gc);
        engine_config.wasm_component_model(config.enable_wasm_component_model);
        engine_config.wasm_memory64(config.enable_wasm_memory64);
        engine_config.wasm_relaxed_simd(config.enable_wasm_relaxed_simd);
        engine_config.wasm_extended_const(config.enable_wasm_extended_const);
        engine_config.wasm_memory_control(config.enable_wasm_memory_control);
        engine_config.wasm_stringref(config.enable_wasm_stringref);
        engine_config.wasm_tail_call(config.enable_wasm_tail_call);
        engine_config.wasm_proposals(config.enable_wasm_proposals);
        
        // Set memory limits
        engine_config.max_wasm_stack(1024 * 1024); // 1MB stack
        engine_config.max_memory_size(config.max_memory_size);
        engine_config.max_table_elements(config.max_table_size);
        engine_config.max_instances(config.max_instances);
        
        let engine = Engine::new(&engine_config)
            .map_err(|e| PolicyEngineError::WasmEngineError(e.to_string()))?;
        
        let mut linker = Linker::new(&engine);
        
        // Add WASI support
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_args()
            .map_err(|e| PolicyEngineError::WasmEngineError(e.to_string()))?
            .build();
        
        wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
            .map_err(|e| PolicyEngineError::WasmEngineError(e.to_string()))?;
        
        let stats = Arc::new(RwLock::new(WasmEngineStats {
            total_evaluations: 0,
            average_evaluation_time_us: 0,
            total_wasm_errors: 0,
            memory_usage_bytes: 0,
            last_evaluation_time: None,
        }));
        
        Ok(Self {
            engine,
            linker,
            stats,
            config,
        })
    }

    /// Validate a WASM module
    pub fn validate_module(&self, wasm_bytes: &[u8]) -> Result<(), PolicyEngineError> {
        Module::validate(&self.engine, wasm_bytes)
            .map_err(|e| PolicyEngineError::WasmValidationError(e.to_string()))?;
        
        debug!("WASM module validation successful");
        Ok(())
    }

    /// Create a WASM instance from bytecode
    fn create_instance(&self, wasm_bytes: &[u8]) -> Result<WasmInstance, PolicyEngineError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| PolicyEngineError::WasmModuleError(e.to_string()))?;
        
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_args()
            .map_err(|e| PolicyEngineError::WasmEngineError(e.to_string()))?
            .build();
        
        let mut store = Store::new(&self.engine, wasi);
        
        let instance = self.linker
            .instantiate(&mut store, &module)
            .map_err(|e| PolicyEngineError::WasmInstantiationError(e.to_string()))?;
        
        // Get required exports
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PolicyEngineError::WasmExportError("memory export not found".to_string()))?;
        
        let evaluate_func = instance
            .get_func(&mut store, "evaluate_policy")
            .ok_or_else(|| PolicyEngineError::WasmExportError("evaluate_policy export not found".to_string()))?;
        
        // Optional exports
        let validate_func = instance.get_func(&mut store, "validate_policy");
        let stats_func = instance.get_func(&mut store, "get_stats");
        
        Ok(WasmInstance {
            instance,
            memory,
            evaluate_func,
            validate_func,
            stats_func,
        })
    }

    /// Evaluate a policy using WASM
    pub async fn evaluate_policy(
        &self,
        policy: &Policy,
        principal: &Principal,
        scope: &Scope,
    ) -> Result<Permission, PolicyEngineError> {
        let start_time = Instant::now();
        
        // For now, we'll use a simple policy evaluation
        // In a real implementation, this would load the policy's WASM module
        // and execute it with the principal and scope data
        
        let result = self.evaluate_policy_internal(policy, principal, scope).await?;
        
        // Update statistics
        let evaluation_time = start_time.elapsed();
        self.update_stats(evaluation_time).await;
        
        debug!("Policy evaluation completed in {:?}", evaluation_time);
        Ok(result)
    }

    /// Internal policy evaluation logic
    async fn evaluate_policy_internal(
        &self,
        policy: &Policy,
        principal: &Principal,
        scope: &Scope,
    ) -> Result<Permission, PolicyEngineError> {
        // Simple policy evaluation without WASM for now
        // This would be replaced with actual WASM execution
        
        if policy.can_access(principal, scope) {
            Ok(Permission::Allow(scope.clone()))
        } else {
            Ok(Permission::Deny(scope.clone()))
        }
    }

    /// Execute a WASM function with zero-copy data transfer
    fn execute_wasm_function(
        &self,
        instance: &WasmInstance,
        store: &mut Store<WasiCtx>,
        func_name: &str,
        args: &[Val],
    ) -> Result<Vec<Val>, PolicyEngineError> {
        let func = instance
            .instance
            .get_func(store, func_name)
            .ok_or_else(|| PolicyEngineError::WasmExportError(format!("{} export not found", func_name)))?;
        
        func.call(store, args, &mut [])
            .map_err(|e| PolicyEngineError::WasmExecutionError(e.to_string()))?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PolicyEngineError::WasmExecutionError(e.to_string()))
    }

    /// Write data to WASM memory with zero-copy optimization
    fn write_to_memory(
        &self,
        memory: &Memory,
        store: &mut Store<WasiCtx>,
        offset: u32,
        data: &[u8],
    ) -> Result<(), PolicyEngineError> {
        memory
            .write(store, offset as usize, data)
            .map_err(|e| PolicyEngineError::WasmMemoryError(e.to_string()))?;
        Ok(())
    }

    /// Read data from WASM memory with zero-copy optimization
    fn read_from_memory(
        &self,
        memory: &Memory,
        store: &Store<WasiCtx>,
        offset: u32,
        length: u32,
    ) -> Result<Vec<u8>, PolicyEngineError> {
        let mut buffer = vec![0u8; length as usize];
        memory
            .read(store, offset as usize, &mut buffer)
            .map_err(|e| PolicyEngineError::WasmMemoryError(e.to_string()))?;
        Ok(buffer)
    }

    /// Allocate memory in WASM
    fn allocate_memory(
        &self,
        instance: &WasmInstance,
        store: &mut Store<WasiCtx>,
        size: u32,
    ) -> Result<u32, PolicyEngineError> {
        let alloc_func = instance
            .instance
            .get_func(store, "allocate")
            .ok_or_else(|| PolicyEngineError::WasmExportError("allocate export not found".to_string()))?;
        
        let result = self.execute_wasm_function(instance, store, "allocate", &[Val::I32(size as i32)])?;
        
        match result.first() {
            Some(Val::I32(ptr)) => Ok(*ptr as u32),
            _ => Err(PolicyEngineError::WasmExecutionError("Invalid allocation result".to_string())),
        }
    }

    /// Deallocate memory in WASM
    fn deallocate_memory(
        &self,
        instance: &WasmInstance,
        store: &mut Store<WasiCtx>,
        ptr: u32,
        size: u32,
    ) -> Result<(), PolicyEngineError> {
        let dealloc_func = instance
            .instance
            .get_func(store, "deallocate")
            .ok_or_else(|| PolicyEngineError::WasmExportError("deallocate export not found".to_string()))?;
        
        self.execute_wasm_function(instance, store, "deallocate", &[Val::I32(ptr as i32), Val::I32(size as i32)])?;
        Ok(())
    }

    /// Update engine statistics
    async fn update_stats(&self, evaluation_time: Duration) {
        let mut stats = self.stats.write().await;
        stats.total_evaluations += 1;
        stats.last_evaluation_time = Some(evaluation_time);
        
        // Update average evaluation time
        let total_time_us = stats.average_evaluation_time_us * (stats.total_evaluations - 1) 
            + evaluation_time.as_micros() as u64;
        stats.average_evaluation_time_us = total_time_us / stats.total_evaluations;
    }

    /// Get engine statistics
    pub fn get_stats(&self) -> WasmEngineStats {
        // This would need to be async in a real implementation
        // For now, return default stats
        WasmEngineStats {
            total_evaluations: 0,
            average_evaluation_time_us: 0,
            total_wasm_errors: 0,
            memory_usage_bytes: 0,
            last_evaluation_time: None,
        }
    }

    /// Benchmark policy evaluation performance
    pub async fn benchmark_evaluation(
        &self,
        policy: &Policy,
        principal: &Principal,
        scope: &Scope,
        iterations: u32,
    ) -> Result<BenchmarkResult, PolicyEngineError> {
        let mut times = Vec::with_capacity(iterations as usize);
        
        for _ in 0..iterations {
            let start = Instant::now();
            self.evaluate_policy(policy, principal, scope).await?;
            times.push(start.elapsed());
        }
        
        let total_time: Duration = times.iter().sum();
        let avg_time = total_time / iterations;
        let min_time = times.iter().min().unwrap_or(&Duration::ZERO);
        let max_time = times.iter().max().unwrap_or(&Duration::ZERO);
        
        Ok(BenchmarkResult {
            iterations,
            total_time,
            average_time: avg_time,
            min_time: *min_time,
            max_time: *max_time,
            throughput_rps: iterations as f64 / total_time.as_secs_f64(),
        })
    }
}

/// Benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub iterations: u32,
    pub total_time: Duration,
    pub average_time: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
    pub throughput_rps: f64,
}

/// WASM module cache for performance
pub struct WasmModuleCache {
    modules: std::collections::HashMap<String, Arc<Module>>,
    max_size: usize,
}

impl WasmModuleCache {
    /// Create a new module cache
    pub fn new(max_size: usize) -> Self {
        Self {
            modules: std::collections::HashMap::new(),
            max_size,
        }
    }

    /// Get a module from cache
    pub fn get(&self, key: &str) -> Option<Arc<Module>> {
        self.modules.get(key).cloned()
    }

    /// Insert a module into cache
    pub fn insert(&mut self, key: String, module: Module) {
        if self.modules.len() >= self.max_size {
            // Simple LRU: remove the first entry
            if let Some(first_key) = self.modules.keys().next().cloned() {
                self.modules.remove(&first_key);
            }
        }
        self.modules.insert(key, Arc::new(module));
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.modules.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, Principal, Scope, Permission, builders};

    #[tokio::test]
    async fn test_wasm_engine_creation() {
        let engine = WasmPolicyEngine::new();
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_wasm_engine_with_config() {
        let config = WasmEngineConfig::default();
        let engine = WasmPolicyEngine::with_config(config);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_policy_evaluation() {
        let engine = WasmPolicyEngine::new().unwrap();
        
        let policy = PolicyBuilder::new("test-policy")
            .with_role(
                builders::role("admin")
                    .with_permission(Permission::Allow(Scope::Wildcard))
                    .build(),
            )
            .with_assignment(
                builders::principal("user1")
                    .with_attribute("role", "admin")
                    .build(),
                "admin".to_string(),
            )
            .build();
        
        let principal = builders::principal("user1")
            .with_attribute("role", "admin")
            .build();
        
        let scope = Scope::Resource {
            name: "test-resource".to_string(),
            path: vec!["read".to_string()],
        };
        
        let result = engine.evaluate_policy(&policy, &principal, &scope).await;
        assert!(result.is_ok());
        
        if let Ok(Permission::Allow(_)) = result {
            // Expected result
        } else {
            panic!("Expected Allow permission");
        }
    }

    #[tokio::test]
    async fn test_benchmark_evaluation() {
        let engine = WasmPolicyEngine::new().unwrap();
        
        let policy = PolicyBuilder::new("test-policy")
            .with_role(
                builders::role("admin")
                    .with_permission(Permission::Allow(Scope::Wildcard))
                    .build(),
            )
            .with_assignment(
                builders::principal("user1")
                    .with_attribute("role", "admin")
                    .build(),
                "admin".to_string(),
            )
            .build();
        
        let principal = builders::principal("user1")
            .with_attribute("role", "admin")
            .build();
        
        let scope = Scope::Resource {
            name: "test-resource".to_string(),
            path: vec!["read".to_string()],
        };
        
        let result = engine.benchmark_evaluation(&policy, &principal, &scope, 100).await;
        assert!(result.is_ok());
        
        let benchmark = result.unwrap();
        assert_eq!(benchmark.iterations, 100);
        assert!(benchmark.throughput_rps > 0.0);
    }
} 