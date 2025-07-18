//! Error handling for the PolicyEngine
//!
//! This module defines comprehensive error types for all PolicyEngine operations,
//! including WASM execution, policy validation, and runtime errors.

use thiserror::Error;
use std::fmt;

/// Main error type for PolicyEngine operations
#[derive(Error, Debug)]
pub enum PolicyEngineError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("No policies loaded")]
    NoPoliciesLoaded,

    #[error("WASM engine error: {0}")]
    WasmEngineError(String),

    #[error("WASM validation error: {0}")]
    WasmValidationError(String),

    #[error("WASM module error: {0}")]
    WasmModuleError(String),

    #[error("WASM instantiation error: {0}")]
    WasmInstantiationError(String),

    #[error("WASM execution error: {0}")]
    WasmExecutionError(String),

    #[error("WASM export error: {0}")]
    WasmExportError(String),

    #[error("WASM memory error: {0}")]
    WasmMemoryError(String),

    #[error("Policy validation error: {0}")]
    PolicyValidationError(String),

    #[error("Principal validation error: {0}")]
    PrincipalValidationError(String),

    #[error("Scope validation error: {0}")]
    ScopeValidationError(String),

    #[error("Permission validation error: {0}")]
    PermissionValidationError(String),

    #[error("Role validation error: {0}")]
    RoleValidationError(String),

    #[error("ABAC condition error: {0}")]
    ABACConditionError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("Attestation error: {0}")]
    AttestationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("State error: {0}")]
    StateError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Parse float error: {0}")]
    ParseFloatError(#[from] std::num::ParseFloatError),
}

impl PolicyEngineError {
    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            PolicyEngineError::NetworkError(_) |
            PolicyEngineError::TimeoutError(_) |
            PolicyEngineError::RateLimitError(_) |
            PolicyEngineError::IoError(_)
        )
    }

    /// Check if the error is a validation error
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            PolicyEngineError::PolicyValidationError(_) |
            PolicyEngineError::PrincipalValidationError(_) |
            PolicyEngineError::ScopeValidationError(_) |
            PolicyEngineError::PermissionValidationError(_) |
            PolicyEngineError::RoleValidationError(_) |
            PolicyEngineError::ABACConditionError(_) |
            PolicyEngineError::InvalidArgument(_)
        )
    }

    /// Check if the error is a WASM-related error
    pub fn is_wasm_error(&self) -> bool {
        matches!(
            self,
            PolicyEngineError::WasmEngineError(_) |
            PolicyEngineError::WasmValidationError(_) |
            PolicyEngineError::WasmModuleError(_) |
            PolicyEngineError::WasmInstantiationError(_) |
            PolicyEngineError::WasmExecutionError(_) |
            PolicyEngineError::WasmExportError(_) |
            PolicyEngineError::WasmMemoryError(_)
        )
    }

    /// Get the error code for the error
    pub fn error_code(&self) -> &'static str {
        match self {
            PolicyEngineError::PolicyNotFound(_) => "POLICY_NOT_FOUND",
            PolicyEngineError::NoPoliciesLoaded => "NO_POLICIES_LOADED",
            PolicyEngineError::WasmEngineError(_) => "WASM_ENGINE_ERROR",
            PolicyEngineError::WasmValidationError(_) => "WASM_VALIDATION_ERROR",
            PolicyEngineError::WasmModuleError(_) => "WASM_MODULE_ERROR",
            PolicyEngineError::WasmInstantiationError(_) => "WASM_INSTANTIATION_ERROR",
            PolicyEngineError::WasmExecutionError(_) => "WASM_EXECUTION_ERROR",
            PolicyEngineError::WasmExportError(_) => "WASM_EXPORT_ERROR",
            PolicyEngineError::WasmMemoryError(_) => "WASM_MEMORY_ERROR",
            PolicyEngineError::PolicyValidationError(_) => "POLICY_VALIDATION_ERROR",
            PolicyEngineError::PrincipalValidationError(_) => "PRINCIPAL_VALIDATION_ERROR",
            PolicyEngineError::ScopeValidationError(_) => "SCOPE_VALIDATION_ERROR",
            PolicyEngineError::PermissionValidationError(_) => "PERMISSION_VALIDATION_ERROR",
            PolicyEngineError::RoleValidationError(_) => "ROLE_VALIDATION_ERROR",
            PolicyEngineError::ABACConditionError(_) => "ABAC_CONDITION_ERROR",
            PolicyEngineError::ConfigurationError(_) => "CONFIGURATION_ERROR",
            PolicyEngineError::StorageError(_) => "STORAGE_ERROR",
            PolicyEngineError::SerializationError(_) => "SERIALIZATION_ERROR",
            PolicyEngineError::DeserializationError(_) => "DESERIALIZATION_ERROR",
            PolicyEngineError::CryptographicError(_) => "CRYPTOGRAPHIC_ERROR",
            PolicyEngineError::AttestationError(_) => "ATTESTATION_ERROR",
            PolicyEngineError::NetworkError(_) => "NETWORK_ERROR",
            PolicyEngineError::TimeoutError(_) => "TIMEOUT_ERROR",
            PolicyEngineError::RateLimitError(_) => "RATE_LIMIT_ERROR",
            PolicyEngineError::ResourceNotFound(_) => "RESOURCE_NOT_FOUND",
            PolicyEngineError::AccessDenied(_) => "ACCESS_DENIED",
            PolicyEngineError::InternalError(_) => "INTERNAL_ERROR",
            PolicyEngineError::UnsupportedOperation(_) => "UNSUPPORTED_OPERATION",
            PolicyEngineError::InvalidArgument(_) => "INVALID_ARGUMENT",
            PolicyEngineError::StateError(_) => "STATE_ERROR",
            PolicyEngineError::IoError(_) => "IO_ERROR",
            PolicyEngineError::JsonError(_) => "JSON_ERROR",
            PolicyEngineError::Utf8Error(_) => "UTF8_ERROR",
            PolicyEngineError::ParseIntError(_) => "PARSE_INT_ERROR",
            PolicyEngineError::ParseFloatError(_) => "PARSE_FLOAT_ERROR",
        }
    }

    /// Get the HTTP status code for the error
    pub fn http_status_code(&self) -> u16 {
        match self {
            PolicyEngineError::PolicyNotFound(_) => 404,
            PolicyEngineError::NoPoliciesLoaded => 503,
            PolicyEngineError::WasmEngineError(_) => 500,
            PolicyEngineError::WasmValidationError(_) => 400,
            PolicyEngineError::WasmModuleError(_) => 500,
            PolicyEngineError::WasmInstantiationError(_) => 500,
            PolicyEngineError::WasmExecutionError(_) => 500,
            PolicyEngineError::WasmExportError(_) => 500,
            PolicyEngineError::WasmMemoryError(_) => 500,
            PolicyEngineError::PolicyValidationError(_) => 400,
            PolicyEngineError::PrincipalValidationError(_) => 400,
            PolicyEngineError::ScopeValidationError(_) => 400,
            PolicyEngineError::PermissionValidationError(_) => 400,
            PolicyEngineError::RoleValidationError(_) => 400,
            PolicyEngineError::ABACConditionError(_) => 400,
            PolicyEngineError::ConfigurationError(_) => 500,
            PolicyEngineError::StorageError(_) => 500,
            PolicyEngineError::SerializationError(_) => 500,
            PolicyEngineError::DeserializationError(_) => 400,
            PolicyEngineError::CryptographicError(_) => 500,
            PolicyEngineError::AttestationError(_) => 500,
            PolicyEngineError::NetworkError(_) => 503,
            PolicyEngineError::TimeoutError(_) => 408,
            PolicyEngineError::RateLimitError(_) => 429,
            PolicyEngineError::ResourceNotFound(_) => 404,
            PolicyEngineError::AccessDenied(_) => 403,
            PolicyEngineError::InternalError(_) => 500,
            PolicyEngineError::UnsupportedOperation(_) => 501,
            PolicyEngineError::InvalidArgument(_) => 400,
            PolicyEngineError::StateError(_) => 500,
            PolicyEngineError::IoError(_) => 500,
            PolicyEngineError::JsonError(_) => 400,
            PolicyEngineError::Utf8Error(_) => 400,
            PolicyEngineError::ParseIntError(_) => 400,
            PolicyEngineError::ParseFloatError(_) => 400,
        }
    }
}

/// Result type for PolicyEngine operations
pub type PolicyEngineResult<T> = Result<T, PolicyEngineError>;

/// Error context for adding additional information to errors
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub operation: String,
    pub resource: Option<String>,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub timestamp: std::time::SystemTime,
    pub request_id: Option<String>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            resource: None,
            user_id: None,
            tenant_id: None,
            timestamp: std::time::SystemTime::now(),
            request_id: None,
        }
    }

    /// Set the resource
    pub fn with_resource(mut self, resource: &str) -> Self {
        self.resource = Some(resource.to_string());
        self
    }

    /// Set the user ID
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    /// Set the tenant ID
    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    /// Set the request ID
    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_string());
        self
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operation: {}", self.operation)?;
        
        if let Some(ref resource) = self.resource {
            write!(f, ", Resource: {}", resource)?;
        }
        
        if let Some(ref user_id) = self.user_id {
            write!(f, ", User: {}", user_id)?;
        }
        
        if let Some(ref tenant_id) = self.tenant_id {
            write!(f, ", Tenant: {}", tenant_id)?;
        }
        
        if let Some(ref request_id) = self.request_id {
            write!(f, ", Request: {}", request_id)?;
        }
        
        Ok(())
    }
}

/// Error with context
#[derive(Debug)]
pub struct ContextualError {
    pub error: PolicyEngineError,
    pub context: ErrorContext,
}

impl ContextualError {
    /// Create a new contextual error
    pub fn new(error: PolicyEngineError, context: ErrorContext) -> Self {
        Self { error, context }
    }

    /// Get the underlying error
    pub fn error(&self) -> &PolicyEngineError {
        &self.error
    }

    /// Get the context
    pub fn context(&self) -> &ErrorContext {
        &self.context
    }
}

impl fmt::Display for ContextualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (Context: {})", self.error, self.context)
    }
}

impl std::error::Error for ContextualError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Error handling utilities
pub mod utils {
    use super::*;

    /// Add context to a result
    pub fn with_context<T>(
        result: PolicyEngineResult<T>,
        context: ErrorContext,
    ) -> Result<T, ContextualError> {
        result.map_err(|error| ContextualError::new(error, context))
    }

    /// Create a policy not found error
    pub fn policy_not_found(policy_id: &str) -> PolicyEngineError {
        PolicyEngineError::PolicyNotFound(policy_id.to_string())
    }

    /// Create an access denied error
    pub fn access_denied(reason: &str) -> PolicyEngineError {
        PolicyEngineError::AccessDenied(reason.to_string())
    }

    /// Create an invalid argument error
    pub fn invalid_argument(reason: &str) -> PolicyEngineError {
        PolicyEngineError::InvalidArgument(reason.to_string())
    }

    /// Create a validation error
    pub fn validation_error(field: &str, reason: &str) -> PolicyEngineError {
        PolicyEngineError::PolicyValidationError(format!("{}: {}", field, reason))
    }

    /// Create a WASM execution error
    pub fn wasm_execution_error(reason: &str) -> PolicyEngineError {
        PolicyEngineError::WasmExecutionError(reason.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retryable() {
        let network_error = PolicyEngineError::NetworkError("connection failed".to_string());
        assert!(network_error.is_retryable());

        let validation_error = PolicyEngineError::PolicyValidationError("invalid policy".to_string());
        assert!(!validation_error.is_retryable());
    }

    #[test]
    fn test_error_validation() {
        let validation_error = PolicyEngineError::PolicyValidationError("invalid policy".to_string());
        assert!(validation_error.is_validation_error());

        let network_error = PolicyEngineError::NetworkError("connection failed".to_string());
        assert!(!network_error.is_validation_error());
    }

    #[test]
    fn test_error_wasm() {
        let wasm_error = PolicyEngineError::WasmExecutionError("execution failed".to_string());
        assert!(wasm_error.is_wasm_error());

        let network_error = PolicyEngineError::NetworkError("connection failed".to_string());
        assert!(!network_error.is_wasm_error());
    }

    #[test]
    fn test_error_code() {
        let error = PolicyEngineError::PolicyNotFound("test".to_string());
        assert_eq!(error.error_code(), "POLICY_NOT_FOUND");
    }

    #[test]
    fn test_http_status_code() {
        let error = PolicyEngineError::PolicyNotFound("test".to_string());
        assert_eq!(error.http_status_code(), 404);

        let error = PolicyEngineError::AccessDenied("test".to_string());
        assert_eq!(error.http_status_code(), 403);
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("test_operation")
            .with_resource("test_resource")
            .with_user_id("test_user")
            .with_tenant_id("test_tenant")
            .with_request_id("test_request");

        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.resource, Some("test_resource".to_string()));
        assert_eq!(context.user_id, Some("test_user".to_string()));
        assert_eq!(context.tenant_id, Some("test_tenant".to_string()));
        assert_eq!(context.request_id, Some("test_request".to_string()));
    }

    #[test]
    fn test_contextual_error() {
        let context = ErrorContext::new("test_operation");
        let error = PolicyEngineError::PolicyNotFound("test".to_string());
        let contextual_error = ContextualError::new(error, context);

        assert_eq!(contextual_error.error().error_code(), "POLICY_NOT_FOUND");
        assert_eq!(contextual_error.context().operation, "test_operation");
    }
} 