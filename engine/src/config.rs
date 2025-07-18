//! Configuration management for PolicyEngine
//!
//! This module provides configuration management for all PolicyEngine components,
//! including WASM engine settings, storage configuration, and runtime options.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration for PolicyEngine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// WASM engine configuration
    pub wasm: WasmConfig,
    
    /// Storage configuration
    pub storage: StorageConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Performance configuration
    pub performance: PerformanceConfig,
    
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
    
    /// Development configuration
    pub development: DevelopmentConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wasm: WasmConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
            monitoring: MonitoringConfig::default(),
            development: DevelopmentConfig::default(),
        }
    }
}

/// WASM engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmConfig {
    /// Maximum memory size in bytes
    pub max_memory_size: usize,
    
    /// Maximum table size
    pub max_table_size: u32,
    
    /// Maximum number of instances
    pub max_instances: usize,
    
    /// Maximum stack size in bytes
    pub max_stack_size: usize,
    
    /// Enable WASM backtrace
    pub enable_backtrace: bool,
    
    /// Enable WASM multi-value
    pub enable_multi_value: bool,
    
    /// Enable WASM bulk memory
    pub enable_bulk_memory: bool,
    
    /// Enable WASM reference types
    pub enable_reference_types: bool,
    
    /// Enable WASM SIMD
    pub enable_simd: bool,
    
    /// Enable WASM threads
    pub enable_threads: bool,
    
    /// Enable WASM exceptions
    pub enable_exceptions: bool,
    
    /// Enable WASM function references
    pub enable_function_references: bool,
    
    /// Enable WASM garbage collection
    pub enable_gc: bool,
    
    /// Enable WASM component model
    pub enable_component_model: bool,
    
    /// Enable WASM memory64
    pub enable_memory64: bool,
    
    /// Enable WASM relaxed SIMD
    pub enable_relaxed_simd: bool,
    
    /// Enable WASM extended const
    pub enable_extended_const: bool,
    
    /// Enable WASM memory control
    pub enable_memory_control: bool,
    
    /// Enable WASM stringref
    pub enable_stringref: bool,
    
    /// Enable WASM tail call
    pub enable_tail_call: bool,
    
    /// Enable WASM proposals
    pub enable_proposals: bool,
    
    /// WASM module cache size
    pub module_cache_size: usize,
    
    /// WASM instance cache size
    pub instance_cache_size: usize,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            max_memory_size: 64 * 1024 * 1024, // 64MB
            max_table_size: 10000,
            max_instances: 1000,
            max_stack_size: 1024 * 1024, // 1MB
            enable_backtrace: true,
            enable_multi_value: true,
            enable_bulk_memory: true,
            enable_reference_types: true,
            enable_simd: true,
            enable_threads: false, // Disabled for security
            enable_exceptions: false, // Disabled for security
            enable_function_references: false, // Disabled for security
            enable_gc: false, // Disabled for security
            enable_component_model: false, // Disabled for security
            enable_memory64: false, // Disabled for security
            enable_relaxed_simd: false, // Disabled for security
            enable_extended_const: false, // Disabled for security
            enable_memory_control: false, // Disabled for security
            enable_stringref: false, // Disabled for security
            enable_tail_call: false, // Disabled for security
            enable_proposals: false, // Disabled for security
            module_cache_size: 100,
            instance_cache_size: 50,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage type
    pub storage_type: StorageType,
    
    /// File system path for local storage
    pub file_path: Option<PathBuf>,
    
    /// Database connection string
    pub database_url: Option<String>,
    
    /// Redis connection string
    pub redis_url: Option<String>,
    
    /// S3 configuration
    pub s3: Option<S3Config>,
    
    /// Azure Blob configuration
    pub azure_blob: Option<AzureBlobConfig>,
    
    /// Google Cloud Storage configuration
    pub gcs: Option<GCSConfig>,
    
    /// Encryption key for stored data
    pub encryption_key: Option<String>,
    
    /// Enable compression
    pub enable_compression: bool,
    
    /// Enable encryption
    pub enable_encryption: bool,
    
    /// Backup configuration
    pub backup: BackupConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::File,
            file_path: Some(PathBuf::from("./data")),
            database_url: None,
            redis_url: None,
            s3: None,
            azure_blob: None,
            gcs: None,
            encryption_key: None,
            enable_compression: true,
            enable_encryption: false,
            backup: BackupConfig::default(),
        }
    }
}

/// Storage types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    File,
    Database,
    Redis,
    S3,
    AzureBlob,
    GCS,
    Memory,
}

/// S3 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub endpoint: Option<String>,
    pub use_path_style: bool,
}

/// Azure Blob configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureBlobConfig {
    pub account_name: String,
    pub account_key: String,
    pub container_name: String,
    pub endpoint: Option<String>,
}

/// Google Cloud Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCSConfig {
    pub bucket: String,
    pub project_id: String,
    pub credentials_file: Option<PathBuf>,
    pub service_account_key: Option<String>,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub retention_days: u32,
    pub backup_path: Option<PathBuf>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: Duration::from_secs(24 * 60 * 60), // 24 hours
            retention_days: 7,
            backup_path: None,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    
    /// Log format
    pub format: LogFormat,
    
    /// Log file path
    pub file_path: Option<PathBuf>,
    
    /// Enable console logging
    pub enable_console: bool,
    
    /// Enable structured logging
    pub enable_structured: bool,
    
    /// Enable request logging
    pub enable_request_logging: bool,
    
    /// Enable performance logging
    pub enable_performance_logging: bool,
    
    /// Log rotation configuration
    pub rotation: LogRotationConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            file_path: None,
            enable_console: true,
            enable_structured: true,
            enable_request_logging: true,
            enable_performance_logging: false,
            rotation: LogRotationConfig::default(),
        }
    }
}

/// Log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Log formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Text,
    Json,
    Compact,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    pub enabled: bool,
    pub max_size_mb: u64,
    pub max_files: u32,
    pub compress: bool,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_mb: 100,
            max_files: 5,
            compress: true,
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// HTTP server configuration
    pub http: HttpConfig,
    
    /// gRPC server configuration
    pub grpc: GrpcConfig,
    
    /// NATS configuration
    pub nats: NatsConfig,
    
    /// CORS configuration
    pub cors: CorsConfig,
    
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            http: HttpConfig::default(),
            grpc: GrpcConfig::default(),
            nats: NatsConfig::default(),
            cors: CorsConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
        }
    }
}

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub keep_alive_timeout: Duration,
    pub enable_tls: bool,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: num_cpus::get(),
            max_connections: 10000,
            request_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(5),
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// gRPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    pub host: String,
    pub port: u16,
    pub max_concurrent_streams: usize,
    pub max_connection_idle: Duration,
    pub max_connection_age: Duration,
    pub enable_reflection: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 9090,
            max_concurrent_streams: 1000,
            max_connection_idle: Duration::from_secs(300),
            max_connection_age: Duration::from_secs(3600),
            enable_reflection: true,
        }
    }
}

/// NATS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    pub url: String,
    pub cluster_id: Option<String>,
    pub client_id: String,
    pub max_reconnect_attempts: usize,
    pub reconnect_timeout: Duration,
    pub ping_interval: Duration,
    pub max_outstanding_pings: usize,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://127.0.0.1:4222".to_string(),
            cluster_id: None,
            client_id: "policyengine".to_string(),
            max_reconnect_attempts: 10,
            reconnect_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(30),
            max_outstanding_pings: 5,
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Duration,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
            allowed_headers: vec!["*".to_string()],
            allow_credentials: true,
            max_age: Duration::from_secs(3600),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub window_size: Duration,
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 1000,
            burst_size: 100,
            window_size: Duration::from_secs(1),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Authentication configuration
    pub authentication: AuthenticationConfig,
    
    /// Authorization configuration
    pub authorization: AuthorizationConfig,
    
    /// TLS configuration
    pub tls: TlsConfig,
    
    /// JWT configuration
    pub jwt: JwtConfig,
    
    /// OAuth2 configuration
    pub oauth2: OAuth2Config,
    
    /// Rate limiting configuration
    pub rate_limiting: SecurityRateLimitingConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            authentication: AuthenticationConfig::default(),
            authorization: AuthorizationConfig::default(),
            tls: TlsConfig::default(),
            jwt: JwtConfig::default(),
            oauth2: OAuth2Config::default(),
            rate_limiting: SecurityRateLimitingConfig::default(),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    pub enabled: bool,
    pub methods: Vec<AuthMethod>,
    pub session_timeout: Duration,
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            methods: vec![AuthMethod::Jwt, AuthMethod::OAuth2],
            session_timeout: Duration::from_secs(3600),
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(300),
        }
    }
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    Jwt,
    OAuth2,
    ApiKey,
    Basic,
    Certificate,
}

/// Authorization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationConfig {
    pub enabled: bool,
    pub default_policy: String,
    pub cache_size: usize,
    pub cache_ttl: Duration,
}

impl Default for AuthorizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_policy: "deny".to_string(),
            cache_size: 10000,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
    pub min_version: TlsVersion,
    pub cipher_suites: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            ca_path: None,
            min_version: TlsVersion::Tls12,
            cipher_suites: vec![],
        }
    }
}

/// TLS versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub algorithm: JwtAlgorithm,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub expiration: Duration,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key".to_string(),
            algorithm: JwtAlgorithm::HS256,
            issuer: None,
            audience: None,
            expiration: Duration::from_secs(3600),
        }
    }
}

/// JWT algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

/// OAuth2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub enabled: bool,
    pub providers: HashMap<String, OAuth2Provider>,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: HashMap::new(),
        }
    }
}

/// OAuth2 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Provider {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub scopes: Vec<String>,
}

/// Security rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRateLimitingConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub window_size: Duration,
}

impl Default for SecurityRateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            burst_size: 10,
            window_size: Duration::from_secs(60),
        }
    }
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Thread pool configuration
    pub thread_pool: ThreadPoolConfig,
    
    /// Cache configuration
    pub cache: CacheConfig,
    
    /// Connection pool configuration
    pub connection_pool: ConnectionPoolConfig,
    
    /// Batch processing configuration
    pub batch: BatchConfig,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            thread_pool: ThreadPoolConfig::default(),
            cache: CacheConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            batch: BatchConfig::default(),
        }
    }
}

/// Thread pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPoolConfig {
    pub min_threads: usize,
    pub max_threads: usize,
    pub keep_alive: Duration,
    pub queue_size: usize,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        Self {
            min_threads: 4,
            max_threads: num_cpus::get() * 2,
            keep_alive: Duration::from_secs(60),
            queue_size: 1000,
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_size: usize,
    pub ttl: Duration,
    pub eviction_policy: EvictionPolicy,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 10000,
            ttl: Duration::from_secs(300),
            eviction_policy: EvictionPolicy::LRU,
        }
    }
}

/// Cache eviction policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvictionPolicy {
    LRU,
    LFU,
    FIFO,
    Random,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    pub min_connections: usize,
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 5,
            max_connections: 20,
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

/// Batch processing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    pub enabled: bool,
    pub batch_size: usize,
    pub batch_timeout: Duration,
    pub max_concurrent_batches: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size: 100,
            batch_timeout: Duration::from_secs(1),
            max_concurrent_batches: 10,
        }
    }
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Metrics configuration
    pub metrics: MetricsConfig,
    
    /// Health check configuration
    pub health_check: HealthCheckConfig,
    
    /// Tracing configuration
    pub tracing: TracingConfig,
    
    /// Alerting configuration
    pub alerting: AlertingConfig,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics: MetricsConfig::default(),
            health_check: HealthCheckConfig::default(),
            tracing: TracingConfig::default(),
            alerting: AlertingConfig::default(),
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub port: u16,
    pub path: String,
    pub interval: Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "127.0.0.1".to_string(),
            port: 9091,
            path: "/metrics".to_string(),
            interval: Duration::from_secs(15),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub port: u16,
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "127.0.0.1".to_string(),
            port: 8081,
            path: "/health".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub port: u16,
    pub service_name: String,
    pub sampling_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "127.0.0.1".to_string(),
            port: 6831,
            service_name: "policyengine".to_string(),
            sampling_rate: 0.1,
        }
    }
}

/// Alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub enabled: bool,
    pub webhook_url: Option<String>,
    pub email: Option<EmailConfig>,
    pub slack: Option<SlackConfig>,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: None,
            email: None,
            slack: None,
        }
    }
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
}

/// Slack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
}

/// Development configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevelopmentConfig {
    pub debug_mode: bool,
    pub hot_reload: bool,
    pub mock_mode: bool,
    pub test_mode: bool,
    pub profile_mode: bool,
}

impl Default for DevelopmentConfig {
    fn default() -> Self {
        Self {
            debug_mode: false,
            hot_reload: false,
            mock_mode: false,
            test_mode: false,
            profile_mode: false,
        }
    }
}

/// Configuration loader
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from file
    pub fn from_file(path: &PathBuf) -> Result<Config, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Config, Box<dyn std::error::Error>> {
        let mut config = Config::default();
        
        // Load from environment variables
        if let Ok(level) = std::env::var("POLICYENGINE_LOG_LEVEL") {
            config.logging.level = match level.to_lowercase().as_str() {
                "trace" => LogLevel::Trace,
                "debug" => LogLevel::Debug,
                "info" => LogLevel::Info,
                "warn" => LogLevel::Warn,
                "error" => LogLevel::Error,
                _ => LogLevel::Info,
            };
        }
        
        if let Ok(port) = std::env::var("POLICYENGINE_HTTP_PORT") {
            if let Ok(port) = port.parse() {
                config.network.http.port = port;
            }
        }
        
        if let Ok(host) = std::env::var("POLICYENGINE_HTTP_HOST") {
            config.network.http.host = host;
        }
        
        Ok(config)
    }

    /// Load configuration from multiple sources
    pub fn load() -> Result<Config, Box<dyn std::error::Error>> {
        // Try to load from file first
        let config_paths = vec![
            PathBuf::from("config.yaml"),
            PathBuf::from("config.yml"),
            PathBuf::from("/etc/policyengine/config.yaml"),
        ];
        
        for path in config_paths {
            if path.exists() {
                return Self::from_file(&path);
            }
        }
        
        // Fall back to environment variables
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.network.http.port, 8080);
        assert_eq!(config.network.grpc.port, 9090);
        assert!(config.logging.enable_console);
    }

    #[test]
    fn test_wasm_config_default() {
        let config = WasmConfig::default();
        assert_eq!(config.max_memory_size, 64 * 1024 * 1024);
        assert!(!config.enable_threads); // Should be disabled for security
    }

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert!(matches!(config.storage_type, StorageType::File));
        assert!(config.enable_compression);
        assert!(!config.enable_encryption);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        
        assert_eq!(config.network.http.port, deserialized.network.http.port);
        assert_eq!(config.network.grpc.port, deserialized.network.grpc.port);
    }
} 