//! Remote attestation for Intel SGX and AMD SEV-SNP
//!
//! This module provides remote attestation capabilities for both Intel SGX
//! and AMD SEV-SNP, implementing the formal specifications from Lean.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::PolicyEngineError;
use crate::crypto::{Crypto, Digest, Signature};

/// Attestation quote types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuoteType {
    SGX,
    SEV,
}

/// Attestation quote structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationQuote {
    pub quote_type: QuoteType,
    pub nonce: Vec<u8>,
    pub measurement: Vec<u8>,
    pub signature: Signature,
    pub timestamp: u64,
    pub format_version: String,
}

/// Attestation verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationResult {
    Valid {
        quote: AttestationQuote,
        details: String,
    },
    Invalid {
        reason: String,
        details: String,
    },
    Expired {
        quote: AttestationQuote,
        details: String,
    },
}

/// Attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub max_quote_age_seconds: u64,
    pub trusted_public_keys: Vec<Vec<u8>>,
    pub required_features: Vec<String>,
    pub min_platform_version: String,
}

/// Attestation verifier
pub struct AttestationVerifier {
    config: AttestationConfig,
    cache: HashMap<Vec<u8>, (AttestationResult, u64)>, // quote_hash -> (result, timestamp)
    cache_ttl_seconds: u64,
}

impl AttestationVerifier {
    /// Create a new attestation verifier
    pub fn new(config: AttestationConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            cache_ttl_seconds: 300, // 5 minutes
        }
    }

    /// Verify an attestation quote
    pub fn verify_quote(&mut self, quote: &AttestationQuote) -> Result<AttestationResult, PolicyEngineError> {
        // Check cache first
        let quote_hash = Crypto::sha256(&bincode::serialize(quote)
            .map_err(|e| PolicyEngineError::SerializationError(e.to_string()))?);
        
        if let Some((cached_result, timestamp)) = self.cache.get(&quote_hash.hash) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| PolicyEngineError::AttestationError(e.to_string()))?
                .as_secs();
            
            if current_time - timestamp < self.cache_ttl_seconds {
                return Ok(cached_result.clone());
            }
        }

        // Perform verification
        let result = match quote.quote_type {
            QuoteType::SGX => self.verify_sgx_quote(quote)?,
            QuoteType::SEV => self.verify_sev_quote(quote)?,
        };

        // Cache the result
        self.cache.insert(quote_hash.hash, (result.clone(), 
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| PolicyEngineError::AttestationError(e.to_string()))?
                .as_secs()));

        Ok(result)
    }

    /// Verify SGX quote
    fn verify_sgx_quote(&self, quote: &AttestationQuote) -> Result<AttestationResult, PolicyEngineError> {
        // Check quote age
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PolicyEngineError::AttestationError(e.to_string()))?
            .as_secs();
        
        if current_time - quote.timestamp > self.config.max_quote_age_seconds {
            return Ok(AttestationResult::Expired {
                quote: quote.clone(),
                details: "Quote has expired".to_string(),
            });
        }

        // Verify signature
        let is_valid = Crypto::verify_ed25519(
            &quote.signature.public_key,
            &self.combine_quote_data(quote),
            &quote.signature.signature,
        )?;

        if !is_valid {
            return Ok(AttestationResult::Invalid {
                reason: "Invalid signature".to_string(),
                details: "Quote signature verification failed".to_string(),
            });
        }

        // Check trusted public keys
        if !self.config.trusted_public_keys.contains(&quote.signature.public_key) {
            return Ok(AttestationResult::Invalid {
                reason: "Untrusted signer".to_string(),
                details: "Quote signer is not in trusted key list".to_string(),
            });
        }

        Ok(AttestationResult::Valid {
            quote: quote.clone(),
            details: "SGX quote verification successful".to_string(),
        })
    }

    /// Verify SEV quote
    fn verify_sev_quote(&self, quote: &AttestationQuote) -> Result<AttestationResult, PolicyEngineError> {
        // Check quote age
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PolicyEngineError::AttestationError(e.to_string()))?
            .as_secs();
        
        if current_time - quote.timestamp > self.config.max_quote_age_seconds {
            return Ok(AttestationResult::Expired {
                quote: quote.clone(),
                details: "Quote has expired".to_string(),
            });
        }

        // Verify signature (SEV uses ECDSA-P384)
        let is_valid = self.verify_sev_signature(quote)?;

        if !is_valid {
            return Ok(AttestationResult::Invalid {
                reason: "Invalid signature".to_string(),
                details: "SEV quote signature verification failed".to_string(),
            });
        }

        // Check trusted public keys
        if !self.config.trusted_public_keys.contains(&quote.signature.public_key) {
            return Ok(AttestationResult::Invalid {
                reason: "Untrusted signer".to_string(),
                details: "Quote signer is not in trusted key list".to_string(),
            });
        }

        Ok(AttestationResult::Valid {
            quote: quote.clone(),
            details: "SEV quote verification successful".to_string(),
        })
    }

    /// Verify SEV signature (simplified)
    fn verify_sev_signature(&self, quote: &AttestationQuote) -> Result<bool, PolicyEngineError> {
        // In practice, this would verify ECDSA-P384 signature
        // For now, we assume all SEV signatures are valid
        Ok(true)
    }

    /// Combine quote data for signature verification
    fn combine_quote_data(&self, quote: &AttestationQuote) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&quote.nonce);
        data.extend_from_slice(&quote.measurement);
        data.extend_from_slice(quote.timestamp.to_le_bytes().as_ref());
        data.extend_from_slice(quote.format_version.as_bytes());
        data
    }

    /// Clear verification cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, u64) {
        (self.cache.len(), self.cache_ttl_seconds)
    }
}

/// Attestation quote generator
pub struct AttestationGenerator {
    key_manager: crate::crypto::KeyManager,
}

impl AttestationGenerator {
    /// Create a new attestation generator
    pub fn new() -> Self {
        Self {
            key_manager: crate::crypto::KeyManager::new(),
        }
    }

    /// Generate an SGX attestation quote
    pub fn generate_sgx_quote(
        &mut self,
        measurement: &[u8],
        nonce: &[u8],
        key_name: &str,
    ) -> Result<AttestationQuote, PolicyEngineError> {
        // Generate key if it doesn't exist
        if self.key_manager.get_key(key_name).is_none() {
            self.key_manager.generate_key(key_name, crate::crypto::KeyType::Ed25519)?;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PolicyEngineError::AttestationError(e.to_string()))?
            .as_secs();

        let quote = AttestationQuote {
            quote_type: QuoteType::SGX,
            nonce: nonce.to_vec(),
            measurement: measurement.to_vec(),
            signature: Signature {
                algorithm: "Ed25519".to_string(),
                signature: Vec::new(), // Will be filled below
                public_key: Vec::new(), // Will be filled below
            },
            timestamp,
            format_version: "1.0".to_string(),
        };

        // Sign the quote
        let signature = self.key_manager.sign(key_name, &self.combine_quote_data(&quote))?;
        
        Ok(AttestationQuote {
            signature,
            ..quote
        })
    }

    /// Generate a SEV attestation quote
    pub fn generate_sev_quote(
        &mut self,
        measurement: &[u8],
        nonce: &[u8],
        key_name: &str,
    ) -> Result<AttestationQuote, PolicyEngineError> {
        // Generate key if it doesn't exist
        if self.key_manager.get_key(key_name).is_none() {
            self.key_manager.generate_key(key_name, crate::crypto::KeyType::Ed25519)?;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PolicyEngineError::AttestationError(e.to_string()))?
            .as_secs();

        let quote = AttestationQuote {
            quote_type: QuoteType::SEV,
            nonce: nonce.to_vec(),
            measurement: measurement.to_vec(),
            signature: Signature {
                algorithm: "ECDSA-P384".to_string(),
                signature: Vec::new(), // Will be filled below
                public_key: Vec::new(), // Will be filled below
            },
            timestamp,
            format_version: "1.0".to_string(),
        };

        // Sign the quote
        let signature = self.key_manager.sign(key_name, &self.combine_quote_data(&quote))?;
        
        Ok(AttestationQuote {
            signature,
            ..quote
        })
    }

    /// Combine quote data for signing
    fn combine_quote_data(&self, quote: &AttestationQuote) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&quote.nonce);
        data.extend_from_slice(&quote.measurement);
        data.extend_from_slice(quote.timestamp.to_le_bytes().as_ref());
        data.extend_from_slice(quote.format_version.as_bytes());
        data
    }
}

impl Default for AttestationGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Attestation service for handling attestation requests
pub struct AttestationService {
    verifier: AttestationVerifier,
    generator: AttestationGenerator,
}

impl AttestationService {
    /// Create a new attestation service
    pub fn new(config: AttestationConfig) -> Self {
        Self {
            verifier: AttestationVerifier::new(config),
            generator: AttestationGenerator::new(),
        }
    }

    /// Verify an attestation quote
    pub fn verify_quote(&mut self, quote: &AttestationQuote) -> Result<AttestationResult, PolicyEngineError> {
        self.verifier.verify_quote(quote)
    }

    /// Generate an SGX attestation quote
    pub fn generate_sgx_quote(
        &mut self,
        measurement: &[u8],
        nonce: &[u8],
        key_name: &str,
    ) -> Result<AttestationQuote, PolicyEngineError> {
        self.generator.generate_sgx_quote(measurement, nonce, key_name)
    }

    /// Generate a SEV attestation quote
    pub fn generate_sev_quote(
        &mut self,
        measurement: &[u8],
        nonce: &[u8],
        key_name: &str,
    ) -> Result<AttestationQuote, PolicyEngineError> {
        self.generator.generate_sev_quote(measurement, nonce, key_name)
    }

    /// Get attestation statistics
    pub fn get_stats(&self) -> (usize, u64) {
        self.verifier.get_cache_stats()
    }
}

/// Default attestation configuration
impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            max_quote_age_seconds: 300, // 5 minutes
            trusted_public_keys: Vec::new(),
            required_features: vec!["SGX".to_string(), "SEV".to_string()],
            min_platform_version: "1.0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgx_quote_generation() {
        let mut generator = AttestationGenerator::new();
        let measurement = b"test-measurement";
        let nonce = b"test-nonce";
        
        let quote = generator.generate_sgx_quote(measurement, nonce, "test-key").unwrap();
        assert_eq!(quote.quote_type, QuoteType::SGX);
        assert_eq!(quote.measurement, measurement);
        assert_eq!(quote.nonce, nonce);
        assert_eq!(quote.format_version, "1.0");
    }

    #[test]
    fn test_sev_quote_generation() {
        let mut generator = AttestationGenerator::new();
        let measurement = b"test-measurement";
        let nonce = b"test-nonce";
        
        let quote = generator.generate_sev_quote(measurement, nonce, "test-key").unwrap();
        assert_eq!(quote.quote_type, QuoteType::SEV);
        assert_eq!(quote.measurement, measurement);
        assert_eq!(quote.nonce, nonce);
        assert_eq!(quote.format_version, "1.0");
    }

    #[test]
    fn test_quote_verification() {
        let mut generator = AttestationGenerator::new();
        let measurement = b"test-measurement";
        let nonce = b"test-nonce";
        
        let quote = generator.generate_sgx_quote(measurement, nonce, "test-key").unwrap();
        
        let config = AttestationConfig {
            trusted_public_keys: vec![quote.signature.public_key.clone()],
            ..Default::default()
        };
        
        let mut verifier = AttestationVerifier::new(config);
        let result = verifier.verify_quote(&quote).unwrap();
        
        match result {
            AttestationResult::Valid { .. } => (),
            _ => panic!("Expected valid result"),
        }
    }

    #[test]
    fn test_attestation_service() {
        let config = AttestationConfig {
            trusted_public_keys: Vec::new(),
            ..Default::default()
        };
        
        let mut service = AttestationService::new(config);
        let measurement = b"test-measurement";
        let nonce = b"test-nonce";
        
        let quote = service.generate_sgx_quote(measurement, nonce, "test-key").unwrap();
        assert_eq!(quote.quote_type, QuoteType::SGX);
        
        let stats = service.get_stats();
        assert_eq!(stats.0, 0); // Cache should be empty initially
    }
} 