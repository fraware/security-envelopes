//! Cryptographic operations for PolicyEngine
//!
//! This module provides cryptographic primitives for policy integrity,
//! artifact verification, and sensitive data protection.

use ring::{
    aead::{self, BoundKey, Nonce, UnboundKey},
    digest::{self, Digest},
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use sha2::{Sha256, Digest as Sha2Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::PolicyEngineError;

/// Cryptographic key types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    ECDSA_P256,
    ECDSA_P384,
    AES256,
}

/// Cryptographic key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // In practice, this would be encrypted
}

/// Digital signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Hash digest
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest {
    pub algorithm: String,
    pub hash: Vec<u8>,
}

/// Encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub algorithm: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Cryptographic operations
pub struct Crypto;

impl Crypto {
    /// Generate a new Ed25519 key pair
    pub fn generate_ed25519_keypair() -> Result<KeyPair, PolicyEngineError> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        Ok(KeyPair {
            key_type: KeyType::Ed25519,
            public_key: key_pair.public_key().as_ref().to_vec(),
            private_key: pkcs8_bytes.as_ref().to_vec(),
        })
    }

    /// Sign data with Ed25519
    pub fn sign_ed25519(key_pair: &KeyPair, data: &[u8]) -> Result<Signature, PolicyEngineError> {
        if key_pair.key_type != KeyType::Ed25519 {
            return Err(PolicyEngineError::CryptographicError(
                "Key type is not Ed25519".to_string()
            ));
        }

        let key_pair = Ed25519KeyPair::from_pkcs8(&key_pair.private_key)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        let signature = key_pair.sign(data);
        
        Ok(Signature {
            algorithm: "Ed25519".to_string(),
            signature: signature.as_ref().to_vec(),
            public_key: key_pair.public_key().as_ref().to_vec(),
        })
    }

    /// Verify Ed25519 signature
    pub fn verify_ed25519(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, PolicyEngineError> {
        let public_key = UnparsedPublicKey::new(
            &signature::ED25519,
            public_key
        );
        
        match public_key.verify(data, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Compute SHA-256 hash
    pub fn sha256(data: &[u8]) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        
        Digest {
            algorithm: "SHA-256".to_string(),
            hash: result.to_vec(),
        }
    }

    /// Compute SHA-256 hash of multiple data chunks
    pub fn sha256_multiple(chunks: &[&[u8]]) -> Digest {
        let mut hasher = Sha256::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        let result = hasher.finalize();
        
        Digest {
            algorithm: "SHA-256".to_string(),
            hash: result.to_vec(),
        }
    }

    /// Encrypt data with AES-256-GCM
    pub fn encrypt_aes256_gcm(key: &[u8], data: &[u8], associated_data: &[u8]) -> Result<EncryptedData, PolicyEngineError> {
        if key.len() != 32 {
            return Err(PolicyEngineError::CryptographicError(
                "AES-256 key must be 32 bytes".to_string()
            ));
        }

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        let nonce_bytes = SystemRandom::new().fill(&mut [0u8; 12])
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce);
        let mut ciphertext = data.to_vec();
        sealing_key.seal_in_place_append_tag(aead::Aad::from(associated_data), &mut ciphertext)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        Ok(EncryptedData {
            algorithm: "AES-256-GCM".to_string(),
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            tag: Vec::new(), // Tag is appended to ciphertext in GCM mode
        })
    }

    /// Decrypt data with AES-256-GCM
    pub fn decrypt_aes256_gcm(key: &[u8], encrypted_data: &EncryptedData, associated_data: &[u8]) -> Result<Vec<u8>, PolicyEngineError> {
        if key.len() != 32 {
            return Err(PolicyEngineError::CryptographicError(
                "AES-256 key must be 32 bytes".to_string()
            ));
        }

        if encrypted_data.nonce.len() != 12 {
            return Err(PolicyEngineError::CryptographicError(
                "Nonce must be 12 bytes".to_string()
            ));
        }

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        let nonce = Nonce::assume_unique_for_key(encrypted_data.nonce.try_into().unwrap());
        let mut opening_key = aead::OpeningKey::new(unbound_key, nonce);
        
        let mut plaintext = encrypted_data.ciphertext.clone();
        opening_key.open_in_place(aead::Aad::from(associated_data), &mut plaintext)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        Ok(plaintext)
    }

    /// Generate random bytes
    pub fn random_bytes(length: usize) -> Result<Vec<u8>, PolicyEngineError> {
        let mut bytes = vec![0u8; length];
        SystemRandom::new().fill(&mut bytes)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        Ok(bytes)
    }

    /// Generate a secure nonce
    pub fn generate_nonce() -> Result<Vec<u8>, PolicyEngineError> {
        Self::random_bytes(32)
    }

    /// Compute HMAC-SHA256
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Digest, PolicyEngineError> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let signature = ring::hmac::sign(&key, data);
        
        Ok(Digest {
            algorithm: "HMAC-SHA256".to_string(),
            hash: signature.as_ref().to_vec(),
        })
    }

    /// Verify HMAC-SHA256
    pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected_hmac: &[u8]) -> Result<bool, PolicyEngineError> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        ring::hmac::verify(&key, data, expected_hmac)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        Ok(true)
    }

    /// Derive key using HKDF
    pub fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, PolicyEngineError> {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(secret);
        let okm = prk.expand(info, ring::hkdf::HKDF_SHA256)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        let mut key = vec![0u8; length];
        okm.fill(&mut key)
            .map_err(|e| PolicyEngineError::CryptographicError(e.to_string()))?;
        
        Ok(key)
    }

    /// Constant-time comparison
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        ring::constant_time::verify_slices_are_equal(a, b).is_ok()
    }
}

/// Key management
pub struct KeyManager {
    keys: HashMap<String, KeyPair>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Generate and store a new key
    pub fn generate_key(&mut self, name: &str, key_type: KeyType) -> Result<(), PolicyEngineError> {
        let key_pair = match key_type {
            KeyType::Ed25519 => Crypto::generate_ed25519_keypair()?,
            _ => return Err(PolicyEngineError::CryptographicError(
                "Unsupported key type".to_string()
            )),
        };
        
        self.keys.insert(name.to_string(), key_pair);
        Ok(())
    }

    /// Get a key by name
    pub fn get_key(&self, name: &str) -> Option<&KeyPair> {
        self.keys.get(name)
    }

    /// Sign data with a named key
    pub fn sign(&self, key_name: &str, data: &[u8]) -> Result<Signature, PolicyEngineError> {
        let key = self.get_key(key_name)
            .ok_or_else(|| PolicyEngineError::CryptographicError(
                format!("Key '{}' not found", key_name)
            ))?;
        
        Crypto::sign_ed25519(key, data)
    }

    /// Remove a key
    pub fn remove_key(&mut self, name: &str) -> Option<KeyPair> {
        self.keys.remove(name)
    }

    /// List all key names
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_generation() {
        let key_pair = Crypto::generate_ed25519_keypair().unwrap();
        assert_eq!(key_pair.key_type, KeyType::Ed25519);
        assert_eq!(key_pair.public_key.len(), 32);
        assert!(!key_pair.private_key.is_empty());
    }

    #[test]
    fn test_ed25519_signature() {
        let key_pair = Crypto::generate_ed25519_keypair().unwrap();
        let data = b"Hello, World!";
        
        let signature = Crypto::sign_ed25519(&key_pair, data).unwrap();
        assert_eq!(signature.algorithm, "Ed25519");
        assert_eq!(signature.signature.len(), 64);
        
        let is_valid = Crypto::verify_ed25519(&key_pair.public_key, data, &signature.signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"Hello, World!";
        let digest = Crypto::sha256(data);
        
        assert_eq!(digest.algorithm, "SHA-256");
        assert_eq!(digest.hash.len(), 32);
    }

    #[test]
    fn test_aes256_gcm_encryption() {
        let key = Crypto::random_bytes(32).unwrap();
        let data = b"Secret message";
        let associated_data = b"Additional data";
        
        let encrypted = Crypto::encrypt_aes256_gcm(&key, data, associated_data).unwrap();
        assert_eq!(encrypted.algorithm, "AES-256-GCM");
        assert_eq!(encrypted.nonce.len(), 12);
        
        let decrypted = Crypto::decrypt_aes256_gcm(&key, &encrypted, associated_data).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_key_manager() {
        let mut manager = KeyManager::new();
        
        manager.generate_key("test-key", KeyType::Ed25519).unwrap();
        assert!(manager.get_key("test-key").is_some());
        
        let data = b"Test data";
        let signature = manager.sign("test-key", data).unwrap();
        assert_eq!(signature.algorithm, "Ed25519");
        
        let keys = manager.list_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "test-key");
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret-key";
        let data = b"message";
        
        let hmac = Crypto::hmac_sha256(key, data).unwrap();
        assert_eq!(hmac.algorithm, "HMAC-SHA256");
        
        let is_valid = Crypto::verify_hmac_sha256(key, data, &hmac.hash).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_hkdf() {
        let secret = b"secret";
        let salt = b"salt";
        let info = b"info";
        
        let derived_key = Crypto::hkdf_sha256(secret, salt, info, 32).unwrap();
        assert_eq!(derived_key.len(), 32);
    }
} 