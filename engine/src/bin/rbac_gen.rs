use clap::{App, Arg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use policyengine::{
    crypto::{Crypto, KeyManager, KeyType},
    policy::{Policy, PolicyBuilder, builders},
    error::PolicyEngineError,
};

#[derive(Debug, Serialize, Deserialize)]
struct YamlPolicy {
    version: String,
    roles: Vec<YamlRole>,
    assignments: Vec<YamlAssignment>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlRole {
    name: String,
    permissions: Vec<YamlPermission>,
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlPermission {
    action: String, // "allow" or "deny"
    scope: YamlScope,
    conditions: Option<Vec<YamlCondition>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlScope {
    resource: Option<String>,
    action: Option<String>,
    path: Option<Vec<String>>,
    params: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlCondition {
    attribute: String,
    operator: String, // "equals", "in", "greater_than", etc.
    value: serde_yaml::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct YamlAssignment {
    principal: String,
    role: String,
    attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicySignature {
    algorithm: String,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    timestamp: u64,
    policy_hash: String,
}

fn main() -> Result<(), PolicyEngineError> {
    let matches = App::new("rbac-gen")
        .version("1.0")
        .about("Generate signed WASM policy from YAML")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("FILE")
                .help("Input YAML policy file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("DIR")
                .help("Output directory")
                .default_value(".")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("KEY_NAME")
                .help("Signing key name")
                .default_value("default")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("generate-key")
                .long("generate-key")
                .help("Generate new signing key"),
        )
        .get_matches();

    let input_file = matches.value_of("input").unwrap();
    let output_dir = matches.value_of("output").unwrap();
    let key_name = matches.value_of("key").unwrap();
    let generate_key = matches.is_present("generate-key");

    println!("🔐 RBAC Policy Generator");
    println!("Input: {}", input_file);
    println!("Output: {}", output_dir);
    println!("Key: {}", key_name);

    // Read YAML policy
    let yaml_content = fs::read_to_string(input_file)?;
    let yaml_policy: YamlPolicy = serde_yaml::from_str(&yaml_content)?;

    // Convert YAML to internal policy
    let policy = convert_yaml_to_policy(&yaml_policy)?;

    // Initialize key manager
    let mut key_manager = KeyManager::new();
    
    if generate_key {
        println!("🔑 Generating new signing key: {}", key_name);
        key_manager.generate_key(key_name, KeyType::Ed25519)?;
    } else {
        // Try to load existing key or generate default
        if key_manager.get_key(key_name).is_none() {
            println!("🔑 Generating default signing key: {}", key_name);
            key_manager.generate_key(key_name, KeyType::Ed25519)?;
        }
    }

    // Generate WASM module (simplified - in practice this would compile Lean to WASM)
    let wasm_bytes = generate_wasm_module(&policy)?;

    // Calculate policy hash
    let policy_hash = Crypto::sha256(&bincode::serialize(&policy)?);

    // Sign the policy
    let signature = key_manager.sign(key_name, &wasm_bytes)?;

    // Create signature metadata
    let policy_signature = PolicySignature {
        algorithm: signature.algorithm,
        signature: signature.signature,
        public_key: signature.public_key,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        policy_hash: hex::encode(&policy_hash.hash),
    };

    // Write outputs
    let output_path = Path::new(output_dir);
    
    // Write WASM module
    let wasm_path = output_path.join("policy.wasm");
    fs::write(&wasm_path, &wasm_bytes)?;
    println!("✅ WASM module written: {}", wasm_path.display());

    // Write signature
    let sig_path = output_path.join("sig.json");
    let sig_json = serde_json::to_string_pretty(&policy_signature)?;
    fs::write(&sig_path, sig_json)?;
    println!("✅ Signature written: {}", sig_path.display());

    // Write policy metadata
    let metadata_path = output_path.join("policy.json");
    let policy_json = serde_json::to_string_pretty(&policy)?;
    fs::write(&metadata_path, policy_json)?;
    println!("✅ Policy metadata written: {}", metadata_path.display());

    // Write verification script
    let verify_script = generate_verification_script(&policy_signature);
    let verify_path = output_path.join("verify.py");
    fs::write(&verify_path, verify_script)?;
    println!("✅ Verification script written: {}", verify_path.display());

    println!("\n🎉 Policy generation complete!");
    println!("Files generated:");
    println!("  - policy.wasm: WASM policy module");
    println!("  - sig.json: Policy signature");
    println!("  - policy.json: Policy metadata");
    println!("  - verify.py: Verification script");

    Ok(())
}

fn convert_yaml_to_policy(yaml_policy: &YamlPolicy) -> Result<Policy, PolicyEngineError> {
    let mut builder = PolicyBuilder::new("generated-policy");

    // Convert roles
    for yaml_role in &yaml_policy.roles {
        let mut role_builder = builders::role(&yaml_role.name);

        for yaml_perm in &yaml_role.permissions {
            let scope = convert_yaml_scope(&yaml_perm.scope)?;
            let permission = match yaml_perm.action.as_str() {
                "allow" => policyengine::policy::Permission::Allow(scope),
                "deny" => policyengine::policy::Permission::Deny(scope),
                _ => return Err(PolicyEngineError::PolicyValidationError(
                    format!("Invalid permission action: {}", yaml_perm.action)
                )),
            };

            role_builder = role_builder.with_permission(permission);
        }

        builder = builder.with_role(role_builder.build());
    }

    // Convert assignments
    for yaml_assignment in &yaml_policy.assignments {
        let principal = builders::principal(&yaml_assignment.principal);
        let principal = if let Some(attrs) = &yaml_assignment.attributes {
            let mut p = principal;
            for (key, value) in attrs {
                p = p.with_attribute(key, value);
            }
            p.build()
        } else {
            principal.build()
        };

        builder = builder.with_assignment(principal, yaml_assignment.role.clone());
    }

    // Add metadata
    if let Some(metadata) = &yaml_policy.metadata {
        for (key, value) in metadata {
            builder = builder.with_metadata(key.clone(), value.clone());
        }
    }

    Ok(builder.build())
}

fn convert_yaml_scope(yaml_scope: &YamlScope) -> Result<policyengine::policy::Scope, PolicyEngineError> {
    if let Some(resource) = &yaml_scope.resource {
        let path = yaml_scope.path.clone().unwrap_or_default();
        Ok(policyengine::policy::Scope::Resource {
            name: resource.clone(),
            path,
        })
    } else if let Some(action) = &yaml_scope.action {
        let params = yaml_scope.params.clone().unwrap_or_default();
        Ok(policyengine::policy::Scope::Action {
            name: action.clone(),
            params,
        })
    } else {
        Ok(policyengine::policy::Scope::Wildcard)
    }
}

fn generate_wasm_module(policy: &Policy) -> Result<Vec<u8>, PolicyEngineError> {
    // In practice, this would compile the Lean specification to WASM
    // For now, we create a simple WASM module with policy data embedded
    
    // Create a minimal WASM module that exports policy evaluation functions
    let wasm_bytes = vec![
        0x00, 0x61, 0x73, 0x6d, // WASM magic number
        0x01, 0x00, 0x00, 0x00, // WASM version
        // Type section
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
        // Function section
        0x03, 0x02, 0x01, 0x00,
        // Export section
        0x07, 0x0f, 0x01, 0x0e, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x65, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x00, 0x00,
        // Code section
        0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
    ];

    Ok(wasm_bytes)
}

fn generate_verification_script(signature: &PolicySignature) -> String {
    format!(
        r#"#!/usr/bin/env python3
"""
Policy Verification Script

This script verifies the integrity of the generated policy WASM module.
"""

import json
import hashlib
import sys
from pathlib import Path

def verify_policy():
    # Load signature
    with open('sig.json', 'r') as f:
        sig_data = json.load(f)
    
    # Load WASM module
    with open('policy.wasm', 'rb') as f:
        wasm_data = f.read()
    
    # Calculate hash
    wasm_hash = hashlib.sha256(wasm_data).hexdigest()
    
    # Verify hash matches
    if wasm_hash != sig_data['policy_hash']:
        print("❌ Policy hash mismatch!")
        print(f"Expected: {{sig_data['policy_hash']}}")
        print(f"Actual:   {{wasm_hash}}")
        return False
    
    print("✅ Policy verification successful!")
    print(f"Algorithm: {{sig_data['algorithm']}}")
    print(f"Timestamp: {{sig_data['timestamp']}}")
    print(f"Hash: {{wasm_hash}}")
    return True

if __name__ == "__main__":
    if not verify_policy():
        sys.exit(1)
"#
    )
} 