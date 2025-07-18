//! Policy module for RBAC/ABAC definitions and WASM integration
//!
//! This module defines the core policy structures that correspond to the Lean
//! formal specifications, and provides integration with WASM for policy execution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

/// A principal represents an entity that can be assigned roles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub attributes: Vec<(String, String)>, // Key-value pairs for ABAC
}

/// A scope represents a resource or action that can be accessed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Scope {
    Resource {
        name: String,
        path: Vec<String>,
    },
    Action {
        name: String,
        params: Vec<String>,
    },
    Wildcard,
}

/// A permission grants or denies access to a scope
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    Allow(Scope),
    Deny(Scope),
}

/// A role is a named collection of permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
}

/// ABAC attribute predicate for dynamic policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttributePredicate {
    Equals(String, String),
    NotEquals(String, String),
    InList(String, Vec<String>),
    GreaterThan(String, String),
    LessThan(String, String),
    And(Box<AttributePredicate>, Box<AttributePredicate>),
    Or(Box<AttributePredicate>, Box<AttributePredicate>),
    Not(Box<AttributePredicate>),
}

/// Extended permission with ABAC conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACPermission {
    pub permission: Permission,
    pub condition: Option<AttributePredicate>,
}

/// Extended role with ABAC support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACRole {
    pub name: String,
    pub permissions: Vec<ABACPermission>,
}

/// A policy defines the complete RBAC/ABAC system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub version: String,
    pub roles: Vec<Role>,
    pub abac_roles: Vec<ABACRole>,
    pub assignments: Vec<(Principal, String)>, // Principal × Role name
    pub rules: Vec<PolicyRule>,
    pub metadata: HashMap<String, String>,
}

/// A policy rule for complex decision logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub priority: u32,
    pub enabled: bool,
}

/// Rule condition for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    Always,
    PrincipalHasRole(String),
    PrincipalHasAttribute(String, String),
    ScopeMatches(Scope),
    TimeBetween(u64, u64), // Unix timestamps
    LocationWithin(f64, f64, f64), // lat, lon, radius_km
    Custom(String), // WASM function name
}

/// Rule action for policy decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
    Custom(String), // WASM function name
}

impl Policy {
    /// Create a new policy from WASM bytecode
    pub fn from_wasm(wasm_bytes: &[u8], policy_id: &str) -> Result<Self> {
        // In a real implementation, this would parse the WASM module
        // and extract policy information from exported functions
        
        Ok(Self {
            id: policy_id.to_string(),
            version: "1.0.0".to_string(),
            roles: Vec::new(),
            abac_roles: Vec::new(),
            assignments: Vec::new(),
            rules: Vec::new(),
            metadata: HashMap::new(),
        })
    }

    /// Get all roles assigned to a principal
    pub fn get_assigned_roles(&self, principal: &Principal) -> Vec<&Role> {
        self.assignments
            .iter()
            .filter(|(p, _)| p.id == principal.id)
            .filter_map(|(_, role_name)| {
                self.roles.iter().find(|r| r.name == *role_name)
            })
            .collect()
    }

    /// Get all ABAC roles assigned to a principal
    pub fn get_assigned_abac_roles(&self, principal: &Principal) -> Vec<&ABACRole> {
        self.assignments
            .iter()
            .filter(|(p, _)| p.id == principal.id)
            .filter_map(|(_, role_name)| {
                self.abac_roles.iter().find(|r| r.name == *role_name)
            })
            .collect()
    }

    /// Check if a principal has a specific permission
    pub fn has_permission(&self, principal: &Principal, scope: &Scope) -> bool {
        let roles = self.get_assigned_roles(principal);
        let permissions: Vec<&Permission> = roles
            .iter()
            .flat_map(|r| r.permissions.iter())
            .collect();

        permissions.iter().any(|perm| {
            matches!(perm, Permission::Allow(s) if scope_matches(s, scope))
        })
    }

    /// Check if a permission is explicitly denied
    pub fn is_denied(&self, principal: &Principal, scope: &Scope) -> bool {
        let roles = self.get_assigned_roles(principal);
        let permissions: Vec<&Permission> = roles
            .iter()
            .flat_map(|r| r.permissions.iter())
            .collect();

        permissions.iter().any(|perm| {
            matches!(perm, Permission::Deny(s) if scope_matches(s, scope))
        })
    }

    /// Check if a principal can access a scope (allow unless denied)
    pub fn can_access(&self, principal: &Principal, scope: &Scope) -> bool {
        if self.is_denied(principal, scope) {
            false
        } else {
            self.has_permission(principal, scope)
        }
    }

    /// Evaluate ABAC conditions for a principal
    pub fn evaluate_abac_conditions(&self, principal: &Principal, scope: &Scope) -> bool {
        let abac_roles = self.get_assigned_abac_roles(principal);
        
        for role in abac_roles {
            for abac_perm in &role.permissions {
                let condition_met = match &abac_perm.condition {
                    Some(condition) => evaluate_attribute_predicate(condition, principal),
                    None => true,
                };

                if condition_met {
                    match &abac_perm.permission {
                        Permission::Allow(s) if scope_matches(s, scope) => return true,
                        Permission::Deny(s) if scope_matches(s, scope) => return false,
                        _ => continue,
                    }
                }
            }
        }
        
        false
    }

    /// Add a role to the policy
    pub fn add_role(&mut self, role: Role) {
        self.roles.push(role);
    }

    /// Add an ABAC role to the policy
    pub fn add_abac_role(&mut self, role: ABACRole) {
        self.abac_roles.push(role);
    }

    /// Assign a role to a principal
    pub fn assign_role(&mut self, principal: Principal, role_name: String) {
        self.assignments.push((principal, role_name));
    }

    /// Remove a role assignment
    pub fn remove_role_assignment(&mut self, principal_id: &str, role_name: &str) {
        self.assignments.retain(|(p, r)| {
            p.id != principal_id || r != role_name
        });
    }

    /// Get policy metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Set policy metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Helper function to check if two scopes match
fn scope_matches(scope1: &Scope, scope2: &Scope) -> bool {
    match (scope1, scope2) {
        (Scope::Wildcard, _) | (_, Scope::Wildcard) => true,
        (
            Scope::Resource { name: n1, path: p1 },
            Scope::Resource { name: n2, path: p2 },
        ) => n1 == n2 && p1 == p2,
        (
            Scope::Action { name: n1, params: p1 },
            Scope::Action { name: n2, params: p2 },
        ) => n1 == n2 && p1 == p2,
        _ => false,
    }
}

/// Evaluate an attribute predicate against a principal
fn evaluate_attribute_predicate(predicate: &AttributePredicate, principal: &Principal) -> bool {
    match predicate {
        AttributePredicate::Equals(key, value) => {
            principal.attributes.iter().any(|(k, v)| k == key && v == value)
        }
        AttributePredicate::NotEquals(key, value) => {
            !principal.attributes.iter().any(|(k, v)| k == key && v == value)
        }
        AttributePredicate::InList(key, values) => {
            principal.attributes.iter().any(|(k, v)| k == key && values.contains(v))
        }
        AttributePredicate::GreaterThan(key, value) => {
            principal.attributes.iter().any(|(k, v)| {
                k == key && v.parse::<f64>().unwrap_or(0.0) > value.parse::<f64>().unwrap_or(0.0)
            })
        }
        AttributePredicate::LessThan(key, value) => {
            principal.attributes.iter().any(|(k, v)| {
                k == key && v.parse::<f64>().unwrap_or(0.0) < value.parse::<f64>().unwrap_or(0.0)
            })
        }
        AttributePredicate::And(left, right) => {
            evaluate_attribute_predicate(left, principal) && evaluate_attribute_predicate(right, principal)
        }
        AttributePredicate::Or(left, right) => {
            evaluate_attribute_predicate(left, principal) || evaluate_attribute_predicate(right, principal)
        }
        AttributePredicate::Not(pred) => {
            !evaluate_attribute_predicate(pred, principal)
        }
    }
}

/// Policy builder for constructing policies programmatically
pub struct PolicyBuilder {
    policy: Policy,
}

impl PolicyBuilder {
    /// Create a new policy builder
    pub fn new(policy_id: &str) -> Self {
        Self {
            policy: Policy {
                id: policy_id.to_string(),
                version: "1.0.0".to_string(),
                roles: Vec::new(),
                abac_roles: Vec::new(),
                assignments: Vec::new(),
                rules: Vec::new(),
                metadata: HashMap::new(),
            },
        }
    }

    /// Add a role to the policy
    pub fn with_role(mut self, role: Role) -> Self {
        self.policy.add_role(role);
        self
    }

    /// Add an ABAC role to the policy
    pub fn with_abac_role(mut self, role: ABACRole) -> Self {
        self.policy.add_abac_role(role);
        self
    }

    /// Assign a role to a principal
    pub fn with_assignment(mut self, principal: Principal, role_name: String) -> Self {
        self.policy.assign_role(principal, role_name);
        self
    }

    /// Add a policy rule
    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.policy.rules.push(rule);
        self
    }

    /// Set policy metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.policy.set_metadata(key, value);
        self
    }

    /// Build the policy
    pub fn build(self) -> Policy {
        self.policy
    }
}

/// Helper functions for creating common policy components
pub mod builders {
    use super::*;

    /// Create a simple RBAC role
    pub fn role(name: &str) -> RoleBuilder {
        RoleBuilder::new(name)
    }

    /// Create an ABAC role
    pub fn abac_role(name: &str) -> ABACRoleBuilder {
        ABACRoleBuilder::new(name)
    }

    /// Create a principal
    pub fn principal(id: &str) -> PrincipalBuilder {
        PrincipalBuilder::new(id)
    }

    /// Create a scope
    pub fn scope() -> ScopeBuilder {
        ScopeBuilder::new()
    }
}

/// Builder for creating roles
pub struct RoleBuilder {
    role: Role,
}

impl RoleBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            role: Role {
                name: name.to_string(),
                permissions: Vec::new(),
            },
        }
    }

    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.role.permissions.push(permission);
        self
    }

    pub fn build(self) -> Role {
        self.role
    }
}

/// Builder for creating ABAC roles
pub struct ABACRoleBuilder {
    role: ABACRole,
}

impl ABACRoleBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            role: ABACRole {
                name: name.to_string(),
                permissions: Vec::new(),
            },
        }
    }

    pub fn with_permission(mut self, permission: ABACPermission) -> Self {
        self.role.permissions.push(permission);
        self
    }

    pub fn build(self) -> ABACRole {
        self.role
    }
}

/// Builder for creating principals
pub struct PrincipalBuilder {
    principal: Principal,
}

impl PrincipalBuilder {
    pub fn new(id: &str) -> Self {
        Self {
            principal: Principal {
                id: id.to_string(),
                attributes: Vec::new(),
            },
        }
    }

    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.principal.attributes.push((key.to_string(), value.to_string()));
        self
    }

    pub fn build(self) -> Principal {
        self.principal
    }
}

/// Builder for creating scopes
pub struct ScopeBuilder {
    scope_type: Option<Scope>,
}

impl ScopeBuilder {
    pub fn new() -> Self {
        Self { scope_type: None }
    }

    pub fn resource(mut self, name: &str, path: Vec<String>) -> Self {
        self.scope_type = Some(Scope::Resource {
            name: name.to_string(),
            path,
        });
        self
    }

    pub fn action(mut self, name: &str, params: Vec<String>) -> Self {
        self.scope_type = Some(Scope::Action {
            name: name.to_string(),
            params,
        });
        self
    }

    pub fn wildcard(mut self) -> Self {
        self.scope_type = Some(Scope::Wildcard);
        self
    }

    pub fn build(self) -> Option<Scope> {
        self.scope_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_matching() {
        let wildcard = Scope::Wildcard;
        let resource1 = Scope::Resource {
            name: "test".to_string(),
            path: vec!["read".to_string()],
        };
        let resource2 = Scope::Resource {
            name: "test".to_string(),
            path: vec!["read".to_string()],
        };
        let resource3 = Scope::Resource {
            name: "other".to_string(),
            path: vec!["read".to_string()],
        };

        assert!(scope_matches(&wildcard, &resource1));
        assert!(scope_matches(&resource1, &wildcard));
        assert!(scope_matches(&resource1, &resource2));
        assert!(!scope_matches(&resource1, &resource3));
    }

    #[test]
    fn test_policy_builder() {
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

        assert_eq!(policy.id, "test-policy");
        assert_eq!(policy.roles.len(), 1);
        assert_eq!(policy.assignments.len(), 1);
    }

    #[test]
    fn test_attribute_predicate_evaluation() {
        let principal = builders::principal("user1")
            .with_attribute("role", "admin")
            .with_attribute("level", "5")
            .build();

        let equals_pred = AttributePredicate::Equals("role".to_string(), "admin".to_string());
        assert!(evaluate_attribute_predicate(&equals_pred, &principal));

        let not_equals_pred = AttributePredicate::NotEquals("role".to_string(), "user".to_string());
        assert!(evaluate_attribute_predicate(&not_equals_pred, &principal));

        let in_list_pred = AttributePredicate::InList("role".to_string(), vec!["admin".to_string(), "user".to_string()]);
        assert!(evaluate_attribute_predicate(&in_list_pred, &principal));

        let greater_than_pred = AttributePredicate::GreaterThan("level".to_string(), "3".to_string());
        assert!(evaluate_attribute_predicate(&greater_than_pred, &principal));
    }
} 