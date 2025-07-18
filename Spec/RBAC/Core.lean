/-
# RBAC Core Specification

This module defines the core Role-Based Access Control (RBAC) system with formal
specifications for roles, scopes, principals, and permission rules.

## Key Components:
- Role: A named collection of permissions
- Scope: A resource or action that can be accessed
- Principal: An entity (user, service) that can be assigned roles
- Permission: A rule that grants or denies access to a scope
- ABAC: Attribute-Based Access Control extension

## Formal Properties:
- Soundness: All granted permissions are valid
- Completeness: All valid permissions are granted
- Decidability: Permission checking terminates
- Non-interference: Role changes don't affect other principals
-/

import Mathlib.Data.Set.Basic
import Mathlib.Data.List.Basic
import Mathlib.Logic.Basic

namespace RBAC

/-- A principal represents an entity that can be assigned roles -/
structure Principal where
  id : String
  attributes : List (String × String) -- Key-value pairs for ABAC
  deriving DecidableEq, Repr

/-- A scope represents a resource or action that can be accessed -/
inductive Scope where
  | resource (name : String) (path : List String) : Scope
  | action (name : String) (params : List String) : Scope
  | wildcard : Scope
  deriving DecidableEq, Repr

/-- A permission grants or denies access to a scope -/
inductive Permission where
  | allow (scope : Scope) : Permission
  | deny (scope : Scope) : Permission
  deriving DecidableEq, Repr

/-- A role is a named collection of permissions -/
structure Role where
  name : String
  permissions : List Permission
  deriving DecidableEq, Repr

/-- A policy defines the complete RBAC system -/
structure Policy where
  roles : List Role
  assignments : List (Principal × String) -- Principal × Role name
  deriving DecidableEq, Repr

/-- ABAC attribute predicate -/
inductive AttributePredicate where
  | equals (key : String) (value : String) : AttributePredicate
  | not_equals (key : String) (value : String) : AttributePredicate
  | in_list (key : String) (values : List String) : AttributePredicate
  | greater_than (key : String) (value : String) : AttributePredicate
  | less_than (key : String) (value : String) : AttributePredicate
  | and (left : AttributePredicate) (right : AttributePredicate) : AttributePredicate
  | or (left : AttributePredicate) (right : AttributePredicate) : AttributePredicate
  | not (pred : AttributePredicate) : AttributePredicate
  deriving DecidableEq, Repr

/-- Extended permission with ABAC conditions -/
structure ABACPermission where
  permission : Permission
  condition : Option AttributePredicate
  deriving DecidableEq, Repr

/-- Extended role with ABAC support -/
structure ABACRole where
  name : String
  permissions : List ABACPermission
  deriving DecidableEq, Repr

/-- Extended policy with ABAC support -/
structure ABACPolicy where
  roles : List ABACRole
  assignments : List (Principal × String)
  deriving DecidableEq, Repr

/-- Helper functions for working with principals -/
namespace Principal

/-- Get an attribute value for a principal -/
def getAttribute (p : Principal) (key : String) : Option String :=
  p.attributes.find? (fun (k, _) => k == key) |>.map (fun (_, v) => v)

/-- Check if a principal has a specific attribute -/
def hasAttribute (p : Principal) (key : String) (value : String) : Bool :=
  p.getAttribute key == some value

/-- Add an attribute to a principal -/
def addAttribute (p : Principal) (key : String) (value : String) : Principal :=
  { p with attributes := (key, value) :: p.attributes }

end Principal

/-- Helper functions for working with scopes -/
namespace Scope

/-- Check if a scope matches another scope (including wildcards) -/
def matches (s1 s2 : Scope) : Bool :=
  match s1, s2 with
  | wildcard, _ => true
  | _, wildcard => true
  | resource n1 p1, resource n2 p2 => n1 == n2 && p1 == p2
  | action n1 p1, action n2 p2 => n1 == n2 && p1 == p2
  | _, _ => false

/-- Check if a scope is more specific than another -/
def isMoreSpecific (s1 s2 : Scope) : Bool :=
  match s1, s2 with
  | wildcard, _ => false
  | _, wildcard => true
  | resource n1 p1, resource n2 p2 =>
    n1 == n2 && p1.length > p2.length
  | action n1 p1, action n2 p2 =>
    n1 == n2 && p1.length > p2.length
  | _, _ => false

end Scope

/-- Helper functions for working with attribute predicates -/
namespace AttributePredicate

/-- Evaluate an attribute predicate against a principal -/
def evaluate (pred : AttributePredicate) (principal : Principal) : Bool :=
  match pred with
  | equals key value => principal.hasAttribute key value
  | not_equals key value => !principal.hasAttribute key value
  | in_list key values =>
    match principal.getAttribute key with
    | some v => values.contains v
    | none => false
  | greater_than key value =>
    match principal.getAttribute key with
    | some v => v > value
    | none => false
  | less_than key value =>
    match principal.getAttribute key with
    | some v => v < value
    | none => false
  | and left right => evaluate left principal && evaluate right principal
  | or left right => evaluate left principal || evaluate right principal
  | not pred => !evaluate pred principal

/-- Check if a predicate is decidable -/
def isDecidable (pred : AttributePredicate) : Bool :=
  match pred with
  | equals _ _ => true
  | not_equals _ _ => true
  | in_list _ _ => true
  | greater_than _ _ => true
  | less_than _ _ => true
  | and left right => isDecidable left && isDecidable right
  | or left right => isDecidable left && isDecidable right
  | not pred => isDecidable pred

end AttributePredicate

/-- Core RBAC permission checking -/
namespace Policy

/-- Get all roles assigned to a principal -/
def getAssignedRoles (policy : Policy) (principal : Principal) : List Role :=
  policy.assignments
    .filter (fun (p, _) => p == principal)
    .map (fun (_, roleName) =>
      policy.roles.find? (fun r => r.name == roleName) |>.getD ⟨"", []⟩)

/-- Check if a principal has a specific permission -/
def hasPermission (policy : Policy) (principal : Principal) (scope : Scope) : Bool :=
  let roles := policy.getAssignedRoles principal
  let permissions := roles.bind (fun r => r.permissions)
  permissions.any (fun perm =>
    match perm with
    | Permission.allow s => s.matches scope
    | Permission.deny s => s.matches scope)

/-- Check if a permission is explicitly denied -/
def isDenied (policy : Policy) (principal : Principal) (scope : Scope) : Bool :=
  let roles := policy.getAssignedRoles principal
  let permissions := roles.bind (fun r => r.permissions)
  permissions.any (fun perm =>
    match perm with
    | Permission.deny s => s.matches scope
    | Permission.allow _ => false)

/-- Check if a principal can access a scope (allow unless denied) -/
def canAccess (policy : Policy) (principal : Principal) (scope : Scope) : Bool :=
  if policy.isDenied principal scope then
    false
  else
    policy.hasPermission principal scope

end Policy

/-- ABAC policy permission checking -/
namespace ABACPolicy

/-- Get all ABAC roles assigned to a principal -/
def getAssignedRoles (policy : ABACPolicy) (principal : Principal) : List ABACRole :=
  policy.assignments
    .filter (fun (p, _) => p == principal)
    .map (fun (_, roleName) =>
      policy.roles.find? (fun r => r.name == roleName) |>.getD ⟨"", []⟩)

/-- Check if a principal has a specific ABAC permission -/
def hasPermission (policy : ABACPolicy) (principal : Principal) (scope : Scope) : Bool :=
  let roles := policy.getAssignedRoles principal
  let permissions := roles.bind (fun r => r.permissions)
  permissions.any (fun abacPerm =>
    match abacPerm.condition with
    | some condition =>
      if AttributePredicate.evaluate condition principal then
        match abacPerm.permission with
        | Permission.allow s => s.matches scope
        | Permission.deny s => s.matches scope
      else
        false
    | none =>
      match abacPerm.permission with
      | Permission.allow s => s.matches scope
      | Permission.deny s => s.matches scope)

/-- Check if an ABAC permission is explicitly denied -/
def isDenied (policy : ABACPolicy) (principal : Principal) (scope : Scope) : Bool :=
  let roles := policy.getAssignedRoles principal
  let permissions := roles.bind (fun r => r.permissions)
  permissions.any (fun abacPerm =>
    match abacPerm.condition with
    | some condition =>
      if AttributePredicate.evaluate condition principal then
        match abacPerm.permission with
        | Permission.deny s => s.matches scope
        | Permission.allow _ => false
      else
        false
    | none =>
      match abacPerm.permission with
      | Permission.deny s => s.matches scope
      | Permission.allow _ => false)

/-- Check if a principal can access a scope with ABAC (allow unless denied) -/
def canAccess (policy : ABACPolicy) (principal : Principal) (scope : Scope) : Bool :=
  if policy.isDenied principal scope then
    false
  else
    policy.hasPermission principal scope

end ABACPolicy

/-- Utility functions for policy construction -/
namespace PolicyBuilder

/-- Create a basic RBAC policy -/
def mkBasicPolicy : Policy :=
  { roles := [], assignments := [] }

/-- Add a role to a policy -/
def addRole (policy : Policy) (role : Role) : Policy :=
  { policy with roles := role :: policy.roles }

/-- Assign a role to a principal -/
def assignRole (policy : Policy) (principal : Principal) (roleName : String) : Policy :=
  { policy with assignments := (principal, roleName) :: policy.assignments }

/-- Create a basic ABAC policy -/
def mkABACPolicy : ABACPolicy :=
  { roles := [], assignments := [] }

/-- Add an ABAC role to a policy -/
def addABACRole (policy : ABACPolicy) (role : ABACRole) : ABACPolicy :=
  { policy with roles := role :: policy.roles }

/-- Assign an ABAC role to a principal -/
def assignABACRole (policy : ABACPolicy) (principal : Principal) (roleName : String) : ABACPolicy :=
  { policy with assignments := (principal, roleName) :: policy.assignments }

end PolicyBuilder

end RBAC
