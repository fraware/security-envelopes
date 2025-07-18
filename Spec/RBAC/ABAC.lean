/-
# ABAC Extension

This module extends the core RBAC system with Attribute-Based Access Control (ABAC)
capabilities, allowing for dynamic policy evaluation based on principal attributes,
environmental conditions, and resource properties.

## Key Features:
- Complex attribute predicates (AND, OR, NOT, comparisons)
- Time-based conditions
- Location-based conditions
- Risk-based conditions
- Dynamic policy evaluation
-/

import RBAC.Core
import Mathlib.Data.Set.Basic
import Mathlib.Data.List.Basic
import Mathlib.Logic.Basic
import Mathlib.Data.Time.Basic

namespace RBAC.ABAC

/-- Extended attribute types for ABAC -/
inductive AttributeType where
  | string : AttributeType
  | integer : AttributeType
  | boolean : AttributeType
  | timestamp : AttributeType
  | ip_address : AttributeType
  | location : AttributeType
  deriving DecidableEq, Repr

/-- Typed attribute value -/
inductive AttributeValue where
  | string (value : String) : AttributeValue
  | integer (value : Int) : AttributeValue
  | boolean (value : Bool) : AttributeValue
  | timestamp (value : Nat) : AttributeValue -- Unix timestamp
  | ip_address (value : String) : AttributeValue
  | location (lat : Float) (lon : Float) : AttributeValue
  deriving DecidableEq, Repr

/-- Extended principal with typed attributes -/
structure ABACPrincipal where
  id : String
  attributes : List (String × AttributeValue)
  deriving DecidableEq, Repr

/-- Advanced attribute predicates for ABAC -/
inductive AdvancedPredicate where
  -- Basic comparisons
  | equals (key : String) (value : AttributeValue) : AdvancedPredicate
  | not_equals (key : String) (value : AttributeValue) : AdvancedPredicate
  | greater_than (key : String) (value : AttributeValue) : AdvancedPredicate
  | less_than (key : String) (value : AttributeValue) : AdvancedPredicate
  | greater_equal (key : String) (value : AttributeValue) : AdvancedPredicate
  | less_equal (key : String) (value : AttributeValue) : AdvancedPredicate

  -- String operations
  | starts_with (key : String) (prefix : String) : AdvancedPredicate
  | ends_with (key : String) (suffix : String) : AdvancedPredicate
  | contains (key : String) (substring : String) : AdvancedPredicate
  | regex_match (key : String) (pattern : String) : AdvancedPredicate

  -- List operations
  | in_list (key : String) (values : List AttributeValue) : AdvancedPredicate
  | not_in_list (key : String) (values : List AttributeValue) : AdvancedPredicate

  -- Time-based conditions
  | time_between (key : String) (start : Nat) (end : Nat) : AdvancedPredicate
  | time_after (key : String) (timestamp : Nat) : AdvancedPredicate
  | time_before (key : String) (timestamp : Nat) : AdvancedPredicate

  -- Location-based conditions
  | within_radius (lat_key : String) (lon_key : String) (center_lat : Float) (center_lon : Float) (radius_km : Float) : AdvancedPredicate
  | in_region (lat_key : String) (lon_key : String) (bounds : List (Float × Float)) : AdvancedPredicate

  -- IP address conditions
  | ip_in_range (key : String) (start_ip : String) (end_ip : String) : AdvancedPredicate
  | ip_in_subnet (key : String) (subnet : String) (mask : Int) : AdvancedPredicate

  -- Logical operators
  | and (left : AdvancedPredicate) (right : AdvancedPredicate) : AdvancedPredicate
  | or (left : AdvancedPredicate) (right : AdvancedPredicate) : AdvancedPredicate
  | not (pred : AdvancedPredicate) : AdvancedPredicate
  | implies (left : AdvancedPredicate) (right : AdvancedPredicate) : AdvancedPredicate

  -- Aggregation
  | all (pred : AdvancedPredicate) : AdvancedPredicate
  | any (pred : AdvancedPredicate) : AdvancedPredicate
  | count (pred : AdvancedPredicate) (min : Int) (max : Int) : AdvancedPredicate

  deriving DecidableEq, Repr

/-- Helper functions for ABAC principals -/
namespace ABACPrincipal

/-- Get a typed attribute value -/
def getAttribute (p : ABACPrincipal) (key : String) : Option AttributeValue :=
  p.attributes.find? (fun (k, _) => k == key) |>.map (fun (_, v) => v)

/-- Check if principal has a specific attribute -/
def hasAttribute (p : ABACPrincipal) (key : String) (value : AttributeValue) : Bool :=
  p.getAttribute key == some value

/-- Add an attribute to a principal -/
def addAttribute (p : ABACPrincipal) (key : String) (value : AttributeValue) : ABACPrincipal :=
  { p with attributes := (key, value) :: p.attributes }

/-- Convert to basic principal for compatibility -/
def toBasicPrincipal (p : ABACPrincipal) : Principal :=
  { id := p.id
    attributes := p.attributes.map (fun (k, v) =>
      (k, match v with
        | AttributeValue.string s => s
        | AttributeValue.integer i => toString i
        | AttributeValue.boolean b => toString b
        | AttributeValue.timestamp t => toString t
        | AttributeValue.ip_address ip => ip
        | AttributeValue.location lat lon => s!"{lat},{lon}")) }

end ABACPrincipal

/-- Helper functions for attribute values -/
namespace AttributeValue

/-- Compare two attribute values -/
def compare (v1 v2 : AttributeValue) : Ordering :=
  match v1, v2 with
  | string s1, string s2 => compare s1 s2
  | integer i1, integer i2 => compare i1 i2
  | boolean b1, boolean b2 => compare b1 b2
  | timestamp t1, timestamp t2 => compare t1 t2
  | ip_address ip1, ip_address ip2 => compare ip1 ip2
  | location lat1 lon1, location lat2 lon2 =>
    match compare lat1 lat2 with
    | Ordering.eq => compare lon1 lon2
    | other => other
  | _, _ => Ordering.lt -- Different types are incomparable

/-- Check if value is greater than another -/
def greaterThan (v1 v2 : AttributeValue) : Bool :=
  compare v1 v2 == Ordering.gt

/-- Check if value is less than another -/
def lessThan (v1 v2 : AttributeValue) : Bool :=
  compare v1 v2 == Ordering.lt

/-- Check if value is equal to another -/
def equals (v1 v2 : AttributeValue) : Bool :=
  compare v1 v2 == Ordering.eq

/-- Convert to string for display -/
def toString (v : AttributeValue) : String :=
  match v with
  | string s => s
  | integer i => toString i
  | boolean b => toString b
  | timestamp t => toString t
  | ip_address ip => ip
  | location lat lon => s!"{lat},{lon}"

end AttributeValue

/-- Advanced predicate evaluation -/
namespace AdvancedPredicate

/-- Evaluate an advanced predicate against an ABAC principal -/
def evaluate (pred : AdvancedPredicate) (principal : ABACPrincipal) : Bool :=
  match pred with
  | equals key value => principal.hasAttribute key value
  | not_equals key value => !principal.hasAttribute key value
  | greater_than key value =>
    match principal.getAttribute key with
    | some v => AttributeValue.greaterThan v value
    | none => false
  | less_than key value =>
    match principal.getAttribute key with
    | some v => AttributeValue.lessThan v value
    | none => false
  | greater_equal key value =>
    match principal.getAttribute key with
    | some v => AttributeValue.greaterThan v value || AttributeValue.equals v value
    | none => false
  | less_equal key value =>
    match principal.getAttribute key with
    | some v => AttributeValue.lessThan v value || AttributeValue.equals v value
    | none => false
  | starts_with key prefix =>
    match principal.getAttribute key with
    | some (AttributeValue.string s) => s.startsWith prefix
    | _ => false
  | ends_with key suffix =>
    match principal.getAttribute key with
    | some (AttributeValue.string s) => s.endsWith suffix
    | _ => false
  | contains key substring =>
    match principal.getAttribute key with
    | some (AttributeValue.string s) => s.contains substring
    | _ => false
  | regex_match key pattern =>
    match principal.getAttribute key with
    | some (AttributeValue.string s) =>
      -- Simple regex matching (in practice, use a proper regex library)
      s.contains pattern
    | _ => false
  | in_list key values =>
    match principal.getAttribute key with
    | some v => values.contains v
    | none => false
  | not_in_list key values =>
    match principal.getAttribute key with
    | some v => !values.contains v
    | none => true
  | time_between key start end =>
    match principal.getAttribute key with
    | some (AttributeValue.timestamp t) => t >= start && t <= end
    | _ => false
  | time_after key timestamp =>
    match principal.getAttribute key with
    | some (AttributeValue.timestamp t) => t > timestamp
    | _ => false
  | time_before key timestamp =>
    match principal.getAttribute key with
    | some (AttributeValue.timestamp t) => t < timestamp
    | _ => false
  | within_radius lat_key lon_key center_lat center_lon radius_km =>
    match principal.getAttribute lat_key, principal.getAttribute lon_key with
    | some (AttributeValue.location lat lon), _ =>
      let distance := calculateDistance lat lon center_lat center_lon
      distance <= radius_km
    | _ => false
  | in_region lat_key lon_key bounds =>
    match principal.getAttribute lat_key, principal.getAttribute lon_key with
    | some (AttributeValue.location lat lon), _ =>
      bounds.any (fun (min_lat, max_lat) => lat >= min_lat && lat <= max_lat)
    | _ => false
  | ip_in_range key start_ip end_ip =>
    match principal.getAttribute key with
    | some (AttributeValue.ip_address ip) =>
      isIPInRange ip start_ip end_ip
    | _ => false
  | ip_in_subnet key subnet mask =>
    match principal.getAttribute key with
    | some (AttributeValue.ip_address ip) =>
      isIPInSubnet ip subnet mask
    | _ => false
  | and left right => evaluate left principal && evaluate right principal
  | or left right => evaluate left principal || evaluate right principal
  | not pred => !evaluate pred principal
  | implies left right => !evaluate left principal || evaluate right principal
  | all pred =>
    -- For now, assume this applies to all attributes (simplified)
    principal.attributes.all (fun (_, _) => evaluate pred principal)
  | any pred =>
    -- For now, assume this applies to any attribute (simplified)
    principal.attributes.any (fun (_, _) => evaluate pred principal)
  | count pred min max =>
    let count := principal.attributes.count (fun (_, _) => evaluate pred principal)
    count >= min && count <= max

/-- Calculate distance between two points using Haversine formula -/
def calculateDistance (lat1 lon1 lat2 lon2 : Float) : Float :=
  let R := 6371.0 -- Earth's radius in km
  let dLat := (lat2 - lat1) * Math.pi / 180.0
  let dLon := (lon2 - lon1) * Math.pi / 180.0
  let a := Math.sin (dLat / 2.0) * Math.sin (dLat / 2.0) +
           Math.cos (lat1 * Math.pi / 180.0) * Math.cos (lat2 * Math.pi / 180.0) *
           Math.sin (dLon / 2.0) * Math.sin (dLon / 2.0)
  let c := 2.0 * Math.atan2 (Math.sqrt a) (Math.sqrt (1.0 - a))
  R * c

/-- Check if IP is in range (simplified) -/
def isIPInRange (ip start_ip end_ip : String) : Bool :=
  -- Simplified IP range checking
  ip >= start_ip && ip <= end_ip

/-- Check if IP is in subnet (simplified) -/
def isIPInSubnet (ip subnet : String) (mask : Int) : Bool :=
  -- Simplified subnet checking
  ip.startsWith subnet

end AdvancedPredicate

/-- Extended ABAC permission with advanced predicates -/
structure AdvancedABACPermission where
  permission : Permission
  condition : Option AdvancedPredicate
  priority : Int -- Higher priority permissions are evaluated first
  deriving DecidableEq, Repr

/-- Extended ABAC role with advanced permissions -/
structure AdvancedABACRole where
  name : String
  permissions : List AdvancedABACPermission
  deriving DecidableEq, Repr

/-- Extended ABAC policy with advanced features -/
structure AdvancedABACPolicy where
  roles : List AdvancedABACRole
  assignments : List (ABACPrincipal × String)
  default_action : Permission -- Default action when no rules match
  deriving DecidableEq, Repr

/-- Advanced ABAC policy evaluation -/
namespace AdvancedABACPolicy

/-- Get all advanced ABAC roles assigned to a principal -/
def getAssignedRoles (policy : AdvancedABACPolicy) (principal : ABACPrincipal) : List AdvancedABACRole :=
  policy.assignments
    .filter (fun (p, _) => p == principal)
    .map (fun (_, roleName) =>
      policy.roles.find? (fun r => r.name == roleName) |>.getD ⟨"", [], 0⟩)

/-- Evaluate permissions in priority order -/
def evaluatePermissions (policy : AdvancedABACPolicy) (principal : ABACPrincipal) (scope : Scope) : Option Permission :=
  let roles := policy.getAssignedRoles principal
  let allPermissions := roles.bind (fun r => r.permissions)
  let sortedPermissions := allPermissions.sortBy (fun p1 p2 => compare p1.priority p2.priority)

  -- Find the first matching permission
  sortedPermissions.find? (fun abacPerm =>
    match abacPerm.condition with
    | some condition => AdvancedPredicate.evaluate condition principal
    | none => true)

/-- Check if a principal can access a scope with advanced ABAC -/
def canAccess (policy : AdvancedABACPolicy) (principal : ABACPrincipal) (scope : Scope) : Bool :=
  match policy.evaluatePermissions principal scope with
  | some (Permission.allow s) => s.matches scope
  | some (Permission.deny s) => false
  | none =>
    -- Use default action
    match policy.default_action with
    | Permission.allow s => s.matches scope
    | Permission.deny s => false

/-- Get all applicable permissions for a principal and scope -/
def getApplicablePermissions (policy : AdvancedABACPolicy) (principal : ABACPrincipal) (scope : Scope) : List AdvancedABACPermission :=
  let roles := policy.getAssignedRoles principal
  let allPermissions := roles.bind (fun r => r.permissions)
  allPermissions.filter (fun abacPerm =>
    match abacPerm.condition with
    | some condition => AdvancedPredicate.evaluate condition principal
    | none => true)

end AdvancedABACPolicy

/-- Policy builder for advanced ABAC -/
namespace AdvancedPolicyBuilder

/-- Create a basic advanced ABAC policy -/
def mkAdvancedPolicy (default_action : Permission) : AdvancedABACPolicy :=
  { roles := [], assignments := [], default_action := default_action }

/-- Add an advanced ABAC role to a policy -/
def addAdvancedRole (policy : AdvancedABACPolicy) (role : AdvancedABACRole) : AdvancedABACPolicy :=
  { policy with roles := role :: policy.roles }

/-- Assign an advanced ABAC role to a principal -/
def assignAdvancedRole (policy : AdvancedABACPolicy) (principal : ABACPrincipal) (roleName : String) : AdvancedABACPolicy :=
  { policy with assignments := (principal, roleName) :: policy.assignments }

/-- Create a time-based condition -/
def timeCondition (key : String) (start : Nat) (end : Nat) : AdvancedPredicate :=
  AdvancedPredicate.time_between key start end

/-- Create a location-based condition -/
def locationCondition (lat_key : String) (lon_key : String) (center_lat : Float) (center_lon : Float) (radius_km : Float) : AdvancedPredicate :=
  AdvancedPredicate.within_radius lat_key lon_key center_lat center_lon radius_km

/-- Create a risk-based condition -/
def riskCondition (risk_key : String) (threshold : Int) : AdvancedPredicate :=
  AdvancedPredicate.greater_than risk_key (AttributeValue.integer threshold)

end AdvancedPolicyBuilder

end RBAC.ABAC
