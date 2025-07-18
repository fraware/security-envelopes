/-
# Tenant Isolation Test Suite

This module contains comprehensive tests for multi-tenant isolation functionality,
including non-interference, resource bounds, and namespace isolation.
-/

import Tenant.FSM
import Tenant.Isolation
import Mathlib.Data.List.Basic
import Mathlib.Logic.Basic

namespace Tests.Tenant

/-- Test basic tenant isolation -/
def testBasicIsolation : IO Unit := do
  IO.println "Testing basic tenant isolation..."

  -- Create initial FSM state
  let fsm := TenantFSM.mkEmpty

  -- Create two tenants
  let tenant1 := Tenant.mk "tenant-001" "Test Tenant 1" 0 TenantStatus.active
  let tenant2 := Tenant.mk "tenant-002" "Test Tenant 2" 0 TenantStatus.active

  -- Create namespaces for each tenant
  let namespace1 := Namespace.mk "ns-001" "tenant-001" "Namespace 1" ResourceType.storage (Quota.mk 10 2 4 100 10 100)
  let namespace2 := Namespace.mk "ns-002" "tenant-002" "Namespace 2" ResourceType.storage (Quota.mk 10 2 4 100 10 100)

  -- Test that tenants can access their own namespaces
  let can_access1 := TenantFSM.canAccess fsm "tenant-001" "ns-001"
  let can_access2 := TenantFSM.canAccess fsm "tenant-002" "ns-002"

  IO.println s!"Tenant 1 can access namespace 1: {can_access1}"
  IO.println s!"Tenant 2 can access namespace 2: {can_access2}"

  -- Test isolation invariants
  let isolation_proof := Tenant.Isolation.isolationInvariant fsm.state
  IO.println s!"Isolation invariant: {isolation_proof}"

/-- Test non-interference between tenants -/
def testNonInterference : IO Unit := do
  IO.println "Testing non-interference between tenants..."

  let fsm := TenantFSM.mkEmpty

  -- Create tenants and namespaces
  let tenant1 := Tenant.mk "tenant-001" "Test Tenant 1" 0 TenantStatus.active
  let tenant2 := Tenant.mk "tenant-002" "Test Tenant 2" 0 TenantStatus.active

  let namespace1 := Namespace.mk "ns-001" "tenant-001" "Namespace 1" ResourceType.storage (Quota.mk 10 2 4 100 10 100)
  let namespace2 := Namespace.mk "ns-002" "tenant-002" "Namespace 2" ResourceType.storage (Quota.mk 10 2 4 100 10 100)

  -- Test that tenant 1 cannot access tenant 2's namespace
  let cross_access := TenantFSM.canAccess fsm "tenant-001" "ns-002"
  IO.println s!"Tenant 1 can access Tenant 2's namespace: {cross_access}"

  -- Verify non-interference proof
  let noninterference_proof := Tenant.Isolation.nonInterference fsm
  IO.println s!"Non-interference proof: {noninterference_proof}"

/-- Test resource quota enforcement -/
def testResourceQuotas : IO Unit := do
  IO.println "Testing resource quota enforcement..."

  let fsm := TenantFSM.mkEmpty

  -- Create tenant with limited quota
  let tenant := Tenant.mk "tenant-001" "Test Tenant" 0 TenantStatus.active
  let namespace := Namespace.mk "ns-001" "tenant-001" "Namespace 1" ResourceType.storage (Quota.mk 5 1 2 50 5 50)

  -- Test resource usage within quota
  let usage_within := ResourceUsage.mk 2 0 1 25 2 25
  let within_quota := ResourceUsage.withinQuota usage_within namespace.quota
  IO.println s!"Usage within quota: {within_quota}"

  -- Test resource usage exceeding quota
  let usage_exceed := ResourceUsage.mk 10 2 4 100 10 100
  let exceed_quota := ResourceUsage.withinQuota usage_exceed namespace.quota
  IO.println s!"Usage exceeds quota: {exceed_quota}"

  -- Verify quota enforcement
  let quota_proof := Tenant.Isolation.resourceQuotaEnforcement fsm
  IO.println s!"Quota enforcement proof: {quota_proof}"

/-- Test namespace isolation -/
def testNamespaceIsolation : IO Unit := do
  IO.println "Testing namespace isolation..."

  let fsm := TenantFSM.mkEmpty

  -- Create multiple namespaces for different tenants
  let namespace1 := Namespace.mk "ns-001" "tenant-001" "Namespace 1" ResourceType.storage (Quota.mk 10 2 4 100 10 100)
  let namespace2 := Namespace.mk "ns-002" "tenant-002" "Namespace 2" ResourceType.compute (Quota.mk 10 2 4 100 10 100)
  let namespace3 := Namespace.mk "ns-003" "tenant-001" "Namespace 3" ResourceType.database (Quota.mk 10 2 4 100 10 100)

  -- Test that namespaces belong to correct tenants
  let belongs1 := Namespace.belongsTo namespace1 "tenant-001"
  let belongs2 := Namespace.belongsTo namespace2 "tenant-002"
  let belongs3 := Namespace.belongsTo namespace3 "tenant-001"

  IO.println s!"Namespace 1 belongs to tenant 1: {belongs1}"
  IO.println s!"Namespace 2 belongs to tenant 2: {belongs2}"
  IO.println s!"Namespace 3 belongs to tenant 1: {belongs3}"

  -- Verify namespace isolation
  let isolation_proof := Tenant.Isolation.namespaceIsolation fsm
  IO.println s!"Namespace isolation proof: {isolation_proof}"

/-- Test tenant state transitions -/
def testStateTransitions : IO Unit := do
  IO.println "Testing tenant state transitions..."

  let fsm := TenantFSM.mkEmpty

  -- Test tenant creation
  let create_event := TenantEvent.create_tenant "tenant-001" "Test Tenant"
  let fsm_after_create := TenantFSM.applyEvent fsm create_event

  match fsm_after_create with
  | some new_fsm =>
    IO.println "Tenant creation successful"

    -- Test tenant suspension
    let suspend_event := TenantEvent.suspend_tenant "tenant-001"
    let fsm_after_suspend := TenantFSM.applyEvent new_fsm suspend_event

    match fsm_after_suspend with
    | some suspended_fsm =>
      IO.println "Tenant suspension successful"

      -- Test that suspended tenant cannot access resources
      let can_access := TenantFSM.canAccess suspended_fsm "tenant-001" "ns-001"
      IO.println s!"Suspended tenant can access resources: {can_access}"

    | none => IO.println "Tenant suspension failed"

  | none => IO.println "Tenant creation failed"

/-- Test resource operations -/
def testResourceOperations : IO Unit := do
  IO.println "Testing resource operations..."

  let fsm := TenantFSM.mkEmpty

  -- Create tenant and namespace
  let create_tenant_event := TenantEvent.create_tenant "tenant-001" "Test Tenant"
  let fsm_with_tenant := TenantFSM.applyEvent fsm create_tenant_event

  match fsm_with_tenant with
  | some fsm1 =>
    let create_ns_event := TenantEvent.create_namespace "tenant-001" "ns-001" "Namespace 1" ResourceType.storage (Quota.mk 10 2 4 100 10 100)
    let fsm_with_ns := TenantFSM.applyEvent fsm1 create_ns_event

    match fsm_with_ns with
    | some fsm2 =>
      -- Test resource creation
      let create_op := ResourceOperation.create "ns-001" ResourceType.storage
      let create_event := TenantEvent.resource_operation "tenant-001" create_op
      let fsm_after_create := TenantFSM.applyEvent fsm2 create_event

      match fsm_after_create with
      | some fsm3 =>
        IO.println "Resource creation successful"

        -- Test resource read
        let read_op := ResourceOperation.read "ns-001" "resource-001"
        let read_event := TenantEvent.resource_operation "tenant-001" read_op
        let fsm_after_read := TenantFSM.applyEvent fsm3 read_event

        match fsm_after_read with
        | some fsm4 =>
          IO.println "Resource read successful"

          -- Test resource write
          let write_op := ResourceOperation.write "ns-001" "resource-001"
          let write_event := TenantEvent.resource_operation "tenant-001" write_op
          let fsm_after_write := TenantFSM.applyEvent fsm4 write_event

          match fsm_after_write with
          | some fsm5 =>
            IO.println "Resource write successful"

            -- Test resource deletion
            let delete_op := ResourceOperation.delete "ns-001" "resource-001"
            let delete_event := TenantEvent.resource_operation "tenant-001" delete_op
            let fsm_after_delete := TenantFSM.applyEvent fsm5 delete_event

            match fsm_after_delete with
            | some fsm6 =>
              IO.println "Resource deletion successful"

              -- Verify state consistency
              let consistency_proof := Tenant.Isolation.stateConsistency fsm6
              IO.println s!"State consistency proof: {consistency_proof}"

            | none => IO.println "Resource deletion failed"

          | none => IO.println "Resource write failed"

        | none => IO.println "Resource read failed"

      | none => IO.println "Resource creation failed"

    | none => IO.println "Namespace creation failed"

  | none => IO.println "Tenant creation failed"

/-- Test isolation invariants -/
def testIsolationInvariants : IO Unit := do
  IO.println "Testing isolation invariants..."

  let fsm := TenantFSM.mkEmpty

  -- Test no cross-tenant access
  let no_cross_access := IsolationInvariants.noCrossTenantAccess fsm.state
  IO.println s!"No cross-tenant access: {no_cross_access}"

  -- Test all namespaces belong to existing tenants
  let all_namespaces_valid := IsolationInvariants.allNamespacesBelongToExistingTenants fsm.state
  IO.println s!"All namespaces belong to existing tenants: {all_namespaces_valid}"

  -- Test all usage corresponds to existing namespaces
  let all_usage_valid := IsolationInvariants.allUsageCorrespondsToExistingNamespaces fsm.state
  IO.println s!"All usage corresponds to existing namespaces: {all_usage_valid}"

  -- Test all operations are by existing tenants
  let all_operations_valid := IsolationInvariants.allOperationsByExistingTenants fsm.state
  IO.println s!"All operations are by existing tenants: {all_operations_valid}"

  -- Test resource usage is within quotas
  let resource_usage_valid := IsolationInvariants.resourceUsageWithinQuotas fsm.state
  IO.println s!"Resource usage is within quotas: {resource_usage_valid}"

  -- Test combined isolation invariant
  let combined_invariant := IsolationInvariants.isolationInvariant fsm.state
  IO.println s!"Combined isolation invariant: {combined_invariant}"

/-- Test chaos scenarios -/
def testChaosScenarios : IO Unit := do
  IO.println "Testing chaos scenarios..."

  let fsm := TenantFSM.mkEmpty

  -- Simulate multiple tenants and operations
  let tenants := ["tenant-001", "tenant-002", "tenant-003", "tenant-004", "tenant-005"]
  let namespaces := ["ns-001", "ns-002", "ns-003", "ns-004", "ns-005"]

  -- Create tenants
  let mut current_fsm := fsm
  for tenant_id in tenants do
    let create_event := TenantEvent.create_tenant tenant_id s!"Test Tenant {tenant_id}"
    match TenantFSM.applyEvent current_fsm create_event with
    | some new_fsm => current_fsm := new_fsm
    | none => IO.println s!"Failed to create tenant {tenant_id}"

  -- Create namespaces
  for (tenant_id, namespace_id) in List.zip tenants namespaces do
    let create_ns_event := TenantEvent.create_namespace tenant_id namespace_id s!"Namespace {namespace_id}" ResourceType.storage (Quota.mk 10 2 4 100 10 100)
    match TenantFSM.applyEvent current_fsm create_ns_event with
    | some new_fsm => current_fsm := new_fsm
    | none => IO.println s!"Failed to create namespace {namespace_id}"

  -- Simulate random operations
  let operations := [
    ("tenant-001", "ns-001", ResourceOperation.read "ns-001" "resource-001"),
    ("tenant-002", "ns-002", ResourceOperation.write "ns-002" "resource-002"),
    ("tenant-003", "ns-003", ResourceOperation.create "ns-003" ResourceType.storage),
    ("tenant-001", "ns-002", ResourceOperation.read "ns-002" "resource-003"), -- Cross-tenant access attempt
    ("tenant-004", "ns-004", ResourceOperation.delete "ns-004" "resource-004")
  ]

  for (tenant_id, namespace_id, operation) in operations do
    let event := TenantEvent.resource_operation tenant_id operation
    match TenantFSM.applyEvent current_fsm event with
    | some new_fsm =>
      current_fsm := new_fsm
      IO.println s!"Operation successful: {tenant_id} -> {namespace_id}"
    | none =>
      IO.println s!"Operation failed: {tenant_id} -> {namespace_id}"

  -- Verify isolation maintained after chaos
  let final_invariant := IsolationInvariants.isolationInvariant current_fsm.state
  IO.println s!"Isolation maintained after chaos: {final_invariant}"

/-- Run all tenant isolation tests -/
def runAllTests : IO Unit := do
  IO.println "=== Tenant Isolation Test Suite ==="
  IO.println ""

  testBasicIsolation
  IO.println ""

  testNonInterference
  IO.println ""

  testResourceQuotas
  IO.println ""

  testNamespaceIsolation
  IO.println ""

  testStateTransitions
  IO.println ""

  testResourceOperations
  IO.println ""

  testIsolationInvariants
  IO.println ""

  testChaosScenarios
  IO.println ""

  IO.println "=== All tenant isolation tests completed ==="

/-- Main entry point -/
def main : IO Unit := runAllTests

end Tests.Tenant
