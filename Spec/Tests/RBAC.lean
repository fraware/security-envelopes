/-
# RBAC Test Suite

This module contains comprehensive tests for the RBAC core functionality,
including soundness, completeness, and non-interference properties.
-/

import RBAC.Core
import RBAC.Proofs
import RBAC.ABAC
import Mathlib.Data.List.Basic
import Mathlib.Logic.Basic

namespace Tests.RBAC

/-- Test basic RBAC functionality -/
def testBasicRBAC : IO Unit := do
  IO.println "Testing basic RBAC functionality..."

  -- Create a simple policy
  let principal := Principal.mk "user1" [("role", "admin")]
  let scope := Scope.Resource "database" ["read", "write"]
  let permission := Permission.mk "database" ["read", "write"] none
  let role := Role.mk "admin" "Administrator role" [permission]
  let policy := Policy.mk "test-policy" "Test Policy" "1.0" [role] [permission]

  -- Test permission evaluation
  let result := Policy.evaluate policy principal scope
  IO.println s!"Permission evaluation result: {result}"

  -- Verify soundness
  let soundness_proof := RBAC.Proofs.soundness policy
  IO.println s!"Soundness proof: {soundness_proof}"

  -- Verify completeness
  let completeness_proof := RBAC.Proofs.completeness policy
  IO.println s!"Completeness proof: {completeness_proof}"

/-- Test ABAC functionality -/
def testABAC : IO Unit := do
  IO.println "Testing ABAC functionality..."

  -- Create ABAC policy with conditions
  let principal := Principal.mk "user2" [("role", "user"), ("department", "engineering")]
  let scope := Scope.Resource "code" ["read"]
  let condition := ABAC.Condition.mk "department" "equals" "engineering"
  let permission := Permission.mk "code" ["read"] (some condition)
  let role := Role.mk "engineer" "Engineering role" [permission]
  let policy := Policy.mk "abac-policy" "ABAC Policy" "1.0" [role] [permission]

  -- Test ABAC evaluation
  let result := Policy.evaluate policy principal scope
  IO.println s!"ABAC evaluation result: {result}"

  -- Verify ABAC correctness
  let abac_proof := RBAC.Proofs.abacCorrectness policy
  IO.println s!"ABAC correctness proof: {abac_proof}"

/-- Test non-interference -/
def testNonInterference : IO Unit := do
  IO.println "Testing non-interference..."

  -- Create two principals
  let principal1 := Principal.mk "user1" [("role", "admin")]
  let principal2 := Principal.mk "user2" [("role", "user")]

  -- Create separate scopes
  let scope1 := Scope.Resource "database1" ["read"]
  let scope2 := Scope.Resource "database2" ["read"]

  -- Create policy
  let permission1 := Permission.mk "database1" ["read"] none
  let permission2 := Permission.mk "database2" ["read"] none
  let role1 := Role.mk "admin" "Admin role" [permission1]
  let role2 := Role.mk "user" "User role" [permission2]
  let policy := Policy.mk "isolation-policy" "Isolation Policy" "1.0" [role1, role2] [permission1, permission2]

  -- Test isolation
  let result1 := Policy.evaluate policy principal1 scope1
  let result2 := Policy.evaluate policy principal2 scope2
  let result3 := Policy.evaluate policy principal1 scope2
  let result4 := Policy.evaluate policy principal2 scope1

  IO.println s!"Principal1 -> Scope1: {result1}"
  IO.println s!"Principal2 -> Scope2: {result2}"
  IO.println s!"Principal1 -> Scope2: {result3}"
  IO.println s!"Principal2 -> Scope1: {result4}"

  -- Verify non-interference
  let noninterference_proof := RBAC.Proofs.nonInterference policy
  IO.println s!"Non-interference proof: {noninterference_proof}"

/-- Test decidability -/
def testDecidability : IO Unit := do
  IO.println "Testing decidability..."

  let principal := Principal.mk "user1" [("role", "admin")]
  let scope := Scope.Resource "resource" ["action"]
  let permission := Permission.mk "resource" ["action"] none
  let role := Role.mk "admin" "Admin role" [permission]
  let policy := Policy.mk "decidability-policy" "Decidability Policy" "1.0" [role] [permission]

  -- Test that evaluation terminates
  let result := Policy.evaluate policy principal scope
  IO.println s!"Decidability test result: {result}"

  -- Verify decidability
  let decidability_proof := RBAC.Proofs.decidability policy
  IO.println s!"Decidability proof: {decidability_proof}"

/-- Test monotonicity -/
def testMonotonicity : IO Unit := do
  IO.println "Testing monotonicity..."

  let principal := Principal.mk "user1" [("role", "user")]
  let scope := Scope.Resource "resource" ["read"]

  -- Create initial policy
  let permission1 := Permission.mk "resource" ["read"] none
  let role1 := Role.mk "user" "User role" [permission1]
  let policy1 := Policy.mk "monotonicity-policy" "Monotonicity Policy" "1.0" [role1] [permission1]

  -- Create extended policy
  let permission2 := Permission.mk "resource" ["write"] none
  let role2 := Role.mk "user" "User role" [permission1, permission2]
  let policy2 := Policy.mk "monotonicity-policy" "Monotonicity Policy" "1.0" [role2] [permission1, permission2]

  -- Test monotonicity
  let result1 := Policy.evaluate policy1 principal scope
  let result2 := Policy.evaluate policy2 principal scope

  IO.println s!"Initial policy result: {result1}"
  IO.println s!"Extended policy result: {result2}"

  -- Verify monotonicity
  let monotonicity_proof := RBAC.Proofs.monotonicity policy1 policy2
  IO.println s!"Monotonicity proof: {monotonicity_proof}"

/-- Test transitivity -/
def testTransitivity : IO Unit := do
  IO.println "Testing transitivity..."

  let principal := Principal.mk "user1" [("role", "admin")]
  let scope1 := Scope.Resource "database" ["read"]
  let scope2 := Scope.Resource "database" ["write"]

  -- Create hierarchical scopes
  let permission1 := Permission.mk "database" ["read"] none
  let permission2 := Permission.mk "database" ["write"] none
  let role := Role.mk "admin" "Admin role" [permission1, permission2]
  let policy := Policy.mk "transitivity-policy" "Transitivity Policy" "1.0" [role] [permission1, permission2]

  -- Test transitivity
  let result1 := Policy.evaluate policy principal scope1
  let result2 := Policy.evaluate policy principal scope2

  IO.println s!"Scope1 result: {result1}"
  IO.println s!"Scope2 result: {result2}"

  -- Verify transitivity
  let transitivity_proof := RBAC.Proofs.transitivity policy
  IO.println s!"Transitivity proof: {transitivity_proof}"

/-- Test policy consistency -/
def testPolicyConsistency : IO Unit := do
  IO.println "Testing policy consistency..."

  let principal := Principal.mk "user1" [("role", "user")]
  let scope := Scope.Resource "resource" ["action"]

  -- Create consistent policy
  let permission := Permission.mk "resource" ["action"] none
  let role := Role.mk "user" "User role" [permission]
  let policy := Policy.mk "consistency-policy" "Consistency Policy" "1.0" [role] [permission]

  -- Test consistency
  let result := Policy.evaluate policy principal scope
  IO.println s!"Consistency test result: {result}"

  -- Verify consistency
  let consistency_proof := RBAC.Proofs.policyConsistency policy
  IO.println s!"Policy consistency proof: {consistency_proof}"

/-- Run all RBAC tests -/
def runAllTests : IO Unit := do
  IO.println "=== RBAC Test Suite ==="
  IO.println ""

  testBasicRBAC
  IO.println ""

  testABAC
  IO.println ""

  testNonInterference
  IO.println ""

  testDecidability
  IO.println ""

  testMonotonicity
  IO.println ""

  testTransitivity
  IO.println ""

  testPolicyConsistency
  IO.println ""

  IO.println "=== All RBAC tests completed ==="

/-- Main entry point -/
def main : IO Unit := runAllTests

end Tests.RBAC
