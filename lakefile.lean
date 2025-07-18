import Lake
open Lake DSL

package security_envelopes {
  -- add package configuration options here
  srcDir := "Spec"
}

@[default_target]
lean_lib SecurityEnvelopes {
  roots := #[`RBAC, `Tenant, `Attest]
}

-- RBAC Core Library
lean_lib RBAC {
  roots := #[`RBAC.Core, `RBAC.Proofs, `RBAC.ABAC]
}

-- Multi-Tenant Isolation Library
lean_lib Tenant {
  roots := #[`Tenant.FSM, `Tenant.Isolation, `Tenant.Integration]
}

-- Remote Attestation Library
lean_lib Attest {
  roots := #[`Attest.Quote, `Attest.SGX, `Attest.SEV]
}

-- Test suites
lean_exe test_rbac {
  root := `Tests.RBAC
}

lean_exe test_tenant {
  root := `Tests.Tenant
}

lean_exe test_attest {
  root := `Tests.Attest
}

-- Benchmark executables
lean_exe bench_rbac {
  root := `Benchmarks.RBAC
}

lean_exe bench_attest {
  root := `Benchmarks.Attest
}

-- Documentation generation
lean_exe docs {
  root := `Docs.Generator
}

-- Dependencies
require lean_toolchain from git "https://github.com/leanprover/lean4.git" @ "v4.0.0-m4"
require runtime_safety_kernels from git "https://github.com/runtime-safety-kernels/runtime-safety-kernels.git" @ "main"

-- Development dependencies
require aesop from git "https://github.com/JLimperg/aesop" @ "main"
require mathlib from git "https://github.com/leanprover-community/mathlib4.git" @ "main"

-- Scripts
script test do
  let testArgs := #["RBAC", "Tenant", "Attest"]
  for testArg in testArgs do
    IO.println s!"Running {testArg} tests..."
    let exitCode ← proc {
      cmd := "lake"
      args := #["exe", s!"test_{testArg.toLower}"]
    }.run
    if exitCode != 0 then
      IO.println s!"{testArg} tests failed with exit code {exitCode}"
      return exitCode
  IO.println "All tests passed!"
  return 0

script bench do
  IO.println "Running RBAC benchmarks..."
  let _ ← proc {
    cmd := "lake"
    args := #["exe", "bench_rbac"]
  }.run
  IO.println "Running attestation benchmarks..."
  let _ ← proc {
    cmd := "lake"
    args := #["exe", "bench_attest"]
  }.run
  IO.println "Benchmarks completed!"

script docs do
  IO.println "Generating documentation..."
  let _ ← proc {
    cmd := "lake"
    args := #["exe", "docs"]
  }.run
  IO.println "Documentation generated!"

script ci do
  IO.println "Running CI pipeline..."
  let steps := #[
    ("Building", "lake build"),
    ("Testing", "lake run test"),
    ("Benchmarking", "lake run bench"),
    ("Documentation", "lake run docs")
  ]
  for (name, cmd) in steps do
    IO.println s!"Step: {name}"
    let exitCode ← proc {
      cmd := "bash"
      args := #["-c", cmd]
    }.run
    if exitCode != 0 then
      IO.println s!"CI step '{name}' failed with exit code {exitCode}"
      return exitCode
  IO.println "CI pipeline completed successfully!"
  return 0
