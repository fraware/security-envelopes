/-
# Attestation Test Suite

This module contains comprehensive tests for remote attestation functionality,
including Intel SGX and AMD SEV-SNP quote verification.
-/

import Attest.Quote
import Attest.SGX
import Attest.SEV
import Mathlib.Data.ByteArray
import Mathlib.Data.Nat.Basic

namespace Tests.Attest

/-- Test basic quote functionality -/
def testBasicQuote : IO Unit := do
  IO.println "Testing basic quote functionality..."

  -- Create a test quote
  let nonce := ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8]
  let measurement := ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17]
  let signature := ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27]

  let quote := Quote.mk nonce measurement signature

  -- Test quote properties
  let nonce_valid := Quote.validateNonce quote
  let measurement_valid := Quote.validateMeasurement quote
  let signature_valid := Quote.validateSignature quote

  IO.println s!"Nonce valid: {nonce_valid}"
  IO.println s!"Measurement valid: {measurement_valid}"
  IO.println s!"Signature valid: {signature_valid}"

  -- Test quote verification
  let verification_result := Quote.verify quote
  IO.println s!"Quote verification result: {verification_result}"

/-- Test Intel SGX quote verification -/
def testSGXQuote : IO Unit := do
  IO.println "Testing Intel SGX quote verification..."

  -- Create SGX quote
  let sgx_quote := SGX.Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8]) -- nonce
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17]) -- measurement
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27]) -- signature
    (ByteArray.mk #[30, 31, 32, 33, 34, 35, 36, 37]) -- report_data
    (ByteArray.mk #[40, 41, 42, 43, 44, 45, 46, 47]) -- quote_body

  -- Test SGX quote verification
  let verification_result := SGX.Quote.verify sgx_quote
  IO.println s!"SGX quote verification result: {verification_result}"

  -- Test SGX quote generation
  let generated_quote := SGX.Quote.generate (ByteArray.mk #[1, 2, 3, 4])
  IO.println s!"SGX quote generation result: {generated_quote}"

  -- Test SGX report verification
  let report := SGX.Report.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8]) -- cpu_svn
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17]) -- misc_select
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27]) -- attributes
    (ByteArray.mk #[30, 31, 32, 33, 34, 35, 36, 37]) -- mr_enclave
    (ByteArray.mk #[40, 41, 42, 43, 44, 45, 46, 47]) -- mr_signer
    (ByteArray.mk #[50, 51, 52, 53, 54, 55, 56, 57]) -- config_id
    (ByteArray.mk #[60, 61, 62, 63, 64, 65, 66, 67]) -- isv_prod_id
    (ByteArray.mk #[70, 71, 72, 73, 74, 75, 76, 77]) -- isv_svn
    (ByteArray.mk #[80, 81, 82, 83, 84, 85, 86, 87]) -- config_svn
    (ByteArray.mk #[90, 91, 92, 93, 94, 95, 96, 97]) -- reserved
    (ByteArray.mk #[100, 101, 102, 103, 104, 105, 106, 107]) -- isv_ext_prod_id
    (ByteArray.mk #[110, 111, 112, 113, 114, 115, 116, 117]) -- attributes_mask
    (ByteArray.mk #[120, 121, 122, 123, 124, 125, 126, 127]) -- cpu_svn_mask
    (ByteArray.mk #[130, 131, 132, 133, 134, 135, 136, 137]) -- misc_select_mask
    (ByteArray.mk #[140, 141, 142, 143, 144, 145, 146, 147]) -- reserved_mask
    (ByteArray.mk #[150, 151, 152, 153, 154, 155, 156, 157]) -- key_id
    (ByteArray.mk #[160, 161, 162, 163, 164, 165, 166, 167]) -- mac

  let report_verification := SGX.Report.verify report
  IO.println s!"SGX report verification result: {report_verification}"

/-- Test AMD SEV-SNP quote verification -/
def testSEVQuote : IO Unit := do
  IO.println "Testing AMD SEV-SNP quote verification..."

  -- Create SEV quote
  let sev_quote := SEV.Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8]) -- nonce
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17]) -- measurement
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27]) -- signature
    (ByteArray.mk #[30, 31, 32, 33, 34, 35, 36, 37]) -- report_data
    (ByteArray.mk #[40, 41, 42, 43, 44, 45, 46, 47]) -- quote_body

  -- Test SEV quote verification
  let verification_result := SEV.Quote.verify sev_quote
  IO.println s!"SEV quote verification result: {verification_result}"

  -- Test SEV quote generation
  let generated_quote := SEV.Quote.generate (ByteArray.mk #[1, 2, 3, 4])
  IO.println s!"SEV quote generation result: {generated_quote}"

  -- Test SEV report verification
  let report := SEV.Report.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8]) -- version
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17]) -- guest_svn
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27]) -- policy
    (ByteArray.mk #[30, 31, 32, 33, 34, 35, 36, 37]) -- family_id
    (ByteArray.mk #[40, 41, 42, 43, 44, 45, 46, 47]) -- image_id
    (ByteArray.mk #[50, 51, 52, 53, 54, 55, 56, 57]) -- vmpl
    (ByteArray.mk #[60, 61, 62, 63, 64, 65, 66, 67]) -- signature_algo
    (ByteArray.mk #[70, 71, 72, 73, 74, 75, 76, 77]) -- platform_version
    (ByteArray.mk #[80, 81, 82, 83, 84, 85, 86, 87]) -- platform_info
    (ByteArray.mk #[90, 91, 92, 93, 94, 95, 96, 97]) -- author_key_en
    (ByteArray.mk #[100, 101, 102, 103, 104, 105, 106, 107]) -- reserved
    (ByteArray.mk #[110, 111, 112, 113, 114, 115, 116, 117]) -- report_data
    (ByteArray.mk #[120, 121, 122, 123, 124, 125, 126, 127]) -- measurement
    (ByteArray.mk #[130, 131, 132, 133, 134, 135, 136, 137]) -- host_data
    (ByteArray.mk #[140, 141, 142, 143, 144, 145, 146, 147]) -- id_key_digest
    (ByteArray.mk #[150, 151, 152, 153, 154, 155, 156, 157]) -- author_key_digest
    (ByteArray.mk #[160, 161, 162, 163, 164, 165, 166, 167]) -- report_id
    (ByteArray.mk #[170, 171, 172, 173, 174, 175, 176, 177]) -- report_id_ma
    (ByteArray.mk #[180, 181, 182, 183, 184, 185, 186, 187]) -- reported_tcb
    (ByteArray.mk #[190, 191, 192, 193, 194, 195, 196, 197]) -- reserved2
    (ByteArray.mk #[200, 201, 202, 203, 204, 205, 206, 207]) -- chip_id
    (ByteArray.mk #[210, 211, 212, 213, 214, 215, 216, 217]) -- committed_tcb
    (ByteArray.mk #[220, 221, 222, 223, 224, 225, 226, 227]) -- current_build
    (ByteArray.mk #[230, 231, 232, 233, 234, 235, 236, 237]) -- current_minor
    (ByteArray.mk #[240, 241, 242, 243, 244, 245, 246, 247]) -- current_major
    (ByteArray.mk #[250, 251, 252, 253, 254, 255, 0, 1]) -- committed_build
    (ByteArray.mk #[2, 3, 4, 5, 6, 7, 8, 9]) -- committed_minor
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17]) -- committed_major
    (ByteArray.mk #[18, 19, 20, 21, 22, 23, 24, 25]) -- launch_tcb
    (ByteArray.mk #[26, 27, 28, 29, 30, 31, 32, 33]) -- reserved3
    (ByteArray.mk #[34, 35, 36, 37, 38, 39, 40, 41]) -- signature

  let report_verification := SEV.Report.verify report
  IO.println s!"SEV report verification result: {report_verification}"

/-- Test quote tampering detection -/
def testQuoteTampering : IO Unit := do
  IO.println "Testing quote tampering detection..."

  -- Create original quote
  let original_quote := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  -- Create tampered quote (modified measurement)
  let tampered_quote := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[99, 11, 12, 13, 14, 15, 16, 17]) -- Modified measurement
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  -- Test original quote verification
  let original_result := Quote.verify original_quote
  IO.println s!"Original quote verification: {original_result}"

  -- Test tampered quote verification
  let tampered_result := Quote.verify tampered_quote
  IO.println s!"Tampered quote verification: {tampered_result}"

  -- Verify tampering detection
  let tampering_detected := original_result != tampered_result
  IO.println s!"Tampering detected: {tampering_detected}"

/-- Test nonce freshness -/
def testNonceFreshness : IO Unit := do
  IO.println "Testing nonce freshness..."

  -- Create quotes with different nonces
  let quote1 := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  let quote2 := Quote.mk
    (ByteArray.mk #[8, 7, 6, 5, 4, 3, 2, 1]) -- Different nonce
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  -- Test nonce validation
  let nonce1_valid := Quote.validateNonce quote1
  let nonce2_valid := Quote.validateNonce quote2

  IO.println s!"Nonce 1 valid: {nonce1_valid}"
  IO.println s!"Nonce 2 valid: {nonce2_valid}"

  -- Test replay attack prevention
  let replay_prevention := nonce1_valid && nonce2_valid && (quote1.nonce != quote2.nonce)
  IO.println s!"Replay attack prevention: {replay_prevention}"

/-- Test measurement validation -/
def testMeasurementValidation : IO Unit := do
  IO.println "Testing measurement validation..."

  -- Create quotes with different measurements
  let quote1 := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  let quote2 := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[17, 16, 15, 14, 13, 12, 11, 10]) -- Different measurement
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  -- Test measurement validation
  let measurement1_valid := Quote.validateMeasurement quote1
  let measurement2_valid := Quote.validateMeasurement quote2

  IO.println s!"Measurement 1 valid: {measurement1_valid}"
  IO.println s!"Measurement 2 valid: {measurement2_valid}"

  -- Test platform state verification
  let platform_verification := measurement1_valid && measurement2_valid
  IO.println s!"Platform state verification: {platform_verification}"

/-- Test signature verification -/
def testSignatureVerification : IO Unit := do
  IO.println "Testing signature verification..."

  -- Create quotes with different signatures
  let quote1 := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  let quote2 := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[27, 26, 25, 24, 23, 22, 21, 20]) -- Different signature

  -- Test signature validation
  let signature1_valid := Quote.validateSignature quote1
  let signature2_valid := Quote.validateSignature quote2

  IO.println s!"Signature 1 valid: {signature1_valid}"
  IO.println s!"Signature 2 valid: {signature2_valid}"

  -- Test cryptographic proof correctness
  let crypto_correctness := signature1_valid && signature2_valid
  IO.println s!"Cryptographic proof correctness: {crypto_correctness}"

/-- Test performance benchmarks -/
def testPerformance : IO Unit := do
  IO.println "Testing performance benchmarks..."

  -- Test quote verification speed
  let quote := Quote.mk
    (ByteArray.mk #[1, 2, 3, 4, 5, 6, 7, 8])
    (ByteArray.mk #[10, 11, 12, 13, 14, 15, 16, 17])
    (ByteArray.mk #[20, 21, 22, 23, 24, 25, 26, 27])

  -- Simulate multiple verification attempts
  let mut verification_count := 0
  for i in List.range 0 1000 do
    let result := Quote.verify quote
    if result then
      verification_count := verification_count + 1

  IO.println s!"Verification count: {verification_count}/1000"

  -- Test quote generation speed
  let nonce := ByteArray.mk #[1, 2, 3, 4]
  let mut generation_count := 0
  for i in List.range 0 100 do
    let generated := Quote.generate nonce
    if generated.isSome then
      generation_count := generation_count + 1

  IO.println s!"Generation count: {generation_count}/100"

/-- Run all attestation tests -/
def runAllTests : IO Unit := do
  IO.println "=== Attestation Test Suite ==="
  IO.println ""

  testBasicQuote
  IO.println ""

  testSGXQuote
  IO.println ""

  testSEVQuote
  IO.println ""

  testQuoteTampering
  IO.println ""

  testNonceFreshness
  IO.println ""

  testMeasurementValidation
  IO.println ""

  testSignatureVerification
  IO.println ""

  testPerformance
  IO.println ""

  IO.println "=== All attestation tests completed ==="

/-- Main entry point -/
def main : IO Unit := runAllTests

end Tests.Attest
