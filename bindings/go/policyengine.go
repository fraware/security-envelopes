// Package policyengine provides Go bindings for the Security Envelopes PolicyEngine
//
// This package allows Go applications to use the formally verified PolicyEngine
// for RBAC/ABAC policy evaluation with WASM runtime support.
package policyengine

/*
#cgo CFLAGS: -I${SRCDIR}/../../engine/include
#cgo LDFLAGS: -L${SRCDIR}/../../engine/target/release -lpolicyengine
#include <policyengine.h>
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// PolicyEngine represents a PolicyEngine instance
type PolicyEngine struct {
	handle C.policyengine_t
}

// Principal represents a user or service principal
type Principal struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
}

// Scope represents a resource or action scope
type Scope struct {
	Type string   `json:"type"`
	Name string   `json:"name"`
	Path []string `json:"path"`
}

// Permission represents an access permission
type Permission struct {
	Resource   string            `json:"resource"`
	Actions    []string          `json:"actions"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// Policy represents a complete policy definition
type Policy struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Roles       []Role       `json:"roles"`
	Permissions []Permission `json:"permissions"`
}

// Role represents a role with permissions
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// EvaluationResult represents the result of a policy evaluation
type EvaluationResult struct {
	Allowed    bool                   `json:"allowed"`
	Reason     string                 `json:"reason"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Config represents PolicyEngine configuration
type Config struct {
	WasmPath    string            `json:"wasm_path"`
	LogLevel    string            `json:"log_level"`
	MaxMemory   int64             `json:"max_memory"`
	Timeout     int64             `json:"timeout"`
	Environment map[string]string `json:"environment"`
}

// New creates a new PolicyEngine instance
func New(config Config) (*PolicyEngine, error) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	configStr := C.CString(string(configJSON))
	defer C.free(unsafe.Pointer(configStr))

	var handle C.policyengine_t
	result := C.policyengine_new(configStr, &handle)
	if result != 0 {
		return nil, fmt.Errorf("failed to create PolicyEngine: error code %d", result)
	}

	return &PolicyEngine{handle: handle}, nil
}

// LoadPolicy loads a policy from YAML or JSON
func (pe *PolicyEngine) LoadPolicy(policyData []byte) error {
	policyStr := C.CString(string(policyData))
	defer C.free(unsafe.Pointer(policyStr))

	result := C.policyengine_load_policy(pe.handle, policyStr)
	if result != 0 {
		return fmt.Errorf("failed to load policy: error code %d", result)
	}

	return nil
}

// Evaluate evaluates a policy for a principal and scope
func (pe *PolicyEngine) Evaluate(principal Principal, scope Scope, context map[string]interface{}) (*EvaluationResult, error) {
	// Marshal principal
	principalJSON, err := json.Marshal(principal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal principal: %w", err)
	}

	// Marshal scope
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scope: %w", err)
	}

	// Marshal context
	contextJSON, err := json.Marshal(context)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal context: %w", err)
	}

	// Convert to C strings
	principalStr := C.CString(string(principalJSON))
	defer C.free(unsafe.Pointer(principalStr))

	scopeStr := C.CString(string(scopeJSON))
	defer C.free(unsafe.Pointer(scopeStr))

	contextStr := C.CString(string(contextJSON))
	defer C.free(unsafe.Pointer(contextStr))

	// Allocate result buffer
	var resultBuffer *C.char
	defer C.free(unsafe.Pointer(resultBuffer))

	// Evaluate policy
	result := C.policyengine_evaluate(pe.handle, principalStr, scopeStr, contextStr, &resultBuffer)
	if result != 0 {
		return nil, fmt.Errorf("policy evaluation failed: error code %d", result)
	}

	// Parse result
	resultStr := C.GoString(resultBuffer)
	var evalResult EvaluationResult
	if err := json.Unmarshal([]byte(resultStr), &evalResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal evaluation result: %w", err)
	}

	return &evalResult, nil
}

// CanAccess checks if a principal can access a resource
func (pe *PolicyEngine) CanAccess(principal Principal, resource string, action string) (bool, error) {
	scope := Scope{
		Type: "resource",
		Name: resource,
		Path: []string{action},
	}

	result, err := pe.Evaluate(principal, scope, nil)
	if err != nil {
		return false, err
	}

	return result.Allowed, nil
}

// GetStats returns PolicyEngine statistics
func (pe *PolicyEngine) GetStats() (map[string]interface{}, error) {
	var statsBuffer *C.char
	defer C.free(unsafe.Pointer(statsBuffer))

	result := C.policyengine_get_stats(pe.handle, &statsBuffer)
	if result != 0 {
		return nil, fmt.Errorf("failed to get stats: error code %d", result)
	}

	statsStr := C.GoString(statsBuffer)
	var stats map[string]interface{}
	if err := json.Unmarshal([]byte(statsStr), &stats); err != nil {
		return nil, fmt.Errorf("failed to unmarshal stats: %w", err)
	}

	return stats, nil
}

// ValidatePolicy validates a policy without loading it
func (pe *PolicyEngine) ValidatePolicy(policyData []byte) error {
	policyStr := C.CString(string(policyData))
	defer C.free(unsafe.Pointer(policyStr))

	result := C.policyengine_validate_policy(pe.handle, policyStr)
	if result != 0 {
		return fmt.Errorf("policy validation failed: error code %d", result)
	}

	return nil
}

// Close closes the PolicyEngine instance
func (pe *PolicyEngine) Close() error {
	result := C.policyengine_close(pe.handle)
	if result != 0 {
		return fmt.Errorf("failed to close PolicyEngine: error code %d", result)
	}

	return nil
}

// BatchEvaluate evaluates multiple policies in batch
func (pe *PolicyEngine) BatchEvaluate(requests []EvaluationRequest) ([]EvaluationResult, error) {
	requestsJSON, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal requests: %w", err)
	}

	requestsStr := C.CString(string(requestsJSON))
	defer C.free(unsafe.Pointer(requestsStr))

	var resultsBuffer *C.char
	defer C.free(unsafe.Pointer(resultsBuffer))

	result := C.policyengine_batch_evaluate(pe.handle, requestsStr, &resultsBuffer)
	if result != 0 {
		return nil, fmt.Errorf("batch evaluation failed: error code %d", result)
	}

	resultsStr := C.GoString(resultsBuffer)
	var results []EvaluationResult
	if err := json.Unmarshal([]byte(resultsStr), &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal batch results: %w", err)
	}

	return results, nil
}

// EvaluationRequest represents a single evaluation request for batch processing
type EvaluationRequest struct {
	Principal Principal              `json:"principal"`
	Scope     Scope                  `json:"scope"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// SetLogLevel sets the logging level
func (pe *PolicyEngine) SetLogLevel(level string) error {
	levelStr := C.CString(level)
	defer C.free(unsafe.Pointer(levelStr))

	result := C.policyengine_set_log_level(pe.handle, levelStr)
	if result != 0 {
		return fmt.Errorf("failed to set log level: error code %d", result)
	}

	return nil
}

// GetVersion returns the PolicyEngine version
func GetVersion() string {
	version := C.policyengine_get_version()
	return C.GoString(version)
}

// GetCapabilities returns the PolicyEngine capabilities
func (pe *PolicyEngine) GetCapabilities() (map[string]interface{}, error) {
	var capabilitiesBuffer *C.char
	defer C.free(unsafe.Pointer(capabilitiesBuffer))

	result := C.policyengine_get_capabilities(pe.handle, &capabilitiesBuffer)
	if result != 0 {
		return nil, fmt.Errorf("failed to get capabilities: error code %d", result)
	}

	capabilitiesStr := C.GoString(capabilitiesBuffer)
	var capabilities map[string]interface{}
	if err := json.Unmarshal([]byte(capabilitiesStr), &capabilities); err != nil {
		return nil, fmt.Errorf("failed to unmarshal capabilities: %w", err)
	}

	return capabilities, nil
}
