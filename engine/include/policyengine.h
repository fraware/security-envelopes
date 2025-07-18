#ifndef POLICYENGINE_H
#define POLICYENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle for PolicyEngine instance
typedef struct policyengine_t* policyengine_t;

// Error codes
#define POLICYENGINE_SUCCESS 0
#define POLICYENGINE_ERROR_INVALID_CONFIG 1
#define POLICYENGINE_ERROR_INVALID_POLICY 2
#define POLICYENGINE_ERROR_EVALUATION_FAILED 3
#define POLICYENGINE_ERROR_MEMORY_ALLOCATION 4
#define POLICYENGINE_ERROR_INVALID_PARAMETER 5
#define POLICYENGINE_ERROR_WASM_ERROR 6
#define POLICYENGINE_ERROR_CRYPTO_ERROR 7

// PolicyEngine creation and destruction
int policyengine_new(const char* config_json, policyengine_t* engine);
int policyengine_close(policyengine_t engine);

// Policy management
int policyengine_load_policy(policyengine_t engine, const char* policy_data);
int policyengine_validate_policy(policyengine_t engine, const char* policy_data);

// Policy evaluation
int policyengine_evaluate(
    policyengine_t engine,
    const char* principal_json,
    const char* scope_json,
    const char* context_json,
    char** result_json
);

// Batch evaluation
int policyengine_batch_evaluate(
    policyengine_t engine,
    const char* requests_json,
    char** results_json
);

// Statistics and monitoring
int policyengine_get_stats(policyengine_t engine, char** stats_json);
int policyengine_get_capabilities(policyengine_t engine, char** capabilities_json);

// Configuration
int policyengine_set_log_level(policyengine_t engine, const char* level);

// Version information
const char* policyengine_get_version(void);

// Memory management for JSON strings
void policyengine_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif // POLICYENGINE_H 