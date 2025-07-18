# Scripts Directory

This directory contains utility scripts for the Security Envelopes project.

## Policy Linter

The `policy_lint.py` script validates YAML policy files for structural correctness, security properties, and compliance with the Security Envelopes format.

### Usage

```bash
# Lint all policy files in examples directory
python scripts/policy_lint.py examples/*/policy.yaml

# Lint specific files
python scripts/policy_lint.py examples/01_simple_rbac/policy.yaml

# Strict mode (treats warnings as errors)
python scripts/policy_lint.py examples/*/policy.yaml --strict
```

### Features

- **YAML Syntax Validation**: Ensures valid YAML structure
- **Policy Structure Validation**: Checks required fields and format
- **Security Property Validation**: Identifies potential security issues
- **Role and Permission Validation**: Validates RBAC structure
- **Assignment Validation**: Ensures proper role assignments
- **Metadata Validation**: Checks policy metadata completeness

### Policy Format

The linter expects policies to follow this structure:

```yaml
version: "1.0"
metadata:
  name: "Policy Name"
  description: "Policy description"
  author: "Author Name"
  created: "2024-01-01T00:00:00Z"

roles:
  - name: "role_name"
    permissions:
      - action: "allow" | "deny"
        scope:
          resource: "resource_name"
          path: ["action1", "action2"]

assignments:
  - principal: "user_id"
    role: "role_name"
    attributes:
      key: "value"
```

### Error Types

- **Errors**: Critical issues that must be fixed
- **Warnings**: Best practice recommendations

### Integration

The policy linter is integrated into the CI/CD pipeline via `.github/workflows/policy-lint.yml` and runs on every push and pull request.
