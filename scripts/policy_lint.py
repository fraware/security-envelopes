#!/usr/bin/env python3
"""
Policy Linter for Security Envelopes

This script validates YAML policy files for structural correctness,
security properties, and compliance with the Security Envelopes format.
"""

import sys
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
import re
from datetime import datetime


class PolicyLinter:
    """Linter for Security Envelopes policy files"""

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.passed = 0

    def lint_file(self, file_path: Path) -> bool:
        """Lint a single policy file"""
        print(f"Linting {file_path}...")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse YAML
            try:
                policy = yaml.safe_load(content)
            except yaml.YAMLError as e:
                self.errors.append(f"{file_path}: YAML parsing error: {e}")
                return False

            if not policy:
                self.errors.append(f"{file_path}: Empty policy file")
                return False

            # Validate structure
            self._validate_structure(file_path, policy)

            # Validate metadata
            self._validate_metadata(file_path, policy)

            # Validate roles
            self._validate_roles(file_path, policy)

            # Validate assignments
            self._validate_assignments(file_path, policy)

            # Validate security properties
            self._validate_security_properties(file_path, policy)

            if not self.errors:
                self.passed += 1
                print(f"✓ {file_path} - PASSED")
                return True
            else:
                print(f"✗ {file_path} - FAILED")
                return False

        except Exception as e:
            self.errors.append(f"{file_path}: Unexpected error: {e}")
            print(f"✗ {file_path} - ERROR")
            return False

    def _validate_structure(self, file_path: Path, policy: Dict[str, Any]):
        """Validate basic policy structure"""
        required_fields = ["version", "metadata", "roles"]
        for field in required_fields:
            if field not in policy:
                self.errors.append(f"{file_path}: Missing required field '{field}'")

    def _validate_metadata(self, file_path: Path, policy: Dict[str, Any]):
        """Validate metadata section"""
        metadata = policy.get("metadata", {})

        required_metadata = ["name", "description", "author"]
        for field in required_metadata:
            if field not in metadata:
                self.errors.append(f"{file_path}: Missing required metadata '{field}'")

        # Validate created date if present
        if "created" in metadata:
            try:
                datetime.fromisoformat(metadata["created"].replace("Z", "+00:00"))
            except ValueError:
                self.errors.append(f"{file_path}: Invalid created date format")

    def _validate_roles(self, file_path: Path, policy: Dict[str, Any]):
        """Validate roles section"""
        roles = policy.get("roles", [])

        if not roles:
            self.errors.append(f"{file_path}: No roles defined")
            return

        role_names = set()
        for i, role in enumerate(roles):
            if not isinstance(role, dict):
                self.errors.append(f"{file_path}: Role {i} is not a dictionary")
                continue

            # Validate role name
            if "name" not in role:
                self.errors.append(f"{file_path}: Role {i} missing name")
                continue

            role_name = role["name"]
            if not isinstance(role_name, str) or not role_name.strip():
                self.errors.append(f"{file_path}: Role {i} has invalid name")
                continue

            if role_name in role_names:
                self.errors.append(f"{file_path}: Duplicate role name '{role_name}'")
            role_names.add(role_name)

            # Validate permissions
            permissions = role.get("permissions", [])
            if not permissions:
                self.warnings.append(
                    f"{file_path}: Role '{role_name}' has no permissions"
                )
                continue

            for j, permission in enumerate(permissions):
                self._validate_permission(file_path, role_name, j, permission)

    def _validate_permission(
        self, file_path: Path, role_name: str, perm_idx: int, permission: Dict[str, Any]
    ):
        """Validate a single permission"""
        if not isinstance(permission, dict):
            self.errors.append(
                f"{file_path}: Permission {perm_idx} in role '{role_name}' is not a dictionary"
            )
            return

        # Validate action
        if "action" not in permission:
            self.errors.append(
                f"{file_path}: Permission {perm_idx} in role '{role_name}' missing action"
            )
            return

        action = permission["action"]
        if action not in ["allow", "deny"]:
            self.errors.append(
                f"{file_path}: Permission {perm_idx} in role '{role_name}' has invalid action '{action}'"
            )

        # Validate scope
        if "scope" not in permission:
            self.errors.append(
                f"{file_path}: Permission {perm_idx} in role '{role_name}' missing scope"
            )
            return

        scope = permission["scope"]
        if not isinstance(scope, dict):
            self.errors.append(
                f"{file_path}: Permission {perm_idx} in role '{role_name}' has invalid scope"
            )
            return

        # Validate scope fields
        if "resource" not in scope and "action" not in scope:
            self.errors.append(
                f"{file_path}: Permission {perm_idx} in role '{role_name}' scope missing resource or action"
            )

        # Validate path if present
        if "path" in scope:
            path = scope["path"]
            if not isinstance(path, list):
                self.errors.append(
                    f"{file_path}: Permission {perm_idx} in role '{role_name}' path is not a list"
                )
            elif not all(isinstance(p, str) for p in path):
                self.errors.append(
                    f"{file_path}: Permission {perm_idx} in role '{role_name}' path contains non-string elements"
                )

    def _validate_assignments(self, file_path: Path, policy: Dict[str, Any]):
        """Validate assignments section"""
        assignments = policy.get("assignments", [])

        if not assignments:
            self.warnings.append(f"{file_path}: No role assignments defined")
            return

        # Get defined roles
        defined_roles = {role["name"] for role in policy.get("roles", [])}

        for i, assignment in enumerate(assignments):
            if not isinstance(assignment, dict):
                self.errors.append(f"{file_path}: Assignment {i} is not a dictionary")
                continue

            # Validate principal
            if "principal" not in assignment:
                self.errors.append(f"{file_path}: Assignment {i} missing principal")
                continue

            principal = assignment["principal"]
            if not isinstance(principal, str) or not principal.strip():
                self.errors.append(f"{file_path}: Assignment {i} has invalid principal")

            # Validate role
            if "role" not in assignment:
                self.errors.append(f"{file_path}: Assignment {i} missing role")
                continue

            role = assignment["role"]
            if not isinstance(role, str) or not role.strip():
                self.errors.append(f"{file_path}: Assignment {i} has invalid role")
            elif role not in defined_roles:
                self.errors.append(
                    f"{file_path}: Assignment {i} references undefined role '{role}'"
                )

            # Validate attributes if present
            if "attributes" in assignment:
                attributes = assignment["attributes"]
                if not isinstance(attributes, dict):
                    self.errors.append(
                        f"{file_path}: Assignment {i} has invalid attributes"
                    )
                else:
                    for key, value in attributes.items():
                        if not isinstance(key, str) or not isinstance(value, str):
                            self.errors.append(
                                f"{file_path}: Assignment {i} has invalid attribute key/value"
                            )

    def _validate_security_properties(self, file_path: Path, policy: Dict[str, Any]):
        """Validate security properties"""
        roles = policy.get("roles", [])

        # Check for admin role with overly broad permissions
        for role in roles:
            if role.get("name") == "admin":
                permissions = role.get("permissions", [])
                for permission in permissions:
                    scope = permission.get("scope", {})
                    if scope.get("resource") == "*" and scope.get("path") == ["*"]:
                        self.warnings.append(
                            f"{file_path}: Admin role has wildcard permissions - review for least privilege"
                        )

        # Check for deny permissions (good practice)
        has_deny = False
        for role in roles:
            permissions = role.get("permissions", [])
            for permission in permissions:
                if permission.get("action") == "deny":
                    has_deny = True
                    break
            if has_deny:
                break

        if not has_deny:
            self.warnings.append(
                f"{file_path}: No deny permissions found - consider explicit deny rules"
            )

    def print_summary(self):
        """Print linting summary"""
        print("\n" + "=" * 50)
        print("POLICY LINT SUMMARY")
        print("=" * 50)
        print(f"Files passed: {self.passed}")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")

        if self.errors:
            print("\nERRORS:")
            for error in self.errors:
                print(f"  ✗ {error}")

        if self.warnings:
            print("\nWARNINGS:")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")

        print("=" * 50)

        return len(self.errors) == 0


def main():
    parser = argparse.ArgumentParser(description="Lint Security Envelopes policy files")
    parser.add_argument("files", nargs="+", help="Policy files to lint")
    parser.add_argument(
        "--strict", action="store_true", help="Treat warnings as errors"
    )

    args = parser.parse_args()

    linter = PolicyLinter()
    all_passed = True

    for file_pattern in args.files:
        for file_path in Path(".").glob(file_pattern):
            if file_path.is_file() and file_path.suffix in [".yaml", ".yml"]:
                if not linter.lint_file(file_path):
                    all_passed = False

    success = linter.print_summary()

    if args.strict and linter.warnings:
        print("Strict mode: warnings treated as errors")
        success = False

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
