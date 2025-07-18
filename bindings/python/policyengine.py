"""
Python bindings for Security Envelopes PolicyEngine

This module provides Python bindings for the formally verified PolicyEngine
for RBAC/ABAC policy evaluation with WASM runtime support.
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import asyncio
from pathlib import Path

try:
    from ._policyengine import PolicyEngine as _PolicyEngine
    from ._policyengine import PolicyEngineError
except ImportError:
    # Fallback for development
    _PolicyEngine = None
    PolicyEngineError = Exception


class LogLevel(Enum):
    """Logging levels for PolicyEngine"""

    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


@dataclass
class Principal:
    """Represents a user or service principal"""

    id: str
    attributes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {"id": self.id, "attributes": self.attributes}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Principal":
        """Create from dictionary"""
        return cls(id=data["id"], attributes=data.get("attributes", {}))


@dataclass
class Scope:
    """Represents a resource or action scope"""

    type: str
    name: str
    path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {"type": self.type, "name": self.name, "path": self.path}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Scope":
        """Create from dictionary"""
        return cls(type=data["type"], name=data["name"], path=data.get("path", []))


@dataclass
class Permission:
    """Represents an access permission"""

    resource: str
    actions: List[str]
    conditions: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {"resource": self.resource, "actions": self.actions}
        if self.conditions:
            result["conditions"] = self.conditions
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Permission":
        """Create from dictionary"""
        return cls(
            resource=data["resource"],
            actions=data["actions"],
            conditions=data.get("conditions"),
        )


@dataclass
class Role:
    """Represents a role with permissions"""

    name: str
    description: str
    permissions: List[Permission] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "name": self.name,
            "description": self.description,
            "permissions": [p.to_dict() for p in self.permissions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Role":
        """Create from dictionary"""
        return cls(
            name=data["name"],
            description=data["description"],
            permissions=[Permission.from_dict(p) for p in data.get("permissions", [])],
        )


@dataclass
class Policy:
    """Represents a complete policy definition"""

    id: str
    name: str
    version: str
    roles: List[Role] = field(default_factory=list)
    permissions: List[Permission] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "roles": [r.to_dict() for r in self.roles],
            "permissions": [p.to_dict() for p in self.permissions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            roles=[Role.from_dict(r) for r in data.get("roles", [])],
            permissions=[Permission.from_dict(p) for p in data.get("permissions", [])],
        )


@dataclass
class EvaluationResult:
    """Represents the result of a policy evaluation"""

    allowed: bool
    reason: str
    conditions: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {"allowed": self.allowed, "reason": self.reason}
        if self.conditions:
            result["conditions"] = self.conditions
        if self.metadata:
            result["metadata"] = self.metadata
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvaluationResult":
        """Create from dictionary"""
        return cls(
            allowed=data["allowed"],
            reason=data["reason"],
            conditions=data.get("conditions"),
            metadata=data.get("metadata"),
        )


@dataclass
class Config:
    """PolicyEngine configuration"""

    wasm_path: Optional[str] = None
    log_level: LogLevel = LogLevel.INFO
    max_memory: int = 100 * 1024 * 1024  # 100MB
    timeout: int = 5000  # 5 seconds
    environment: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "wasm_path": self.wasm_path,
            "log_level": self.log_level.value,
            "max_memory": self.max_memory,
            "timeout": self.timeout,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create from dictionary"""
        return cls(
            wasm_path=data.get("wasm_path"),
            log_level=LogLevel(data.get("log_level", "info")),
            max_memory=data.get("max_memory", 100 * 1024 * 1024),
            timeout=data.get("timeout", 5000),
            environment=data.get("environment", {}),
        )


class PolicyEngine:
    """
    Python wrapper for the Security Envelopes PolicyEngine

    This class provides a high-level interface to the formally verified
    PolicyEngine for RBAC/ABAC policy evaluation.
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize a new PolicyEngine instance

        Args:
            config: Configuration for the PolicyEngine
        """
        if _PolicyEngine is None:
            raise ImportError("PolicyEngine native module not available")

        if config is None:
            config = Config()

        self._engine = _PolicyEngine(config.to_dict())
        self._config = config

    def load_policy(self, policy_data: Union[str, bytes, Path]) -> None:
        """
        Load a policy from YAML or JSON data

        Args:
            policy_data: Policy data as string, bytes, or file path

        Raises:
            PolicyEngineError: If policy loading fails
        """
        if isinstance(policy_data, Path):
            policy_data = policy_data.read_text()
        elif isinstance(policy_data, bytes):
            policy_data = policy_data.decode("utf-8")

        self._engine.load_policy(policy_data)

    def evaluate(
        self,
        principal: Principal,
        scope: Scope,
        context: Optional[Dict[str, Any]] = None,
    ) -> EvaluationResult:
        """
        Evaluate a policy for a principal and scope

        Args:
            principal: The principal to evaluate
            scope: The scope to evaluate
            context: Optional context for evaluation

        Returns:
            EvaluationResult with the evaluation outcome

        Raises:
            PolicyEngineError: If evaluation fails
        """
        result_dict = self._engine.evaluate(
            principal.to_dict(), scope.to_dict(), context or {}
        )
        return EvaluationResult.from_dict(result_dict)

    def can_access(self, principal: Principal, resource: str, action: str) -> bool:
        """
        Check if a principal can access a resource

        Args:
            principal: The principal to check
            resource: The resource to access
            action: The action to perform

        Returns:
            True if access is allowed, False otherwise

        Raises:
            PolicyEngineError: If access check fails
        """
        scope = Scope(type="resource", name=resource, path=[action])
        result = self.evaluate(principal, scope)
        return result.allowed

    def validate_policy(self, policy_data: Union[str, bytes, Path]) -> None:
        """
        Validate a policy without loading it

        Args:
            policy_data: Policy data to validate

        Raises:
            PolicyEngineError: If policy validation fails
        """
        if isinstance(policy_data, Path):
            policy_data = policy_data.read_text()
        elif isinstance(policy_data, bytes):
            policy_data = policy_data.decode("utf-8")

        self._engine.validate_policy(policy_data)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get PolicyEngine statistics

        Returns:
            Dictionary containing engine statistics
        """
        return self._engine.get_stats()

    def batch_evaluate(self, requests: List[Dict[str, Any]]) -> List[EvaluationResult]:
        """
        Evaluate multiple policies in batch

        Args:
            requests: List of evaluation requests

        Returns:
            List of evaluation results

        Raises:
            PolicyEngineError: If batch evaluation fails
        """
        results = self._engine.batch_evaluate(requests)
        return [EvaluationResult.from_dict(r) for r in results]

    def set_log_level(self, level: LogLevel) -> None:
        """
        Set the logging level

        Args:
            level: The log level to set
        """
        self._engine.set_log_level(level.value)

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get PolicyEngine capabilities

        Returns:
            Dictionary containing engine capabilities
        """
        return self._engine.get_capabilities()

    @property
    def version(self) -> str:
        """Get the PolicyEngine version"""
        return self._engine.version

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    def close(self) -> None:
        """Close the PolicyEngine instance"""
        if hasattr(self._engine, "close"):
            self._engine.close()


# Async wrapper for PolicyEngine
class AsyncPolicyEngine:
    """
    Asynchronous wrapper for PolicyEngine

    This class provides async methods for PolicyEngine operations,
    useful for integration with async frameworks like FastAPI.
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize a new AsyncPolicyEngine instance

        Args:
            config: Configuration for the PolicyEngine
        """
        self._engine = PolicyEngine(config)
        self._loop = asyncio.get_event_loop()

    async def load_policy(self, policy_data: Union[str, bytes, Path]) -> None:
        """Async version of load_policy"""
        return await self._loop.run_in_executor(
            None, self._engine.load_policy, policy_data
        )

    async def evaluate(
        self,
        principal: Principal,
        scope: Scope,
        context: Optional[Dict[str, Any]] = None,
    ) -> EvaluationResult:
        """Async version of evaluate"""
        return await self._loop.run_in_executor(
            None, self._engine.evaluate, principal, scope, context
        )

    async def can_access(
        self, principal: Principal, resource: str, action: str
    ) -> bool:
        """Async version of can_access"""
        return await self._loop.run_in_executor(
            None, self._engine.can_access, principal, resource, action
        )

    async def validate_policy(self, policy_data: Union[str, bytes, Path]) -> None:
        """Async version of validate_policy"""
        return await self._loop.run_in_executor(
            None, self._engine.validate_policy, policy_data
        )

    async def get_stats(self) -> Dict[str, Any]:
        """Async version of get_stats"""
        return await self._loop.run_in_executor(None, self._engine.get_stats)

    async def batch_evaluate(
        self, requests: List[Dict[str, Any]]
    ) -> List[EvaluationResult]:
        """Async version of batch_evaluate"""
        return await self._loop.run_in_executor(
            None, self._engine.batch_evaluate, requests
        )

    async def get_capabilities(self) -> Dict[str, Any]:
        """Async version of get_capabilities"""
        return await self._loop.run_in_executor(None, self._engine.get_capabilities)

    @property
    def version(self) -> str:
        """Get the PolicyEngine version"""
        return self._engine.version

    async def close(self) -> None:
        """Close the PolicyEngine instance"""
        if hasattr(self._engine, "close"):
            await self._loop.run_in_executor(None, self._engine.close)


# Utility functions
def get_version() -> str:
    """Get the PolicyEngine version"""
    if _PolicyEngine is None:
        return "unknown"
    return _PolicyEngine.version


def create_policy_from_yaml(yaml_data: str) -> Policy:
    """
    Create a Policy from YAML data

    Args:
        yaml_data: YAML string containing policy definition

    Returns:
        Policy object

    Raises:
        ValueError: If YAML parsing fails
    """
    try:
        import yaml

        data = yaml.safe_load(yaml_data)
        return Policy.from_dict(data)
    except ImportError:
        raise ImportError("PyYAML is required for YAML parsing")
    except Exception as e:
        raise ValueError(f"Failed to parse YAML: {e}")


def create_policy_from_json(json_data: str) -> Policy:
    """
    Create a Policy from JSON data

    Args:
        json_data: JSON string containing policy definition

    Returns:
        Policy object

    Raises:
        ValueError: If JSON parsing fails
    """
    try:
        data = json.loads(json_data)
        return Policy.from_dict(data)
    except Exception as e:
        raise ValueError(f"Failed to parse JSON: {e}")


# Convenience functions for common operations
def quick_evaluate(
    policy_data: Union[str, bytes, Path],
    principal: Principal,
    scope: Scope,
    context: Optional[Dict[str, Any]] = None,
) -> EvaluationResult:
    """
    Quick evaluation without creating a persistent PolicyEngine instance

    Args:
        policy_data: Policy data
        principal: Principal to evaluate
        scope: Scope to evaluate
        context: Optional context

    Returns:
        EvaluationResult
    """
    with PolicyEngine() as engine:
        engine.load_policy(policy_data)
        return engine.evaluate(principal, scope, context)


def quick_access_check(
    policy_data: Union[str, bytes, Path],
    principal: Principal,
    resource: str,
    action: str,
) -> bool:
    """
    Quick access check without creating a persistent PolicyEngine instance

    Args:
        policy_data: Policy data
        principal: Principal to check
        resource: Resource to access
        action: Action to perform

    Returns:
        True if access is allowed, False otherwise
    """
    with PolicyEngine() as engine:
        engine.load_policy(policy_data)
        return engine.can_access(principal, resource, action)


__all__ = [
    "PolicyEngine",
    "AsyncPolicyEngine",
    "Principal",
    "Scope",
    "Permission",
    "Role",
    "Policy",
    "EvaluationResult",
    "Config",
    "LogLevel",
    "PolicyEngineError",
    "get_version",
    "create_policy_from_yaml",
    "create_policy_from_json",
    "quick_evaluate",
    "quick_access_check",
]
