# Contributing to Security Envelopes

Thank you for your interest in contributing to Security Envelopes! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)
- [Questions and Support](#questions-and-support)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Lean 4.0+** - Formal verification framework
- **Rust 1.70+** - Systems programming language
- **Python 3.9+** - Compliance bundle generation
- **Node.js 18+** - Development tooling
- **Go 1.21+** - Language bindings
- **Docker** - Containerization and testing

### Development Setup

1. **Fork the repository**

   ```bash
   git clone https://github.com/your-username/security-envelopes.git
   cd security-envelopes
   ```

2. **Install dependencies**

   ```bash
   # Install Lean
   curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

   # Install Python dependencies
   pip install -r requirements.txt

   # Install Node.js dependencies (if working on bindings)
   cd bindings/node && npm install
   ```

3. **Build the project**
   ```bash
   lake build
   cargo build
   ```

## Contributing Guidelines

### Types of Contributions

We welcome contributions in the following areas:

- **Formal Specifications**: Lean proofs and formal verification
- **Policy Engine**: Rust/WASM implementation improvements
- **Language Bindings**: Go, Node.js, Python integrations
- **Compliance Framework**: Bundle generation and reporting
- **Documentation**: API docs, tutorials, and guides
- **Testing**: Unit tests, integration tests, chaos testing
- **CI/CD**: GitHub Actions improvements
- **Security**: Vulnerability fixes and security enhancements

### Before You Start

1. **Check existing issues** - Search for existing issues or discussions
2. **Create an issue** - For significant changes, create an issue first
3. **Discuss the approach** - Get feedback on your proposed solution
4. **Follow the coding standards** - Ensure your code meets our standards

## Pull Request Process

### Creating a Pull Request

1. **Create a feature branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**

   - Follow the coding standards
   - Add appropriate tests
   - Update documentation

3. **Test your changes**

   ```bash
   # Run all tests
   lake test
   cargo test
   pytest tests/

   # Run specific test suites
   lake test Spec.Tests.RBAC
   cargo test --package policy-engine
   ```

4. **Commit your changes**

   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Pull Request Requirements

- **Title**: Clear, descriptive title
- **Description**: Detailed description of changes
- **Tests**: All tests must pass
- **Documentation**: Update relevant documentation
- **Formal Verification**: New features must include formal proofs
- **Security Review**: Security-sensitive changes require review

### Review Process

1. **Automated Checks**: CI/CD pipeline must pass
2. **Code Review**: At least one maintainer approval required
3. **Security Review**: Security team review for sensitive changes
4. **Final Approval**: Maintainer approval for merge

## Code Standards

### General Principles

- **Security First**: All code must prioritize security
- **Formal Verification**: Critical components must have formal proofs
- **Performance**: Maintain sub-millisecond latency requirements
- **Documentation**: Comprehensive documentation for all public APIs
- **Testing**: High test coverage with property-based testing

### Language-Specific Standards

#### Lean (Formal Specifications)

```lean
-- Use clear, descriptive theorem names
theorem rbac_soundness : ∀ (p : Principal) (s : Scope) (pol : Policy),
  hasPermission p s pol → validPermission p s pol

-- Include comprehensive documentation
/--
  Soundness theorem for RBAC system.
  Ensures that all granted permissions are valid.
-/
```

#### Rust (Policy Engine)

```rust
// Use idiomatic Rust with safety guarantees
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub roles: HashMap<RoleId, Role>,
    pub permissions: HashSet<Permission>,
}

// Include comprehensive error handling
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Invalid role: {0}")]
    InvalidRole(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}
```

#### Python (Compliance Bundle)

```python
# Use type hints and comprehensive docstrings
def generate_compliance_bundle(
    config: Dict[str, Any],
    output_path: Path
) -> bool:
    """
    Generate comprehensive compliance bundle.

    Args:
        config: Configuration dictionary
        output_path: Output file path

    Returns:
        True if successful, False otherwise

    Raises:
        RuntimeError: If bundle generation fails
    """
```

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance tasks

## Testing

### Test Requirements

- **Unit Tests**: 95%+ coverage for all components
- **Integration Tests**: End-to-end functionality testing
- **Property Tests**: Property-based testing with QuickCheck/Hypothesis
- **Chaos Testing**: Jepsen framework for distributed system testing
- **Security Tests**: OWASP test suite compliance
- **Performance Tests**: Benchmark testing for latency requirements

### Running Tests

```bash
# Run all tests
lake test
cargo test
pytest tests/

# Run specific test suites
lake test Spec.Tests.RBAC
cargo test --package policy-engine -- --nocapture
pytest tests/test_rbac.py -v

# Run chaos testing
docker-compose -f docker-compose.jepsen.yml up -d
./chaos-scripts/network-partition.sh
```

## Documentation

### Documentation Standards

- **API Documentation**: Complete OpenAPI specifications
- **Code Comments**: Comprehensive inline documentation
- **Architecture Docs**: System design and architecture
- **User Guides**: Step-by-step usage instructions
- **Developer Guides**: Setup and development workflows

### Documentation Updates

- Update relevant documentation for all changes
- Include code examples and use cases
- Maintain consistency across all documentation
- Use clear, concise language

## Security

### Security Guidelines

- **No Secrets**: Never commit secrets or sensitive data
- **Vulnerability Reporting**: Report security issues privately
- **Code Review**: All changes require security review
- **Dependency Scanning**: Regular dependency vulnerability scanning
- **Formal Verification**: Critical security properties must be formally verified

### Reporting Security Issues

For security issues, please:

1. **Do not** create a public issue
2. Email security@security-envelopes.org
3. Include detailed description and reproduction steps
4. Allow time for investigation and response

## Questions and Support

### Getting Help

- **Issues**: Use GitHub issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: Check the documentation first
- **Community**: Join our community channels

### Community Guidelines

- Be respectful and inclusive
- Help others learn and contribute
- Follow the code of conduct
- Provide constructive feedback

## Recognition

Contributors will be recognized in:

- **Contributors list** on GitHub
- **Release notes** for significant contributions
- **Documentation** for major features
- **Community acknowledgments**

Thank you for contributing to Security Envelopes!
