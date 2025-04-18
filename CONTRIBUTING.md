# Contributing to PQC-IIoT

Thank you for your interest in contributing to PQC-IIoT! This document provides guidelines and instructions for contributing to our project. We welcome all forms of contributions, including bug reports, feature requests, documentation improvements, and code contributions.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security Considerations](#security-considerations)
- [Pull Request Process](#pull-request-process)
- [License](#license)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before making any contributions.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/doomhammerhell/pqc-iiot.git
   cd pqc-iiot
   ```
3. Set up the development environment:
   ```bash
   rustup default stable
   cargo install cargo-fuzz
   cargo install cargo-criterion
   ```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Run tests and ensure they pass
4. Commit your changes with a descriptive message
5. Push to your fork
6. Create a Pull Request

## Coding Standards

### Rust Style Guide

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/README.html)
- Use `rustfmt` to format your code:
  ```bash
  cargo fmt
  ```
- Run `clippy` to catch common mistakes:
  ```bash
  cargo clippy --all-targets --all-features -- -D warnings
  ```

### Code Organization

- Keep functions small and focused
- Use meaningful variable and function names
- Add comments for complex logic
- Document public APIs with doc comments
- Follow the existing project structure

### Error Handling

- Use the `Result` type for fallible operations
- Provide meaningful error messages
- Use custom error types when appropriate
- Handle errors at the appropriate level

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with specific features
cargo test --features embedded

# Run benchmarks
cargo bench
```

### Writing Tests

- Write unit tests for individual functions
- Write integration tests for component interactions
- Include examples in documentation
- Test edge cases and error conditions

### Fuzzing

- Add fuzz targets for security-critical code
- Run fuzz tests before submitting PRs:
  ```bash
  cargo fuzz run fuzz_target_1
  ```

## Documentation

### Code Documentation

- Document all public APIs
- Include examples in doc comments
- Keep documentation up to date
- Use markdown in doc comments

### README and Guides

- Update README.md for significant changes
- Add or update guides as needed
- Keep examples current

## Security Considerations

- Follow security best practices
- Report security vulnerabilities responsibly
- Use constant-time operations for cryptographic code
- Avoid unsafe code unless absolutely necessary
- Document security assumptions and guarantees

## Pull Request Process

1. Ensure your code follows the coding standards
2. Run all tests and ensure they pass
3. Update documentation as needed
4. Write a clear PR description
5. Reference any related issues
6. Request review from maintainers

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Security considerations addressed
- [ ] No breaking changes (unless discussed)
- [ ] Changes are backward compatible

## License

By contributing to PQC-IIoT, you agree that your contributions will be licensed under both the MIT and Apache 2.0 licenses, as specified in the project's LICENSE files. 