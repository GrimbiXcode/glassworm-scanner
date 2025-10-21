# Contributing to GlassWorm Scanner

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Be respectful and inclusive. We're building a security tool to protect developers, and we value all contributors regardless of background or experience level.

## Getting Started

### Prerequisites

- Node.js >= 16
- Git

### Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone git@github.com:YOUR_USERNAME/glassworm-scanner.git
   cd glassworm-scanner
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Making Changes

### Code Style

- Use 2-space indentation
- Follow existing code patterns
- Keep functions focused and reasonably sized
- Add comments for complex logic

### Testing

- Test your changes thoroughly before submitting
- Run the scanner on test directories to verify behavior:
  ```bash
  node scan-glassworm.js /path/to/test/directory
  ```

### Commit Messages

Write clear, descriptive commit messages:
- Use imperative mood ("add feature" not "added feature")
- Reference issues when applicable (e.g., "Fix #123")
- Keep first line under 50 characters

## Submitting Changes

### Pull Requests

1. Push your branch to your fork
2. Open a PR against the main repository
3. Provide a clear description of:
   - What problem you're solving
   - How your solution works
   - Any new patterns or detection logic added
4. Reference related issues

### PR Review

- Expect feedback and be open to discussion
- Address review comments
- Keep PRs focused on a single feature or fix

## Reporting Issues

### Bug Reports

Include:
- Node.js version
- Steps to reproduce
- Expected vs actual behavior
- Relevant file/directory that triggers the issue

### Feature Requests

- Describe the use case
- Explain how it improves the scanner
- Provide examples if possible

## Detection Pattern Contributions

We're always looking to improve malware detection. If you discover new patterns:

1. Document the pattern clearly
2. Explain why it's suspicious
3. Provide test cases
4. Submit as a feature request or PR with the pattern added to `scan-glassworm.js`

## Documentation

- Update README.md if behavior changes
- Document new environment variables in README
- Add examples to EXAMPLES.md for new detection types

## Questions?

Open an issue for questions or discussions. We're happy to help!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
