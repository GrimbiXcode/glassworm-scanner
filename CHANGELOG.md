# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-21

### Added

- Initial release of GlassWorm Scanner
- Multi-layered detection system for malicious code patterns
- GlassWorm-specific detection:
  - Known C2 infrastructure identification (217.69.3.218, 140.82.52.31)
  - Solana blockchain C2 pattern detection
  - Google Calendar C2 pattern detection
  - Credential theft pattern identification
  - Cryptocurrency wallet extension targeting detection
  - VS Code extension malicious behavior detection
- General malicious pattern detection:
  - Invisible Unicode character detection (zero-width, variation selectors)
  - Suspicious keyword detection (solana, metaplex, phantom, etc.)
  - Network function detection (fetch, XMLHttpRequest, axios)
  - Dangerous function detection (eval, exec, child_process)
  - Shell download command detection (curl, wget, Invoke-WebRequest)
  - Hardcoded IP address detection
  - Base64 obfuscation detection
  - Post-install script analysis
- Additive severity scoring system (0-100 scale)
- Four severity classification levels: critical, high, medium, low
- Concurrent file processing with configurable worker pool
- Per-file inspection timeout to prevent hanging
- JSON report generation with detailed findings
- Console output with top 500 findings
- Support for JavaScript, TypeScript, and package.json files
- Environment variable configuration:
  - `MIN_SCORE`: Minimum severity threshold (default: 60)
  - `INCLUDE_LOW`: Include low-severity findings (default: 0)
  - `INSPECT_TIMEOUT`: Per-file timeout in ms (default: 15000)
- Binary file detection and skipping
- Minified file detection and skipping
- Configurable directory ignore list
- Command-line path argument support

### Documentation

- Comprehensive README with usage examples
- CONTRIBUTING guidelines for open source contributions
- MIT License
- EditorConfig for consistent code style
- JSDoc comments throughout codebase

---

For information about future versions, check the [Issues](https://github.com/GrimbiXcode/glassworm-scanner/issues) and [Pull Requests](https://github.com/GrimbiXcode/glassworm-scanner/pulls).
