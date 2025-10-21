# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

GlassWorm Scanner is a security scanning tool that detects suspicious patterns in JavaScript/TypeScript codebases, particularly focused on identifying potential supply chain attacks and malicious code in npm packages. It scans files for invisible Unicode characters, suspicious keywords, obfuscated code, hardcoded IPs, dangerous functions, and other malicious patterns.

## Commands

### Running the Scanner
```bash
# Scan default location (./node_modules)
node scan-glassworm.js

# Scan a specific directory
node scan-glassworm.js /path/to/directory

# Scan with custom minimum score threshold
MIN_SCORE=70 node scan-glassworm.js

# Include low-severity findings
INCLUDE_LOW=1 node scan-glassworm.js

# Adjust inspection timeout (default 15000ms)
INSPECT_TIMEOUT=30000 node scan-glassworm.js
```

### Environment Variables
- `MIN_SCORE` (default: 60) - Minimum severity score to report
- `INCLUDE_LOW` (default: 0) - Set to '1' to include low-severity findings
- `INSPECT_TIMEOUT` (default: 15000) - Timeout in milliseconds for inspecting each file

### Output
The scanner produces:
- Real-time progress output to console
- Summary table with findings by severity
- Detailed findings written to `glassworm-scan-report.json`

## Architecture

### Core Components

**File Scanner (`walk` function)**
- Recursively walks directory tree, filtering out ignored directories (.git, dist, build, etc.)
- Skips binary files, minified files, and common non-code files
- Respects MAX_BYTES limit (3MB) to avoid memory issues

**Pattern Detection (`inspect` function)**
- Multi-layered detection system that analyzes JavaScript, TypeScript, and package.json files
- Each pattern match contributes to a severity score (0-100)
- Returns null for files that don't meet minimum threshold

**Scoring System (`scoreFinding` function)**
Severity scores are additive based on detected patterns:
- Known C2 infrastructure (IPs from GlassWorm): +60 (critical)
- Solana blockchain C2 patterns: +50 (critical)
- Google Calendar C2 patterns: +50 (critical)
- Base64-decoded URLs/code: +45 (high risk)
- Invisible Unicode in identifiers: +40 (high risk)
- package.json post-install scripts with network calls: +40
- Credential theft patterns: +35
- Shell download commands: +35
- Cryptocurrency wallet targeting: +30
- Dangerous functions (eval, exec): +25
- Suspicious keywords (crypto-related): +25
- VS Code extension API usage: +20
- Multiple signals bonus: +15 (when ≥3 patterns found)

**Classification Levels**
- Critical: ≥80
- High: 60-79
- Medium: 40-59
- Low: <40

### Detection Patterns

The scanner checks for GlassWorm-specific indicators and general malicious patterns:

**GlassWorm-Specific Detection:**
1. **Known C2 Infrastructure**: Hardcoded IPs from GlassWorm campaign (217.69.3.218, 140.82.52.31)
2. **Solana Blockchain C2**: Detects Solana wallet addresses (especially 28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2) combined with transaction/memo access patterns
3. **Google Calendar C2**: Detects calendar.app.google URLs used as backup command infrastructure
4. **Credential Theft**: NPM_TOKEN, GITHUB_TOKEN, .npmrc, .gitconfig access patterns
5. **Cryptocurrency Wallet Targeting**: Detects targeting of 49+ crypto wallet extensions (MetaMask, Phantom, etc.)
6. **VS Code Extension Indicators**: package.json with vscode engine, activation events, chrome.storage API

**General Malicious Patterns:**
7. **Invisible Unicode Characters**: Zero-width characters and variation selectors (U+FE00-U+FE0F, U+FEFF) in identifiers
8. **Suspicious Keywords**: solana, metaplex, phantom, transaction, memo, getTransaction, wallet APIs
9. **Network Functions**: fetch, XMLHttpRequest, axios, HTTP requests
10. **Dangerous Functions**: eval, Function constructor, child_process, spawn, exec
11. **Shell Download Commands**: curl, wget, Invoke-WebRequest with HTTP URLs
12. **Hardcoded IP Addresses**: Non-private IP addresses in code
13. **Base64 Obfuscation**: Large base64 strings that decode to URLs or executable code
14. **package.json Analysis**: Post-install scripts that download or execute code

### Concurrency Model

- Uses worker pool pattern with `CONCURRENCY = floor(cpus/2)` workers (minimum 2)
- Workers pull from shared queue until empty
- Each file inspection has a timeout (default 15s) to prevent hanging
- Files timing out are tracked separately in `skipped` array

## Code Conventions

- Node.js ≥16 required
- Uses CommonJS module system (require/module.exports)
- Async/await with fs.promises for file operations
- Regular expressions cached as constants for performance
- Files truncated to 500KB for regex matching to prevent catastrophic backtracking

## Key Implementation Details

**Binary Detection**: First 4KB sampled; if >10% weird bytes or null bytes found, file skipped

**Base64 Decoding**: Only decodes strings 80-200 chars; checks if decoded content is suspicious (URLs, eval, etc.)

**Solana Wallet Detection**: Uses Base58 pattern matching (32-44 chars) and validates against known malicious wallets

**VS Code Extension Detection**: Identifies extensions via package.json engines.vscode field and browser/chrome extension APIs

**Progress Reporting**: 500ms interval updates showing processed count, percentage, elapsed time, findings, and skipped files

**Output Limiting**: Top 500 findings sorted by score printed to console; full results in JSON file

## Security Context

This scanner is specifically designed to detect GlassWorm, the first self-propagating worm targeting VS Code extensions (discovered October 2025). GlassWorm uses:
- Invisible Unicode variation selectors to hide malicious code
- Solana blockchain transactions as C2 infrastructure (reading memo fields)
- Google Calendar events as backup C2 (base64-encoded payloads in event titles)
- Targets 49+ cryptocurrency wallet browser extensions
- Steals NPM, GitHub, Git, and OpenVSX credentials for propagation
