# GlassWorm Scanner

A security scanning tool that detects suspicious patterns in JavaScript/TypeScript codebases, particularly focused on identifying potential supply chain attacks and malicious code in npm packages.

## Overview

GlassWorm Scanner is specifically designed to detect GlassWorm, the first self-propagating worm targeting VS Code extensions. It scans files for:

- Invisible Unicode characters and obfuscated code
- Known C2 (Command & Control) infrastructure
- Suspicious keywords and dangerous functions
- Hardcoded IP addresses
- Credential theft patterns
- Shell download commands
- Cryptocurrency wallet targeting
- Solana blockchain and Google Calendar C2 patterns

## Quick Start

### Basic Usage

```bash
# Scan default location (./node_modules)
node scan-glassworm.js

# Scan a specific directory
node scan-glassworm.js /path/to/directory
```

### Environment Variables

- `MIN_SCORE` (default: 60) - Minimum severity score to report
- `INCLUDE_LOW` (default: 0) - Set to '1' to include low-severity findings
- `INSPECT_TIMEOUT` (default: 15000) - Timeout in milliseconds for inspecting each file

### Examples

```bash
# Scan with custom minimum score threshold
MIN_SCORE=70 node scan-glassworm.js

# Include low-severity findings
INCLUDE_LOW=1 node scan-glassworm.js

# Adjust inspection timeout
INSPECT_TIMEOUT=30000 node scan-glassworm.js
```

## Output

The scanner produces:

- Real-time progress output to console with processing statistics
- Summary table with findings organized by severity level
- Detailed findings written to `glassworm-scan-report.json`

## Detection Patterns

### GlassWorm-Specific Indicators

1. **Known C2 Infrastructure** - Hardcoded IPs from GlassWorm campaign
2. **Solana Blockchain C2** - Solana wallet addresses combined with transaction patterns
3. **Google Calendar C2** - calendar.app.google URLs used as backup command infrastructure
4. **Credential Theft** - NPM_TOKEN, GITHUB_TOKEN, .npmrc, .gitconfig access patterns
5. **Cryptocurrency Wallet Targeting** - 49+ crypto wallet extensions (MetaMask, Phantom, etc.)
6. **VS Code Extension Indicators** - VSCode engines, activation events, and chrome.storage API usage

### General Malicious Patterns

7. **Invisible Unicode Characters** - Zero-width characters and variation selectors
8. **Suspicious Keywords** - solana, metaplex, phantom, transaction, memo, wallet APIs
9. **Network Functions** - fetch, XMLHttpRequest, axios, HTTP requests
10. **Dangerous Functions** - eval, Function constructor, child_process, spawn, exec
11. **Shell Download Commands** - curl, wget, Invoke-WebRequest with URLs
12. **Hardcoded IPs** - Non-private IP addresses in code
13. **Base64 Obfuscation** - Large base64 strings decoding to URLs or executable code
14. **Post-Install Scripts** - package.json scripts that download or execute code

## Severity Classification

Findings are scored on a 0-100 scale:

- **Critical** (≥80) - Known C2 infrastructure, Solana/Google Calendar C2 patterns
- **High** (60-79) - Base64-decoded URLs, invisible Unicode, credential theft, shell downloads
- **Medium** (40-59) - Suspicious keywords, dangerous functions, VS Code APIs
- **Low** (<40) - Generic suspicious patterns

## Architecture

### Core Components

**File Scanner** - Recursively walks directory tree, filtering ignored directories (.git, dist, build, etc.), skipping binary and minified files

**Pattern Detection** - Multi-layered detection system analyzing JavaScript, TypeScript, and package.json files with additive severity scoring

**Concurrency Model** - Uses worker pool pattern with automatic CPU-based concurrency (minimum 2 workers) for efficient scanning

### Key Implementation Details

- **Binary Detection** - Samples first 4KB; skips files with >10% non-text bytes
- **Base64 Decoding** - Decodes strings 80-200 chars to check for suspicious URLs/executable code
- **Solana Validation** - Base58 pattern matching against known malicious wallets
- **VS Code Detection** - Identifies extensions via package.json engines.vscode and browser APIs
- **Progress Reporting** - Real-time updates showing processed count, percentage, elapsed time, and findings

## Requirements

- Node.js ≥16

## Output File

All findings are written to `glassworm-scan-report.json` with full details. Top 500 findings (sorted by severity score) are also printed to console.

## Security Context

This scanner detects attacks by GlassWorm, discovered in October 2025. GlassWorm uses:

- Invisible Unicode variation selectors to hide malicious code in npm packages
- Solana blockchain transactions (reading memo fields) as C2
- Google Calendar events as backup C2 infrastructure
- Targets 49+ cryptocurrency wallet browser extensions
- Steals credentials (NPM, GitHub, Git, OpenVSX tokens) for self-propagation
