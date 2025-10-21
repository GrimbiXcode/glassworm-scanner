# GlassWorm Scanner Examples

Practical examples showing how to use the GlassWorm Scanner for different scenarios.

## Basic Scanning

### Scan default node_modules directory

```bash
node scan-glassworm.js
```

### Scan a specific directory

```bash
node scan-glassworm.js /path/to/project/node_modules
node scan-glassworm.js ./src
node scan-glassworm.js ~/Downloads/suspicious-package
```

## Adjusting Detection Sensitivity

### Only report critical and high-severity findings

```bash
MIN_SCORE=70 node scan-glassworm.js
```

### Include low-severity findings (broader scanning)

```bash
INCLUDE_LOW=1 node scan-glassworm.js
```

### Combination: High threshold + low findings

```bash
MIN_SCORE=50 INCLUDE_LOW=1 node scan-glassworm.js
```

## Performance Tuning

### Increase timeout for slow storage or large files

```bash
INSPECT_TIMEOUT=30000 node scan-glassworm.js
```

### Use npm scripts for convenience

```bash
npm run scan
npm run scan:with-low
```

## Real-World Scenarios

### Suspicious package investigation

When you find a package behaving oddly, scan it:

```bash
node scan-glassworm.js ./node_modules/suspicious-pkg
```

Look for critical and high findings. Check the `glassworm-scan-report.json` for details about:
- Invisible Unicode in identifiers
- Network function usage
- Post-install scripts with downloads

### Pre-deployment security check

Before deploying, scan your entire project:

```bash
# Strict: only critical issues
MIN_SCORE=80 node scan-glassworm.js ./node_modules

# If clean, try medium threshold
MIN_SCORE=50 node scan-glassworm.js ./node_modules
```

### Monitoring supply chain updates

After running `npm update` or `yarn upgrade`:

```bash
# Check what changed
node scan-glassworm.js ./node_modules > latest-scan.txt
diff latest-scan.txt previous-scan.txt
```

### Auditing all project dependencies

```bash
# Full audit with all findings
INCLUDE_LOW=1 node scan-glassworm.js ./node_modules | tee audit-results.txt
```

## Interpreting Results

### Understanding the output

```
[CRITICAL 95] ./node_modules/suspicious-package/index.js
  signals: knownC2Infrastructure, solanaBlockchainC2, credentialTheft
  ips: 217.69.3.218
  solanaWallets: 28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2
```

- **[CRITICAL 95]**: Severity level and score
- **signals**: Detected patterns that triggered findings
- **details**: Specific indicators (IPs, wallets, keywords, etc.)

### What each signal means

- `knownC2Infrastructure` - Known command & control IP detected
- `solanaBlockchainC2` - Solana wallet used for C2 communication
- `googleCalendarC2` - Google Calendar used as C2 infrastructure
- `credentialTheft` - Pattern suggesting credential harvesting
- `cryptoWalletTargeting` - Cryptocurrency extension targeting detected
- `invisInIdentifier` - Invisible Unicode in variable/function names
- `shellDownload` - Download commands (curl, wget) with URLs
- `b64UrlDecoded` - Base64 encoding containing suspicious URLs

### Severity classification

- **Critical (≥80)**: Likely malicious, take action immediately
- **High (60-79)**: Strong indicators of compromise
- **Medium (40-59)**: Suspicious but could be legitimate
- **Low (<40)**: Minor suspicious patterns, may be false positives

## Batch Operations

### Scan multiple directories

```bash
for dir in ./packages/*/node_modules; do
  echo "Scanning $dir..."
  node scan-glassworm.js "$dir"
done
```

### Compare scans over time

```bash
# Initial scan
node scan-glassworm.js ./node_modules > scan-$(date +%Y%m%d).json

# Later, check for new findings
node scan-glassworm.js ./node_modules > scan-$(date +%Y%m%d).json
diff scan-20251020.json scan-20251021.json
```

### Export and analyze findings programmatically

```javascript
const report = require('./glassworm-scan-report.json');
console.log(`Critical findings: ${report.summary.critical}`);
console.log(`High findings: ${report.summary.high}`);

report.findings.critical?.forEach(finding => {
  console.log(`${finding.file}: ${finding.score}`);
});
```

## Troubleshooting

### Scanner hangs on large files

Increase timeout:

```bash
INSPECT_TIMEOUT=60000 node scan-glassworm.js
```

### No findings reported but expect some

Lower the threshold:

```bash
MIN_SCORE=30 INCLUDE_LOW=1 node scan-glassworm.js
```

### Too many false positives

Use a higher threshold:

```bash
MIN_SCORE=70 node scan-glassworm.js
```

### Report file not created

Ensure write permissions in current directory:

```bash
cd /tmp  # or another writable directory
node /path/to/scan-glassworm.js /path/to/scan
```

## Integration Examples

### GitHub Actions workflow

```yaml
- name: Security scan with GlassWorm
  run: |
    node scan-glassworm.js ./node_modules
    if [ -s glassworm-scan-report.json ]; then
      echo "Security issues detected!"
      jq '.summary' glassworm-scan-report.json
      exit 1
    fi
```

### Pre-commit hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
node scan-glassworm.js ./node_modules > /tmp/scan.json
if grep -q '"critical":[^0]' /tmp/scan.json; then
  echo "Critical security issues detected!"
  exit 1
fi
```

## Performance Tips

- Scan specific dependencies instead of entire node_modules when possible
- Increase `MIN_SCORE` to reduce false positives and improve speed
- Use higher `INSPECT_TIMEOUT` values for network-mounted or slow storage
- Run with appropriate process concurrency for your system resources
