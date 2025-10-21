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
npm run scan:ci              # CI mode - fail on high or critical
npm run scan:ci:critical     # CI mode - fail only on critical
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

## CI/CD Integration Examples

### GitHub Actions workflow

Copy `examples/ci-templates/github-actions.yml` to `.github/workflows/glassworm-scan.yml` in your project.

Or add to existing workflow:

```yaml
- name: Security scan with GlassWorm
  run: npx glassworm-scanner
  env:
    CI: true
    FAIL_ON: high  # Fail on high or critical findings
    MIN_SCORE: 60

- name: Upload scan report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: glassworm-scan-report
    path: glassworm-scan-report.json
```

### GitLab CI pipeline

Copy `examples/ci-templates/gitlab-ci.yml` to `.gitlab-ci.yml` in your project root.

Or add to existing pipeline:

```yaml
glassworm-scan:
  stage: security
  image: node:18
  variables:
    CI: "true"
    FAIL_ON: "high"
  script:
    - npm ci
    - npx glassworm-scanner
  artifacts:
    paths:
      - glassworm-scan-report.json
```

### Jenkins Pipeline

```groovy
stage('Security Scan') {
  steps {
    sh 'npm ci'
    sh 'CI=true FAIL_ON=high npx glassworm-scanner'
  }
  post {
    always {
      archiveArtifacts artifacts: 'glassworm-scan-report.json', allowEmptyArchive: true
    }
  }
}
```

### CircleCI

```yaml
jobs:
  security-scan:
    docker:
      - image: node:18
    steps:
      - checkout
      - run: npm ci
      - run:
          name: GlassWorm Security Scan
          command: CI=true FAIL_ON=high npx glassworm-scanner
      - store_artifacts:
          path: glassworm-scan-report.json
```

### Azure Pipelines

```yaml
- task: Npm@1
  inputs:
    command: 'ci'

- script: |
    export CI=true
    export FAIL_ON=high
    npx glassworm-scanner
  displayName: 'Run GlassWorm Scanner'

- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: 'glassworm-scan-report.json'
    artifactName: 'security-scan-report'
```

### Pre-commit hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run scanner with strict threshold
CI=true FAIL_ON=critical node scan-glassworm.js ./node_modules

if [ $? -eq 1 ]; then
  echo "❌ Critical security issues detected!"
  echo "Review glassworm-scan-report.json for details."
  exit 1
fi
```

### npm scripts for different environments

Add to `package.json`:

```json
{
  "scripts": {
    "security:scan": "node scan-glassworm.js",
    "security:scan:dev": "MIN_SCORE=50 INCLUDE_LOW=1 node scan-glassworm.js",
    "security:scan:ci": "CI=true FAIL_ON=high node scan-glassworm.js",
    "security:scan:prod": "CI=true FAIL_ON=critical MIN_SCORE=80 node scan-glassworm.js"
  }
}
```

## Performance Tips

- Scan specific dependencies instead of entire node_modules when possible
- Increase `MIN_SCORE` to reduce false positives and improve speed
- Use higher `INSPECT_TIMEOUT` values for network-mounted or slow storage
- Run with appropriate process concurrency for your system resources
