#!/usr/bin/env node
/**
 * GlassWorm Scanner - Security scanning tool for detecting malicious patterns
 * 
 * Detects suspicious patterns in JavaScript/TypeScript codebases, particularly
 * focused on identifying potential supply chain attacks and malicious code in npm packages.
 * 
 * Usage:
 *   node scan-glassworm.js [path]
 *   MIN_SCORE=70 node scan-glassworm.js
 *   INCLUDE_LOW=1 node scan-glassworm.js
 * 
 * Environment Variables:
 *   MIN_SCORE - Minimum severity score to report (default: 60)
 *   INCLUDE_LOW - Include low-severity findings (default: 0)
 *   INSPECT_TIMEOUT - Timeout in ms for inspecting each file (default: 15000)
 * 
 * Requires: Node.js >= 16
 */

const fs = require('fs').promises;
const path = require('path');
const os = require('os');

const ROOT = process.argv[2] || './node_modules';
const MAX_BYTES = 3 * 1024 * 1024;
const CONCURRENCY = Math.max(2, Math.floor(os.cpus().length / 2));
const MIN_SCORE = Number(process.env.MIN_SCORE || 60);
const INCLUDE_LOW = process.env.INCLUDE_LOW === '1';
const INSPECT_TIMEOUT = Number(process.env.INSPECT_TIMEOUT || 15000);
const CI_MODE = process.env.CI === 'true' || process.env.CI_MODE === '1';
const FAIL_ON = process.env.FAIL_ON || 'critical'; // 'critical', 'high', 'medium', 'low', 'none'

const ALLOWED_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.json', '.jsx', '.tsx']);
const IGNORE_FILES = new Set([
  'LICENSE','CHANGELOG','CHANGES','README','HISTORY','NOTICE',
  'yarn.lock','pnpm-lock.yaml','package-lock.json','npm-shrinkwrap.json'
]);
const IGNORE_DIRS = new Set(['.git','.hg','.svn','dist','build','coverage','__tests__']);
const SKIP_SUFFIX = new Set(['.min.js','.map','.d.ts','.md','.markdown','.txt','.svg','.png','.jpg','.jpeg','.gif','.webp','.wasm']);
const INVIS = /[\u200B\u200C\u200D\u2060\u2063\u00AD\uFE00-\uFE0F\uFEFF\u180E]/g;
const INVIS_ID = /([A-Za-z_$][\w$]*[\u200B\u200C\u200D\u2060\u2063\u00AD\uFE00-\uFE0F\uFEFF\u180E][\w$]*)/g;
const SUS_WORDS = /\b(solana|metaplex|phantom|solscan|rpc(?:Url|\.url)?|calendar\.app\.google|calendar\.google|transaction|memo|getTransaction|getParsedTransaction|wallet|chrome\.storage|browser\.storage)\b/i;
const NET_FUNCS = /\b(fetch|XMLHttpRequest|axios|require\(['"]https?['"]\)|https?\.(get|request))\b/;
const DANGEROUS = /\b(eval|Function|child_process|spawn|exec|execFile|PowerShell|WScript\.Shell)\b/;
const SHELL_DOWNLOAD = /\b(curl|wget|iwr|Invoke-WebRequest)\b.*\b(http|https):\/\//i;
const IP = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})\b/;
const B64 = /(?:^|[^A-Za-z0-9+\/=])([A-Za-z0-9+\/]{80,200}={0,2})(?:[^A-Za-z0-9+\/=]|$)/g;
const HTTP = /https?:\/\/[^\s"'`<>{}]+/i;
const SOLANA_WALLET = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/;
const KNOWN_C2_IPS = ['217.69.3.218', '140.82.52.31'];
const KNOWN_SOLANA_WALLET = '28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2';
const CREDENTIAL_THEFT = /\b(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITHUB_API_KEY|\.npmrc|\.gitconfig|git-credentials|credentials\.helper|process\.env\.(npm|github|git))\b/i;
const VSCODE_EXTENSION_API = /\b(vscode\.(workspace|window|commands|extensions)|chrome\.runtime|browser\.runtime|chrome\.storage|browser\.storage)\b/;
const CRYPTO_WALLET_EXT = /\b(metamask|phantom|solflare|slope|sollet|coinbase.*wallet|trust.*wallet|ledger|trezor)\b/i;

/**
 * Detects if a buffer contains binary data by sampling control characters
 * @param {Buffer} buf - The buffer to check
 * @returns {boolean} True if likely binary
 */
function isBinaryLikely(buf) {
  let weird = 0;
  const len = Math.min(buf.length, 4096);
  for (let i = 0; i < len; i++) {
    const c = buf[i];
    if (c === 0) return true;
    if (c < 9 || (c > 13 && c < 32)) weird++;
  }
  return weird > len * 0.1;
}

/**
 * Safely decodes a base64 string
 * @param {string} s - The base64 string
 * @returns {string|null} Decoded text or null if invalid
 */
function decodeB64(s) {
  try {
    const buf = Buffer.from(s, 'base64');
    if (!buf.length) return null;
    const text = buf.toString('utf8');
    if (isBinaryLikely(buf)) return null;
    return text;
  } catch { return null; }
}

/**
 * Checks if file extension is a supported code file
 * @param {string} ext - File extension
 * @param {string} file - Full file path
 * @returns {boolean} True if supported
 */
function jsLike(ext, file) {
  if (ext === '.json') return path.basename(file) === 'package.json';
  return ALLOWED_EXT.has(ext);
}

/**
 * Checks if a filename should be ignored
 * @param {string} name - Filename
 * @returns {boolean} True if should be ignored
 */
function ignoreName(name) {
  if (IGNORE_FILES.has(name)) return true;
  for (const suf of SKIP_SUFFIX) if (name.endsWith(suf)) return true;
  return false;
}

/**
 * Recursively walks directory tree, executing callback for each file
 * @param {string} root - Root directory to walk
 * @param {Function} cb - Callback function(filepath, filename)
 */
async function walk(root, cb) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = await fs.readdir(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!IGNORE_DIRS.has(e.name)) stack.push(full);
      } else if (e.isFile()) {
        cb(full, e.name);
      }
    }
  }
}

/**
 * Extracts a snippet of text around a given index
 * @param {string} text - Source text
 * @param {number} idx - Center index
 * @param {number} span - Characters to include on each side
 * @returns {string} Normalized snippet
 */
function sliceSnippet(text, idx, span = 140) {
  const s = Math.max(0, idx - Math.floor(span/2));
  const e = Math.min(text.length, idx + Math.floor(span/2));
  return text.slice(s, e).replace(/\s+/g, ' ');
}

/**
 * Calculates severity score for detected findings
 * Score is additive based on detected patterns, max 100
 * @param {Object} parts - Detection results object
 * @returns {number} Score 0-100
 */
function scoreFinding(parts) {
  let score = 0;
  if (parts.invisInIdentifier) score += 40;
  if (parts.invisAnywhere) score += 10;
  if (parts.suspiciousWords) score += 25;
  if (parts.netFuncs) score += 15;
  if (parts.dangerous) score += 25;
  if (parts.shellDownload) score += 35;
  if (parts.hardcodedIp) score += 20;
  if (parts.b64UrlDecoded) score += 45;
  if (parts.pkgPostInstall) score += 40;
  if (parts.pkgExecNet) score += 30;
  if (parts.fileIsExecutableScript) score += 10;
  if (parts.knownC2Infrastructure) score += 60;
  if (parts.solanaBlockchainC2) score += 50;
  if (parts.googleCalendarC2) score += 50;
  if (parts.credentialTheft) score += 35;
  if (parts.vsCodeExtensionAPI) score += 20;
  if (parts.cryptoWalletTargeting) score += 30;
  if (parts.multipleSignals >= 3) score += 15;
  return Math.min(score, 100);
}

/**
 * Classifies finding severity based on score
 * @param {number} score - Severity score
 * @returns {string} Classification: 'critical', 'high', 'medium', 'low'
 */
function classify(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

/**
 * Analyzes a file for malicious patterns
 * @param {string} file - File path to inspect
 * @returns {Promise<Object|null>} Finding object or null if below threshold
 */
async function inspect(file) {
  const base = path.basename(file);
  if (ignoreName(base)) return null;
  let st;
  try { st = await fs.stat(file); } catch { return null; }
  if (st.size > MAX_BYTES) return null;

  const ext = path.extname(file).toLowerCase();
  if (!jsLike(ext, file)) return null;

  let buf;
  try { buf = await fs.readFile(file); } catch { return null; }
  if (isBinaryLikely(buf)) return null;

  const text = buf.toString('utf8');
  // Truncate very large files for regex matching to prevent catastrophic backtracking
  const textForRegex = text.length > 500000 ? text.slice(0, 500000) : text;

  const parts = {
    invisInIdentifier: false,
    invisAnywhere: false,
    suspiciousWords: false,
    netFuncs: false,
    dangerous: false,
    shellDownload: false,
    hardcodedIp: false,
    b64UrlDecoded: false,
    pkgPostInstall: false,
    pkgExecNet: false,
    fileIsExecutableScript: false,
    knownC2Infrastructure: false,
    solanaBlockchainC2: false,
    googleCalendarC2: false,
    credentialTheft: false,
    vsCodeExtensionAPI: false,
    cryptoWalletTargeting: false,
    multipleSignals: 0
  };
  const details = {};

  if (ext !== '.json') {
    const matchId = textForRegex.match(INVIS_ID);
    if (matchId && matchId.length) {
      parts.invisInIdentifier = true;
      details.invisIdentifiers = [...new Set(matchId.slice(0, 5))];
    } else if (INVIS.test(textForRegex)) {
      parts.invisAnywhere = true;
    }

    if (SUS_WORDS.test(textForRegex)) {
      parts.suspiciousWords = true;
      const m = SUS_WORDS.exec(textForRegex);
      details.suspiciousWords = { match: m[0], snippet: sliceSnippet(textForRegex, m.index) };
    }

    if (NET_FUNCS.test(textForRegex)) {
      parts.netFuncs = true;
    }

    if (DANGEROUS.test(textForRegex)) {
      parts.dangerous = true;
    }

    if (SHELL_DOWNLOAD.test(textForRegex)) {
      parts.shellDownload = true;
    }

    const ips = [...textForRegex.matchAll(IP)].map(m => m[0]).filter(ip => !ip.startsWith('127.') && !ip.startsWith('0.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.16.'));
    if (ips.length) {
      parts.hardcodedIp = true;
      details.ips = [...new Set(ips)].slice(0, 8);
      // Check for known C2 infrastructure
      const knownIps = ips.filter(ip => KNOWN_C2_IPS.includes(ip));
      if (knownIps.length) {
        parts.knownC2Infrastructure = true;
        details.knownC2Ips = knownIps;
      }
    }

    // Check for Solana blockchain C2 patterns
    if (SOLANA_WALLET.test(textForRegex)) {
      const wallets = [...textForRegex.matchAll(SOLANA_WALLET)].map(m => m[0]);
      const hasKnownWallet = wallets.includes(KNOWN_SOLANA_WALLET);
      const hasSolanaKeywords = /\b(getTransaction|getParsedTransaction|memo|@solana\/web3|Connection)\b/.test(textForRegex);
      if (hasKnownWallet || (wallets.length && hasSolanaKeywords)) {
        parts.solanaBlockchainC2 = true;
        details.solanaWallets = [...new Set(wallets)].slice(0, 5);
        if (hasKnownWallet) details.hasKnownMaliciousWallet = true;
      }
    }

    // Check for Google Calendar C2
    if (/calendar\.app\.google/i.test(textForRegex)) {
      parts.googleCalendarC2 = true;
      const calendarUrls = [...textForRegex.matchAll(/calendar\.app\.google\/[A-Za-z0-9]+/gi)].map(m => m[0]);
      details.calendarUrls = [...new Set(calendarUrls)].slice(0, 3);
    }

    // Check for credential theft patterns
    if (CREDENTIAL_THEFT.test(textForRegex)) {
      parts.credentialTheft = true;
      const matches = [...textForRegex.matchAll(CREDENTIAL_THEFT)].map(m => m[0]);
      details.credentialPatterns = [...new Set(matches)].slice(0, 5);
    }

    // Check for VS Code extension API usage
    if (VSCODE_EXTENSION_API.test(textForRegex)) {
      parts.vsCodeExtensionAPI = true;
    }

    // Check for cryptocurrency wallet extension targeting
    if (CRYPTO_WALLET_EXT.test(textForRegex)) {
      parts.cryptoWalletTargeting = true;
      const matches = [...textForRegex.matchAll(CRYPTO_WALLET_EXT)].map(m => m[0]);
      details.targetedWallets = [...new Set(matches)].slice(0, 10);
    }

    const b64Hits = [];
    let b64Count = 0;
    for (const m of textForRegex.matchAll(B64)) {
      if (++b64Count > 50) break; // Limit iterations
      const b64str = m[1] || m[0];
      const decoded = decodeB64(b64str);
      if (!decoded) continue;
      if (HTTP.test(decoded) || /(?:fetch|XMLHttpRequest|atob|Function|eval)\s*\(/.test(decoded)) {
        b64Hits.push({ b64Preview: b64str.slice(0, 80) + (b64str.length > 80 ? '…' : ''), decodedPreview: decoded.slice(0, 200).replace(/\s+/g, ' ') });
      }
    }
    if (b64Hits.length) {
      parts.b64UrlDecoded = true;
      details.base64 = b64Hits.slice(0, 3);
    }
  } else if (path.basename(file) === 'package.json') {
    try {
      const pj = JSON.parse(text);
      const scripts = pj.scripts || {};
      const sus = {};
      for (const [k, v] of Object.entries(scripts)) {
        const nameHit = /^(postinstall|preinstall|install|prepare|prepublish(Only)?)$/i.test(k);
        const netHit = HTTP.test(v) || SHELL_DOWNLOAD.test(v);
        const execHit = DANGEROUS.test(v) || /\b(node|sh|bash|powershell)\b/.test(v);
        if (nameHit && (netHit || execHit)) sus[k] = v;
      }
      if (Object.keys(sus).length) {
        parts.pkgPostInstall = true;
        details.pkgScripts = sus;
      } else {
        const execNet = Object.entries(scripts).filter(([k,v]) => HTTP.test(v) && /\b(sh|bash|powershell|curl|wget|node)\b/.test(v));
        if (execNet.length) {
          parts.pkgExecNet = true;
          details.pkgExecNet = Object.fromEntries(execNet.slice(0, 5));
        }
      }
      if (pj.bin && typeof pj.bin === 'object' && Object.keys(pj.bin).length) {
        parts.fileIsExecutableScript = true;
      }
      // Check for VS Code extension indicators
      if (pj.engines && pj.engines.vscode) {
        parts.vsCodeExtensionAPI = true;
        details.vsCodeEngine = pj.engines.vscode;
        if (pj.activationEvents) {
          details.activationEvents = pj.activationEvents;
        }
      }
    } catch {}
  }

  parts.multipleSignals = [
    parts.invisInIdentifier, parts.suspiciousWords, parts.netFuncs, parts.dangerous,
    parts.shellDownload, parts.hardcodedIp, parts.b64UrlDecoded, parts.pkgPostInstall, parts.pkgExecNet,
    parts.solanaBlockchainC2, parts.googleCalendarC2, parts.credentialTheft, parts.cryptoWalletTargeting
  ].filter(Boolean).length;

  const score = scoreFinding(parts);
  const level = classify(score);
  if (level === 'low' && !INCLUDE_LOW) {
    if (score < MIN_SCORE) return null;
  }
  return {
    file,
    level,
    score,
    signals: Object.fromEntries(Object.entries(parts).filter(([,v]) => v)),
    details
  };
}

/**
 * Main scanner entry point - orchestrates file discovery and analysis
 */
async function main() {
  const queue = [];
  console.log(`Scanning ${ROOT}...`);
  await walk(ROOT, (f) => queue.push(f));
  console.log(`Found ${queue.length} files to inspect`);

  const out = [];
  const skipped = [];
  let processed = 0;
  const total = queue.length;
  const startTime = Date.now();
  
  const progressInterval = CI_MODE ? null : setInterval(() => {
    const pct = total > 0 ? Math.floor((processed / total) * 100) : 0;
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    process.stdout.write(`\rProgress: ${processed}/${total} (${pct}%) | ${elapsed}s elapsed | ${out.length} findings | ${skipped.length} skipped`);
  }, 500);

  async function inspectWithTimeout(file, ms) {
    return Promise.race([
      inspect(file),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms))
    ]);
  }

  const workers = Array.from({ length: CONCURRENCY }, async () => {
    let f;
    while ((f = queue.pop()) !== undefined) {
      try {
        const r = await inspectWithTimeout(f, INSPECT_TIMEOUT);
        if (r) out.push(r);
      } catch (err) {
        if (err.message === 'timeout') {
          skipped.push({ file: f, reason: 'timeout' });
        }
      }
      processed++;
    }
  });
  await Promise.all(workers);
  
  if (progressInterval) clearInterval(progressInterval);
  const elapsed = Math.floor((Date.now() - startTime) / 1000);
  if (CI_MODE) {
    console.log(`Scanned ${processed}/${total} files in ${elapsed}s | ${out.length} findings | ${skipped.length} skipped`);
  } else {
    process.stdout.write(`\rProgress: ${processed}/${total} (100%) | ${elapsed}s elapsed | ${out.length} findings | ${skipped.length} skipped\n`);
    console.log('\nInspection complete.');
  }
  
  if (skipped.length) {
    console.log(`\n${skipped.length} files skipped due to timeout:`);
    for (const s of skipped.slice(0, 10)) {
      console.log(`  ${s.file}`);
    }
    if (skipped.length > 10) console.log(`  ... and ${skipped.length - 10} more`);
  }

  out.sort((a,b) => b.score - a.score || a.file.localeCompare(b.file));

  const grouped = out.reduce((acc, r) => {
    (acc[r.level] ||= []).push(r);
    return acc;
  }, {});

  const summary = Object.fromEntries(['critical','high','medium','low'].map(k => [k, (grouped[k] || []).length]));
  const result = {
    scannedPath: path.resolve(ROOT),
    timestamp: new Date().toISOString(),
    threshold: { minScore: MIN_SCORE, includeLow: INCLUDE_LOW },
    summary,
    findings: grouped
  };

  const printable = ['critical','high','medium'].flatMap(k => (grouped[k] || [])).slice(0, 500);
  console.log(`\nGlassWorm scan summary @ ${result.scannedPath}`);
  console.table(summary);
  
  if (!CI_MODE || printable.length > 0) {
    console.log('\nTop findings:');
    for (const r of printable) {
      console.log(`[${r.level.toUpperCase()} ${r.score}] ${r.file}`);
      const s = Object.keys(r.signals).join(', ');
      console.log(`  signals: ${s}`);
      if (r.details.invisIdentifiers) console.log(`  invisIdentifiers: ${r.details.invisIdentifiers.join(', ')}`);
      if (r.details.ips) console.log(`  ips: ${r.details.ips.join(', ')}`);
      if (r.details.pkgScripts) console.log(`  pkgScripts: ${JSON.stringify(r.details.pkgScripts)}`);
      if (r.details.pkgExecNet) console.log(`  pkgExecNet: ${JSON.stringify(r.details.pkgExecNet)}`);
      if (r.details.base64) console.log(`  base64-decoded: ${r.details.base64.map(x => x.decodedPreview).join(' | ')}`);
      if (r.details.suspiciousWords) console.log(`  suspiciousWords: ${r.details.suspiciousWords.match} …${r.details.suspiciousWords.snippet}…`);
    }
  }

  await fs.writeFile('glassworm-scan-report.json', JSON.stringify(result, null, 2), 'utf8');
  console.log('\nReport written to ./glassworm-scan-report.json');
  
  // Determine exit code based on FAIL_ON threshold
  let exitCode = 0;
  if (FAIL_ON !== 'none') {
    const levels = ['critical', 'high', 'medium', 'low'];
    const failIndex = levels.indexOf(FAIL_ON);
    if (failIndex >= 0) {
      const shouldFail = levels.slice(0, failIndex + 1).some(level => summary[level] > 0);
      if (shouldFail) {
        exitCode = 1;
        console.log(`\n❌ Scan failed: Found ${summary.critical || 0} critical, ${summary.high || 0} high, ${summary.medium || 0} medium, ${summary.low || 0} low severity findings (threshold: ${FAIL_ON})`);
      } else {
        console.log(`\n✅ Scan passed: No findings at or above ${FAIL_ON} severity threshold`);
      }
    }
  }
  
  process.exit(exitCode);
}

main().catch(e => { console.error(e); process.exit(2); });
