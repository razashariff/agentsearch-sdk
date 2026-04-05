// agentsearch - Register your AI agent with AgenticSearch
// (c) 2026 CyberSecAI Ltd. MIT Licensed.
// Raza Sharif | contact@agentsign.dev | https://cybersecai.co.uk
// https://agentsearch.cybersecai.co.uk

'use strict';

const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');

const SEARCH_API = 'https://agentsearch.cybersecai.co.uk';

// ============================================================================
// Key Management
// ============================================================================

/**
 * Generate an ECDSA P-256 key pair for agent identity.
 * Keys are saved to disk so the agent keeps the same identity across restarts.
 *
 * SECURITY:
 * - Private key file permissions set to 0o600 (owner read/write only)
 * - Public key file permissions set to 0o644 (readable by all, writable by owner)
 * - A .gitignore is auto-created to prevent accidental commits
 * - Key directory permissions set to 0o700 (owner only)
 * - Existing keys are reused, never overwritten
 * - Private key is PKCS8 PEM format, standard and portable
 */
function generateKeys(keyDir) {
  const dir = keyDir || path.join(process.cwd(), '.agentsearch');

  // Create directory with restrictive permissions
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const privPath = path.join(dir, 'agent.key');
  const pubPath = path.join(dir, 'agent.pub');
  const gitignorePath = path.join(dir, '.gitignore');
  const readmePath = path.join(dir, 'README.md');

  // Always ensure .gitignore exists to protect private key
  if (!fs.existsSync(gitignorePath)) {
    fs.writeFileSync(gitignorePath, [
      '# AgenticSearch -- Protect your private key',
      '# This file was auto-generated. Do NOT remove it.',
      'agent.key',
      '*.key',
      '*.pem',
    ].join('\n') + '\n', { mode: 0o644 });
  }

  // Always ensure README exists explaining what these files are
  if (!fs.existsSync(readmePath)) {
    fs.writeFileSync(readmePath, [
      '# AgenticSearch Identity',
      '',
      'This directory contains your agent\'s cryptographic identity for AgenticSearch.',
      '',
      '## Files',
      '',
      '- `agent.key` -- **PRIVATE KEY. Keep this safe. NEVER share, commit, or upload it.**',
      '  If compromised, anyone can impersonate your agent.',
      '- `agent.pub` -- Public key. Safe to share. This is how others verify your identity.',
      '- `.gitignore` -- Prevents accidental commit of private key. Do NOT remove.',
      '',
      '## What happens if I lose my private key?',
      '',
      'You lose the ability to prove ownership of your agent in AgenticSearch.',
      'You would need to re-register with a new key pair.',
      'Your previous trust level would need to be re-established.',
      '',
      '## What happens if someone steals my private key?',
      '',
      'They can sign messages pretending to be your agent.',
      'Generate new keys immediately: delete agent.key and agent.pub, then run',
      '`npx @proofxhq/agentsearch register <your-source-id>` again.',
      'Contact contact@agentsign.dev to revoke the compromised key.',
      '',
      '## Best practices',
      '',
      '- Back up agent.key securely (encrypted storage, password manager, HSM)',
      '- Never commit agent.key to version control',
      '- Never share agent.key over email, chat, or unencrypted channels',
      '- Set file permissions: `chmod 600 agent.key`',
      '- Rotate keys periodically by re-registering',
      '',
      'More info: https://agentsearch.cybersecai.co.uk/trust',
      '',
      'CyberSecAI Ltd | contact@agentsign.dev | https://cybersecai.co.uk',
    ].join('\n') + '\n', { mode: 0o644 });
  }

  // Return existing keys if they exist -- never overwrite
  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    // Verify private key permissions are correct (fix if not)
    try {
      const stats = fs.statSync(privPath);
      const mode = stats.mode & 0o777;
      if (mode !== 0o600) {
        fs.chmodSync(privPath, 0o600);
      }
    } catch { /* non-fatal -- Windows doesn't support chmod */ }

    return {
      privateKey: fs.readFileSync(privPath, 'utf8'),
      publicKey: fs.readFileSync(pubPath, 'utf8'),
      keyDir: dir,
      existing: true,
    };
  }

  // Generate new ECDSA P-256 key pair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Write keys with appropriate permissions
  fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });

  // Also add to project root .gitignore if it exists
  const projectGitignore = path.join(process.cwd(), '.gitignore');
  if (fs.existsSync(projectGitignore)) {
    const content = fs.readFileSync(projectGitignore, 'utf8');
    if (!content.includes('.agentsearch/agent.key') && !content.includes('.agentsearch/*.key')) {
      fs.appendFileSync(projectGitignore, '\n# AgenticSearch private key -- do NOT commit\n.agentsearch/agent.key\n.agentsearch/*.key\n');
    }
  }

  return { privateKey, publicKey, keyDir: dir, existing: false };
}

// ============================================================================
// Signing
// ============================================================================

/**
 * Sign data with the agent's private key.
 */
function signData(data, privateKey) {
  const signer = crypto.createSign('SHA256');
  signer.update(typeof data === 'string' ? data : JSON.stringify(data));
  return signer.sign(privateKey, 'base64url');
}

// ============================================================================
// API Communication
// ============================================================================

/**
 * POST JSON to AgenticSearch API.
 */
function apiCall(endpoint, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, SEARCH_API);
    const payload = JSON.stringify(body);
    const req = https.request({
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'User-Agent': 'agentsearch-sdk/1.0.1' },
      timeout: 10000,
    }, (res) => {
      let d = '';
      res.on('data', c => { d += c; if (d.length > 1e6) { res.destroy(); reject(new Error('Response too large')); } });
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error('Invalid response from AgenticSearch API')); } });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('AgenticSearch API timeout')); });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ============================================================================
// Registration
// ============================================================================

/**
 * Register agent with AgenticSearch.
 * Generates keys, claims the source, signs the challenge, verifies ownership.
 * Returns the new trust level.
 *
 * The flow:
 * 1. Generate or reuse ECDSA P-256 key pair (stored in .agentsearch/)
 * 2. Submit public key to AgenticSearch /api/claim
 * 3. Receive a cryptographic challenge
 * 4. Sign the challenge with the private key (proves ownership)
 * 5. Submit signature to /api/claim/verify
 * 6. Trust level upgraded (L0 -> L1+)
 *
 * The private key NEVER leaves the machine. Only the public key and
 * signatures are transmitted.
 */
async function register(sourceId, opts = {}) {
  if (!sourceId || typeof sourceId !== 'string') {
    return { success: false, error: 'sourceId is required and must be a string' };
  }

  const keys = generateKeys(opts.keyDir);

  // Step 1: Claim with public key (public key is safe to transmit)
  const claim = await apiCall('/api/claim', {
    sourceId,
    publicKey: keys.publicKey,
    contact: opts.contact || '',
  });

  if (claim.error) return { success: false, error: claim.error, keys };
  if (!claim.challenge) return { success: false, error: 'No challenge received', keys };

  // Step 2: Sign the challenge with private key (private key stays local)
  const signature = signData(claim.challenge, keys.privateKey);

  // Step 3: Submit signature to verify ownership
  const verify = await apiCall('/api/claim/verify', {
    sourceId,
    signature,
  });

  if (verify.error) return { success: false, error: verify.error, keys };

  return {
    success: true,
    sourceId,
    trustLevel: verify.newTrustLevel,
    trustScore: verify.newTrustScore,
    message: verify.message,
    keys,
  };
}

// ============================================================================
// Search & Reports
// ============================================================================

/**
 * Search AgenticSearch.
 */
async function search(query, opts = {}) {
  return apiCall('/api/search', {
    query,
    minTrust: opts.minTrust || 0,
    protocol: opts.protocol || null,
    category: opts.category || null,
    maxResults: opts.maxResults || 10,
  });
}

/**
 * Report a malicious agent.
 */
async function report(sourceId, reason, contact) {
  return apiCall('/api/report', { sourceId, reason, contact });
}

/**
 * Request removal from index.
 */
async function remove(sourceId, reason, contact) {
  return apiCall('/api/remove', { sourceId, reason, contact });
}

module.exports = { generateKeys, signData, register, search, report, remove, SEARCH_API };
