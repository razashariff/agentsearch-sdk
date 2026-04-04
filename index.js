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

/**
 * Generate an ECDSA P-256 key pair for agent identity.
 * Keys are saved to disk so the agent keeps the same identity across restarts.
 */
function generateKeys(keyDir) {
  const dir = keyDir || path.join(process.cwd(), '.agentsearch');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const privPath = path.join(dir, 'agent.key');
  const pubPath = path.join(dir, 'agent.pub');

  // Return existing keys if they exist
  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKey: fs.readFileSync(privPath, 'utf8'),
      publicKey: fs.readFileSync(pubPath, 'utf8'),
      keyDir: dir,
      existing: true,
    };
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });

  return { privateKey, publicKey, keyDir: dir, existing: false };
}

/**
 * Sign data with the agent's private key.
 */
function signData(data, privateKey) {
  const signer = crypto.createSign('SHA256');
  signer.update(typeof data === 'string' ? data : JSON.stringify(data));
  return signer.sign(privateKey, 'base64url');
}

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
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'User-Agent': 'agentsearch-sdk/1.0.0' },
    }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { reject(new Error('Invalid response')); } });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

/**
 * Register agent with AgenticSearch.
 * Generates keys, claims the source, signs the challenge, verifies ownership.
 * Returns the new trust level.
 */
async function register(sourceId, opts = {}) {
  const keys = generateKeys(opts.keyDir);

  // Step 1: Claim with public key
  const claim = await apiCall('/api/claim', {
    sourceId,
    publicKey: keys.publicKey,
    contact: opts.contact || '',
  });

  if (claim.error) return { success: false, error: claim.error, keys };
  if (!claim.challenge) return { success: false, error: 'No challenge received', keys };

  // Step 2: Sign the challenge
  const signature = signData(claim.challenge, keys.privateKey);

  // Step 3: Verify ownership
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
