// agentsearch SDK tests
// (c) 2026 CyberSecAI Ltd. MIT Licensed.

'use strict';

const { generateKeys, signData } = require('./index');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

let passed = 0, failed = 0;
function assert(name, condition) {
  if (condition) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name); }
}

function run() {
  console.log('\nagentsearch SDK Tests\n' + '='.repeat(40));

  // Use temp dir for test keys
  const testDir = path.join(os.tmpdir(), 'agentsearch-test-' + Date.now());

  // 1. Key generation
  console.log('\n-- Key Generation --');
  const keys = generateKeys(testDir);
  assert('generates keys', keys.privateKey && keys.publicKey);
  assert('not existing', !keys.existing);
  assert('private key is PEM', keys.privateKey.includes('BEGIN'));
  assert('public key is PEM', keys.publicKey.includes('BEGIN PUBLIC KEY'));
  assert('key dir created', fs.existsSync(testDir));
  assert('private key file exists', fs.existsSync(path.join(testDir, 'agent.key')));
  assert('public key file exists', fs.existsSync(path.join(testDir, 'agent.pub')));

  // 1b. Security files
  console.log('\n-- Security Files --');
  assert('.gitignore created', fs.existsSync(path.join(testDir, '.gitignore')));
  assert('README.md created', fs.existsSync(path.join(testDir, 'README.md')));
  const gitignore = fs.readFileSync(path.join(testDir, '.gitignore'), 'utf8');
  assert('.gitignore blocks agent.key', gitignore.includes('agent.key'));
  assert('.gitignore blocks *.key', gitignore.includes('*.key'));
  const readme = fs.readFileSync(path.join(testDir, 'README.md'), 'utf8');
  assert('README warns about private key', readme.includes('NEVER share'));
  assert('README has recovery guidance', readme.includes('lose my private key'));
  assert('README has compromise guidance', readme.includes('steals my private key'));
  assert('README has best practices', readme.includes('Best practices'));
  assert('README has contact info', readme.includes('contact@agentsign.dev'));

  // 2. Key reuse
  console.log('\n-- Key Reuse --');
  const keys2 = generateKeys(testDir);
  assert('reuses existing keys', keys2.existing);
  assert('same private key', keys2.privateKey === keys.privateKey);
  assert('same public key', keys2.publicKey === keys.publicKey);

  // 3. Signing
  console.log('\n-- Signing --');
  const sig = signData('test message', keys.privateKey);
  assert('produces signature', typeof sig === 'string' && sig.length > 0);
  assert('signature is base64url', !sig.includes('+') && !sig.includes('/'));

  // 4. Signature verification
  console.log('\n-- Verification --');
  const verifier = crypto.createVerify('SHA256');
  verifier.update('test message');
  const valid = verifier.verify(keys.publicKey, sig, 'base64url');
  assert('signature verifies', valid);

  // 5. Tamper detection
  const verifier2 = crypto.createVerify('SHA256');
  verifier2.update('tampered message');
  const invalid = verifier2.verify(keys.publicKey, sig, 'base64url');
  assert('tampered data fails', !invalid);

  // 6. JSON signing
  console.log('\n-- JSON Signing --');
  const jsonSig = signData({ agent: 'test', ts: Date.now() }, keys.privateKey);
  assert('signs JSON objects', typeof jsonSig === 'string' && jsonSig.length > 0);

  // 7. Private key permissions (Unix only)
  if (process.platform !== 'win32') {
    console.log('\n-- Security --');
    const stats = fs.statSync(path.join(testDir, 'agent.key'));
    const mode = (stats.mode & 0o777).toString(8);
    assert('private key is 600', mode === '600');
  }

  // 8. Module exports
  console.log('\n-- Exports --');
  const mod = require('./index');
  assert('exports generateKeys', typeof mod.generateKeys === 'function');
  assert('exports signData', typeof mod.signData === 'function');
  assert('exports register', typeof mod.register === 'function');
  assert('exports search', typeof mod.search === 'function');
  assert('exports report', typeof mod.report === 'function');
  assert('exports remove', typeof mod.remove === 'function');
  assert('exports SEARCH_API', mod.SEARCH_API === 'https://agentsearch.cybersecai.co.uk');

  // Cleanup
  fs.rmSync(testDir, { recursive: true, force: true });

  console.log('\n' + '='.repeat(40));
  console.log(passed + ' passed, ' + failed + ' failed, ' + (passed + failed) + ' total');
  process.exit(failed > 0 ? 1 : 0);
}

run();
