#!/usr/bin/env node
// agentsearch CLI - Register your agent with AgenticSearch in one command
// (c) 2026 CyberSecAI Ltd. MIT Licensed.
// Raza Sharif | contact@agentsign.dev | https://cybersecai.co.uk

'use strict';

const { generateKeys, register, search, report, remove, SEARCH_API } = require('./index');

const args = process.argv.slice(2);
const cmd = args[0];

async function main() {
  console.log('agentsearch v1.0.0 -- CyberSecAI Ltd');
  console.log(SEARCH_API + '\n');

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    console.log('Usage:');
    console.log('  agentsearch register <sourceId>     Register/claim your agent');
    console.log('  agentsearch keygen                  Generate identity keys only');
    console.log('  agentsearch search <query>          Search the trust-scored index');
    console.log('  agentsearch report <sourceId>       Report a malicious agent');
    console.log('  agentsearch remove <sourceId>       Request removal from index');
    console.log('');
    console.log('Examples:');
    console.log('  npx agentsearch register my-mcp-server');
    console.log('  npx agentsearch search "payment processing"');
    console.log('  npx agentsearch report sketchy-api');
    console.log('');
    console.log('Keys are stored in .agentsearch/ in your project directory.');
    console.log('Your private key never leaves your machine.');
    console.log('');
    console.log('Raza Sharif, CyberSecAI Ltd | contact@agentsign.dev');
    return;
  }

  if (cmd === 'keygen') {
    const keys = generateKeys();
    if (keys.existing) {
      console.log('Keys already exist at ' + keys.keyDir);
      console.log('Public key:\n' + keys.publicKey);
    } else {
      console.log('Generated ECDSA P-256 key pair');
      console.log('Saved to: ' + keys.keyDir);
      console.log('Private key: ' + keys.keyDir + '/agent.key (keep secret)');
      console.log('Public key:  ' + keys.keyDir + '/agent.pub');
      console.log('\nPublic key:\n' + keys.publicKey);
    }
    return;
  }

  if (cmd === 'register') {
    const sourceId = args[1];
    if (!sourceId) { console.error('Usage: agentsearch register <sourceId>'); process.exit(1); }
    console.log('Registering ' + sourceId + '...\n');
    try {
      const result = await register(sourceId, { contact: args[2] || '' });
      if (result.success) {
        console.log('Registered successfully!');
        console.log('Source ID:    ' + result.sourceId);
        console.log('Trust Level:  ' + result.trustLevel);
        console.log('Trust Score:  ' + result.trustScore);
        console.log('Keys:         ' + result.keys.keyDir);
        console.log(result.keys.existing ? '(Using existing keys)' : '(New keys generated)');
        console.log('\n' + result.message);
      } else {
        console.error('Registration failed: ' + result.error);
        if (result.keys) console.log('Keys at: ' + result.keys.keyDir);
        process.exit(1);
      }
    } catch (e) {
      console.error('Error: ' + e.message);
      process.exit(1);
    }
    return;
  }

  if (cmd === 'search') {
    const query = args.slice(1).join(' ');
    if (!query) { console.error('Usage: agentsearch search <query>'); process.exit(1); }
    try {
      const results = await search(query);
      if (results.results && results.results.length > 0) {
        console.log(results.results.length + ' results (' + results.searchTime + 'ms)\n');
        results.results.forEach((r, i) => {
          console.log(`#${i + 1} ${r.name} [${r.trustLevel}] ${r.signed ? 'SIGNED' : 'UNSIGNED'}`);
          console.log(`   ${r.description}`);
          console.log(`   Capabilities: ${r.capabilities.join(', ')}`);
          console.log('');
        });
      } else {
        console.log('No results for: ' + query);
      }
    } catch (e) {
      console.error('Error: ' + e.message);
      process.exit(1);
    }
    return;
  }

  if (cmd === 'report') {
    const sourceId = args[1];
    const reason = args.slice(2).join(' ') || 'Reported via CLI';
    if (!sourceId) { console.error('Usage: agentsearch report <sourceId> [reason]'); process.exit(1); }
    try {
      const result = await report(sourceId, reason);
      console.log(result.message || result.error);
    } catch (e) { console.error('Error: ' + e.message); process.exit(1); }
    return;
  }

  if (cmd === 'remove') {
    const sourceId = args[1];
    const reason = args.slice(2).join(' ') || 'Removal requested via CLI';
    if (!sourceId) { console.error('Usage: agentsearch remove <sourceId>'); process.exit(1); }
    try {
      const result = await remove(sourceId, reason);
      console.log(result.message || result.error);
    } catch (e) { console.error('Error: ' + e.message); process.exit(1); }
    return;
  }

  console.error('Unknown command: ' + cmd + '. Run "agentsearch help" for usage.');
  process.exit(1);
}

main().catch(e => { console.error(e.message); process.exit(1); });
