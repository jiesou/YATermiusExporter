'use strict';

const fs = require('fs');
const path = require('path');
const {
  BOM, LABEL_FIELDS, HOST_FIELDS, USERNAME_FIELDS, PASSWORD_FIELDS,
  PORT_FIELDS, PROTOCOL_FIELDS, PASSPHRASE_FIELDS,
  firstString, firstValue, csvRow, csvCell, valueToString,
  extractPassphrase, normalizeProtocol, normalizeTags
} = require('./utils');

function writeHostsCsv(hostMap, outputPath) {
  const headers = ['Groups', 'Label', 'Tags', 'Hostname/IP', 'Protocol', 'Port', 'Username', 'Password'];
  const rows = [headers];
  hostMap.forEach(h => {
    rows.push([h.groups || '', h.label || '', h.tags || '', h.host || '', h.protocol || 'ssh', h.port || '22', h.username || '', h.password || '']);
  });
  const csv = rows.map(csvRow).join('\n') + '\n';
  fs.writeFileSync(outputPath, BOM + csv);
  return hostMap.size;
}

function writeKeys(data, outputDir) {
  if (!data.keysByLabel || data.keysByLabel.size === 0) return [];
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const results = [];
  data.keysByLabel.forEach((keyData, label) => {
    const pem = keyData.private_key;
    if (!pem) return;
    const safe = label.replace(/[^a-zA-Z0-9_-]/g, '_');

    const privPath = path.join(outputDir, `${safe}.pem`);
    let content = pem;
    const pass = extractPassphrase(keyData);
    if (pass) content += `\n# passphrase: ${pass}\n`;
    fs.writeFileSync(privPath, content);

    const pub = keyData.public_key || keyData.publicKey || '';
    if (pub) {
      fs.writeFileSync(path.join(outputDir, `${safe}.pub`), pub.trim() + '\n');
    }

    results.push({ label, path: privPath, hasPassphrase: !!pass, hasPubkey: !!pub });
  });
  return results;
}

function writeSnippets(data, outputPath) {
  if (!data.snippets || data.snippets.size === 0) return 0;
  const lines = [];
  data.snippets.forEach((s, label) => {
    lines.push(`# ======== ${label} ========`);
    if (s.auto_close) lines.push('# auto_close: true');
    if (s.script) lines.push(s.script);
    lines.push('');
  });
  fs.writeFileSync(outputPath, lines.join('\n'));
  return data.snippets.size;
}

function writePortForwards(data, outputPath) {
  if (!data.portForwards || !data.portForwards.length) return 0;
  const rows = [['Label', 'Type', 'Bind Address', 'Local Port', 'Hostname', 'Remote Port']];
  data.portForwards.forEach(pf => {
    rows.push([
      firstString(pf, LABEL_FIELDS) || '',
      firstString(pf, ['pf_type', 'pfType', 'forward_type', 'forwardType']) || '',
      firstString(pf, ['bound_address', 'bindAddress', 'bind_address']) || '',
      firstString(pf, ['local_port', 'localPort']) || '',
      firstString(pf, ['hostname', 'host', 'remote_host', 'remoteHost']) || '',
      firstString(pf, ['remote_port', 'remotePort']) || ''
    ]);
  });
  const csv = rows.map(csvRow).join('\n') + '\n';
  fs.writeFileSync(outputPath, BOM + csv);
  return data.portForwards.length;
}

function writeSshConfigs(data, outputPath) {
  if (!data.sshConfigs || !data.sshConfigs.length) return 0;
  const keys = new Set();
  data.sshConfigs.forEach(sc => Object.keys(sc).forEach(k => {
    if (k.startsWith('__') || k === 'version') return;
    keys.add(k);
  }));
  const headers = ['Label', ...keys].filter(k => !k.startsWith('_'));
  const rows = [headers];
  data.sshConfigs.forEach(sc => {
    const label = firstString(sc, LABEL_FIELDS) || firstString(sc, ['address', 'hostname', ...HOST_FIELDS]) || '';
    rows.push(headers.map(h => {
      if (h === 'Label') return label;
      return csvCell(valueToString(sc[h]));
    }));
  });
  fs.writeFileSync(outputPath, BOM + rows.map(r => r.join(',')).join('\n') + '\n');
  return data.sshConfigs.length;
}

function writeConnections(data, outputPath) {
  if (!data.connections || !data.connections.length) return 0;
  const keys = new Set();
  data.connections.forEach(c => Object.keys(c).forEach(k => {
    if (k.startsWith('__') || k === 'version') return;
    keys.add(k);
  }));
  const headers = [...keys];
  const rows = [headers];
  data.connections.forEach(c => {
    rows.push(headers.map(h => csvCell(valueToString(c[h]))));
  });
  fs.writeFileSync(outputPath, BOM + rows.map(r => r.join(',')).join('\n') + '\n');
  return data.connections.length;
}

function writeFullJson(data, outputPath) {
  const sanitized = {
    hostDefinitions: data.hostDefinitions.length,
    connections: data.connections.length,
    identities: data.identities.length,
    sshConfigs: data.sshConfigs.length,
    snippets: data.snippets.size,
    portForwards: data.portForwards.length,
    sshKeys: data.keysByLabel.size,
    knownHostKeys: data.knownHostKeys.size,
  };
  fs.writeFileSync(outputPath, JSON.stringify(sanitized, null, 2));
  return sanitized;
}

function runAllExporters(data, hostMap, outDir) {
  const result = {};

  const csvPath = path.join(outDir, 'hosts.csv');
  result.hosts = { path: csvPath, count: writeHostsCsv(hostMap, csvPath) };

  const keyDir = path.join(outDir, 'ssh_keys');
  const keys = writeKeys(data, keyDir);
  if (keys.length) result.keys = { dir: keyDir, count: keys.length, items: keys };

  const snippetPath = path.join(outDir, 'snippets.txt');
  const snippetCount = writeSnippets(data, snippetPath);
  if (snippetCount) result.snippets = { path: snippetPath, count: snippetCount };

  const pfPath = path.join(outDir, 'port_forwards.csv');
  const pfCount = writePortForwards(data, pfPath);
  if (pfCount) result.portForwards = { path: pfPath, count: pfCount };

  const scPath = path.join(outDir, 'ssh_configs.csv');
  const scCount = writeSshConfigs(data, scPath);
  if (scCount) result.sshConfigs = { path: scPath, count: scCount };

  const connPath = path.join(outDir, 'connections.csv');
  const connCount = writeConnections(data, connPath);
  if (connCount) result.connections = { path: connPath, count: connCount };

  const jsonPath = path.join(outDir, 'summary.json');
  result.summary = { path: jsonPath, ...writeFullJson(data, jsonPath) };

  return result;
}

function printSummary(result) {
  console.log('');
  console.log('  Exports:');
  if (result.hosts) console.log(`    hosts.csv           ${result.hosts.count} hosts`);
  if (result.keys) console.log(`    ssh_keys/           ${result.keys.count} keys`);
  if (result.snippets) console.log(`    snippets.txt        ${result.snippets.count} snippets`);
  if (result.portForwards) console.log(`    port_forwards.csv   ${result.portForwards.count} port forwards`);
  if (result.sshConfigs) console.log(`    ssh_configs.csv     ${result.sshConfigs.count} SSH configs`);
  if (result.connections) console.log(`    connections.csv     ${result.connections.count} connections`);
  if (result.summary) console.log(`    summary.json        metadata`);
}

module.exports = { runAllExporters, printSummary };
