'use strict';

const fs = require('fs');
const path = require('path');
const {
  BOM, LABEL_FIELDS, HOST_FIELDS, USERNAME_FIELDS, PASSWORD_FIELDS,
  PORT_FIELDS, PROTOCOL_FIELDS, PASSPHRASE_FIELDS,
  AGENT_FORWARDING_FIELDS, PROXY_HOST_FIELDS, PROXY_PORT_FIELDS,
  PROXY_USER_FIELDS, PROXY_COMMAND_FIELDS,
  DIRECT_REFERENCE_ID_FIELDS, KEY_ID_FIELDS,
  firstString, firstValue, csvRow, csvCell, valueToString,
  extractPassphrase, normalizeProtocol, normalizeTags,
  boolValue, sanitizeHostLabel, collectRecordIds, collectIds,
  addToListMap
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

function writeSshConfigFile(data, hostMap, outDir) {
  const idx = buildIndex(data, hostMap, outDir);

  const lines = [
    '# Generated by YATermiusExporter',
    '# https://github.com/jiesou/YATermiusExporter',
    `# Date: ${new Date().toISOString().slice(0, 10)}`,
    '#',
    '# HostName, User, Port, ForwardAgent, ProxyJump, IdentityFile are active config.',
    '# Groups, Tags, OS, charsets, etc. are saved as comments for reference.',
    ''
  ];

  hostMap.forEach((h, label) => {
    writeSshHost(lines, h, label, idx);
  });

  writeExtraHosts(lines, data, hostMap);

  const configPath = path.join(outDir, 'ssh_config');
  fs.writeFileSync(configPath, lines.join('\n') + '\n');
  return hostMap.size + (data.__extraHostCount || 0);
}

function buildIndex(data, hostMap, outDir) {
  const hdIds = new Set();
  const hdToSc = new Map();
  const hdToConn = new Map();
  const keyIdToPath = new Map();
  const hostIdToConn = new Map();

  data.hostDefinitions.forEach(hd => {
    if (hd.__termius_id) hdIds.add(String(hd.__termius_id));
    if (!hd.__termius_nearby_ids) return;
    const hdSet = new Set(hd.__termius_nearby_ids.map(String));
    hdToSc.set(hd, data.sshConfigs.filter(sc =>
      sc.__termius_nearby_ids && sc.__termius_nearby_ids.some(id => hdSet.has(String(id)))
    ));
  });

  data.connections.forEach(c => {
    if (c.host_id != null) hostIdToConn.set(String(c.host_id), c);
  });

  data.hostDefinitions.forEach(hd => {
    if (hd.__termius_id == null) return;
    const c = hostIdToConn.get(String(hd.__termius_id));
    if (c) hdToConn.set(hd, c);
  });

  data.keysByLabel.forEach((kd, label) => {
    const id = kd.__termius_id || kd.id || kd._id;
    if (id == null) return;
    const safe = label.replace(/[^a-zA-Z0-9_-]/g, '_');
    keyIdToPath.set(String(id), path.join(outDir, 'ssh_keys', `${safe}.pem`));
  });

  return { hdToSc, hdToConn, keyIdToPath, hostIdToConn, hdIds };
}

function writeSshHost(lines, h, label, idx) {
  const hd = h._raw;
  const sshConfigs = hd ? (idx.hdToSc.get(hd) || []) : [];
  const conn = hd ? idx.hdToConn.get(hd) : null;
  const hostLabel = sanitizeHostLabel(label);

  const protocol = resolveProto(h, conn, sshConfigs);
  const port = resolvePort(h, sshConfigs, protocol);
  const username = resolveUser(h, conn, hd, idx);
  const tags = resolveTags(h, conn);
  const groups = h.groups || '';
  const af = resolveAgentForwarding(hd, sshConfigs, conn);
  const pj = resolveProxyJump(hd, sshConfigs, conn);
  const idPath = resolveIdentityFile(hd, idx, conn);

  lines.push(`Host ${hostLabel}`);
  lines.push(`    HostName ${h.host}`);

  if (protocol === 'mosh') {
    if (port) lines.push(`    Port ${port}`);
    if (username) lines.push(`    User ${username}`);
    lines.push(`    # Protocol: mosh — not supported by OpenSSH, use mosh-client directly`);
    const moshPort = sshConfigs.reduce((a, s) => s.mosh_server_command ? s.mosh_server_command : a, '');
    if (moshPort) lines.push(`    # MoshServerCommand: ${moshPort}`);
    addMetaComments(lines, groups, tags);
    lines.push('');
    return;
  }

  if (protocol === 'telnet') {
    if (port) lines.push(`    Port ${port}`);
    if (username) lines.push(`    User ${username}`);
    lines.push(`    # Protocol: telnet — not supported by OpenSSH, use telnet client directly`);
    addMetaComments(lines, groups, tags);
    lines.push('');
    return;
  }

  if (port && port !== '22') lines.push(`    Port ${port}`);
  if (username) lines.push(`    User ${username}`);
  if (af) lines.push(`    ForwardAgent yes`);
  if (pj) lines.push(`    ProxyJump ${pj}`);
  if (idPath) lines.push(`    IdentityFile ${idPath}`);
  addMetaComments(lines, groups, tags);
  lines.push('');
}

function resolveProto(h, conn, sshConfigs) {
  if (conn && conn.connection_type) {
    const t = normalizeProtocol(conn.connection_type);
    if (t !== 'ssh') return t;
  }
  for (const sc of sshConfigs) {
    if (sc.use_mosh === true) return 'mosh';
  }
  if (h.protocol && h.protocol !== 'ssh') return h.protocol;
  return 'ssh';
}

function resolvePort(h, sshConfigs) {
  const scPort = sshConfigs.reduce((a, s) => s.port != null && s.port !== 22 ? String(s.port) : a, '');
  if (scPort) return scPort;
  return h.port || '';
}

function resolveUser(h, conn, hd, idx) {
  if (h.username) return h.username;
  if (conn && conn.user_name) return conn.user_name;
  return '';
}

function resolveTags(h, conn) {
  if (h.tags) return h.tags;
  if (conn && conn.tags) return normalizeTags(conn.tags);
  return '';
}

function resolveAgentForwarding(hd, sshConfigs, conn) {
  for (const sc of sshConfigs) {
    if (sc.agent_forwarding != null && boolValue(sc.agent_forwarding)) return true;
    if (sc.agentForwarding != null && boolValue(sc.agentForwarding)) return true;
  }
  if (hd) {
    if (hd.agent_forwarding != null && boolValue(hd.agent_forwarding)) return true;
    if (hd.agentForwarding != null && boolValue(hd.agentForwarding)) return true;
  }
  return false;
}

function resolveProxyJump(hd, sshConfigs, conn) {
  const objs = [hd, conn, ...sshConfigs].filter(Boolean);
  for (const obj of objs) {
    const hostValue = firstString(obj, PROXY_HOST_FIELDS);
    if (hostValue) {
      const port = firstString(obj, PROXY_PORT_FIELDS);
      const user = firstString(obj, PROXY_USER_FIELDS);
      let jump = '';
      if (user) jump = `${user}@`;
      jump += hostValue;
      if (port) jump += `:${port}`;
      return jump;
    }
    const proxyCmd = firstString(obj, PROXY_COMMAND_FIELDS);
    if (proxyCmd) return proxyCmd;
  }
  return null;
}

function resolveIdentityFile(hd, idx, conn) {
  if (conn && conn.key_id != null) {
    const p = idx.keyIdToPath.get(String(conn.key_id));
    if (p) return p;
  }

  if (!hd || !idx.hdIds.has(String(hd.__termius_id))) return null;

  const identity = idx.hostIdToConn.get(String(hd.__termius_id));
  if (!identity) return null;

  if (identity.key_id != null) {
    const p = idx.keyIdToPath.get(String(identity.key_id));
    if (p) return p;
  }
  return null;
}

function addMetaComments(lines, groups, tags) {
  if (groups) lines.push(`    # Groups: ${groups}`);
  if (tags) lines.push(`    # Tags: ${tags}`);
}

function writeExtraHosts(lines, data, hostMap) {
  const coveredIds = new Set();
  const usedLabels = new Set();
  hostMap.forEach((h, label) => {
    usedLabels.add(sanitizeHostLabel(label));
    if (h._raw && h._raw.__termius_id) coveredIds.add(String(h._raw.__termius_id));
  });

  const unique = new Map();
  data.connections.forEach(c => {
    if (c.host_id != null && coveredIds.has(String(c.host_id))) return;
    if (!c.host) return;
    const prot = c.connection_type || 'ssh';
    if (prot === 'ssh' && !c.use_mosh) return;
    const key = c.host + '|' + (c.user_name || '') + '|' + prot;
    if (unique.has(key)) return;
    unique.set(key, c);
  });

  unique.forEach(c => {
    const protocol = c.use_mosh ? 'mosh' : (c.connection_type || 'ssh');
    let label = sanitizeHostLabel(c.title || c.host);
    if (usedLabels.has(label)) label = label + '_' + protocol;
    usedLabels.add(label);

    const tags = c.tags ? normalizeTags(c.tags) : '';
    lines.push(`Host ${label}`);
    lines.push(`    HostName ${c.host}`);
    if (c.port) lines.push(`    Port ${c.port}`);
    if (c.user_name) lines.push(`    User ${c.user_name}`);
    if (protocol === 'mosh') {
      if (c.mosh_server_command) lines.push(`    # MoshServerCommand: ${c.mosh_server_command}`);
      lines.push(`    # Protocol: mosh — use mosh-client directly`);
    } else if (protocol === 'telnet') {
      lines.push(`    # Protocol: telnet — use telnet client directly`);
    }
    if (tags) lines.push(`    # Tags: ${tags}`);
    lines.push('');
  });

  data.__extraHostCount = unique.size;
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

  const configPath = path.join(outDir, 'ssh_config');
  const configCount = writeSshConfigFile(data, hostMap, outDir);
  if (configCount) result.sshConfig = { path: configPath, count: configCount };

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
  if (result.sshConfig) console.log(`    ssh_config          ${result.sshConfig.count} hosts (OpenSSH format)`);
  if (result.connections) console.log(`    connections.csv     ${result.connections.count} connections`);
  if (result.summary) console.log(`    summary.json        metadata`);
}

module.exports = { runAllExporters, printSummary };
