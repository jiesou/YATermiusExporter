'use strict';

const crypto = require('crypto');
const os = require('os');
const path = require('path');
const fs = require('fs');

const BOM = '\ufeff';

const LABEL_FIELDS = ['label', 'title', 'name', 'nickname'];
const HOST_FIELDS = ['host', 'hostname', 'hostname_ip', 'address', 'ip'];
const USERNAME_FIELDS = ['user_name', 'username', 'login', 'user'];
const PASSWORD_FIELDS = ['password', 'pass', 'ssh_password', 'sshPassword'];
const PORT_FIELDS = ['port', 'ssh_port'];
const PROTOCOL_FIELDS = ['connection_type', 'protocol', 'type'];
const PASSPHRASE_FIELDS = ['passphrase', 'key_passphrase', 'keyPassphrase', 'private_key_passphrase', 'privateKeyPassphrase'];
const PRIVATE_KEY_FIELDS = ['private_key', 'privateKey', 'private', 'key', 'key_body', 'keyBody', 'pem', 'identity'];
const RECORD_ID_FIELDS = ['id', '_id', 'uuid', 'uid', 'identifier', 'local_id', 'localId', '__termius_id', '__termius_local_id'];
const DIRECT_REFERENCE_ID_FIELDS = ['identity_id', 'identityId', 'credential_id', 'credentialId', 'credentials_id', 'credentialsId', 'account_id', 'accountId', 'auth_id', 'authId', 'authentication_id', 'authenticationId', 'login_id', 'loginId', 'password_id', 'passwordId', 'visible_identity_id', 'visibleIdentityId', '__termius_visible_identity_id'];
const NESTED_CREDENTIAL_FIELDS = ['identity', 'credential', 'credentials', 'auth', 'authentication', 'account', 'login_credentials', 'loginCredentials', 'ssh', 'ssh_config', 'sshConfig'];
const CREDENTIAL_LABEL_FIELDS = ['identity', 'credential', 'credentials', 'account', 'identity_label', 'identityLabel', 'credential_label', 'credentialLabel', 'account_label', 'accountLabel'];
const SSH_CONFIG_FIELDS = ['env_variables', 'envVariables', 'charset', 'agent_forwarding', 'agentForwarding', 'proxycommand', 'startup_snippet', 'startupSnippet', ...PORT_FIELDS];
const KEY_ID_FIELDS = ['key_id', 'keyId', 'private_key_id', 'privateKeyId'];
const IDENTITY_ID_FIELDS = [...RECORD_ID_FIELDS, ...DIRECT_REFERENCE_ID_FIELDS];
const ID_FIELDS = [...IDENTITY_ID_FIELDS, ...KEY_ID_FIELDS];

const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/;
const PUBLIC_HOST_KEY_RE = /^(ssh-(rsa|ed25519)|ecdsa-sha2-[^\s]+)\s+/;
const ENCRYPTED_BLOCK_RE = /BA[A-Za-z0-9+/=]{30,}/g;

function valueToString(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(valueToString).filter(Boolean).join(',');
  if (typeof value === 'object') return firstString(value, [...LABEL_FIELDS, 'value', ...ID_FIELDS]);
  return '';
}

function firstValue(obj, fields) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) {
      const value = obj[field];
      if (value !== undefined && value !== null && valueToString(value) !== '') return value;
    }
  }
  return undefined;
}

function firstString(obj, fields) {
  return valueToString(firstValue(obj, fields)).trim();
}

function csvCell(value) {
  const text = valueToString(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function csvRow(values) {
  return values.map(csvCell).join(',');
}

function addToListMap(map, key, value) {
  if (!key) return;
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

function collectRecordIds(obj) {
  return [...collectIds(obj, RECORD_ID_FIELDS)];
}

function collectIds(value, fields, ids = new Set()) {
  if (value === undefined || value === null) return ids;
  if (Array.isArray(value)) {
    value.forEach(item => collectIds(item, fields, ids));
    return ids;
  }
  if (typeof value === 'object') {
    fields.forEach(field => {
      if (!Object.prototype.hasOwnProperty.call(value, field)) return;
      const id = valueToString(value[field]).trim();
      if (id) ids.add(id);
    });
    return ids;
  }
  const id = valueToString(value).trim();
  if (id) ids.add(id);
  return ids;
}

function passwordValueToString(value, seen = new Set()) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(item => passwordValueToString(item, seen)).find(Boolean) || '';
  if (typeof value !== 'object') return '';
  if (seen.has(value)) return '';
  seen.add(value);
  for (const field of ['value', 'secret', 'plaintext', 'plain_text', 'plainText', 'text']) {
    if (Object.prototype.hasOwnProperty.call(value, field)) {
      const password = passwordValueToString(value[field], seen);
      if (password) return password;
    }
  }
  return '';
}

function firstPasswordString(obj) {
  if (!obj || typeof obj !== 'object') return '';
  for (const field of PASSWORD_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) {
      const password = passwordValueToString(obj[field]);
      if (password) return password;
    }
  }
  return '';
}

function extractPasswordFromObject(obj, { nested = false } = {}, seen = new Set(), depth = 2) {
  if (!obj || typeof obj !== 'object') return '';
  if (seen.has(obj)) return '';
  seen.add(obj);
  const direct = firstPasswordString(obj);
  if (direct) return direct;
  if (!nested || depth <= 0) return '';
  for (const field of NESTED_CREDENTIAL_FIELDS) {
    const value = obj[field];
    if (!value || typeof value !== 'object') continue;
    const candidates = Array.isArray(value) ? value : [value];
    for (const candidate of candidates) {
      const password = extractPasswordFromObject(candidate, { nested: true }, seen, depth - 1);
      if (password) return password;
    }
  }
  return '';
}

function extractNestedCredentialPassword(conn) {
  for (const field of NESTED_CREDENTIAL_FIELDS) {
    const value = conn[field];
    if (!value || typeof value !== 'object') continue;
    const candidates = Array.isArray(value) ? value : [value];
    for (const candidate of candidates) {
      const password = extractPasswordFromObject(candidate, { nested: true });
      if (password) return password;
    }
  }
  return '';
}

function extractPrivateKey(value, seen = new Set()) {
  if (!value) return '';
  if (typeof value === 'string') {
    const key = normalizePrivateKey(value);
    const match = key.match(PRIVATE_KEY_RE);
    return match ? match[0] : '';
  }
  if (typeof value !== 'object') return '';
  if (seen.has(value)) return '';
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      const key = extractPrivateKey(item, seen);
      if (key) return key;
    }
    return '';
  }
  for (const field of PRIVATE_KEY_FIELDS) {
    const key = extractPrivateKey(value[field], seen);
    if (key) return key;
  }
  for (const [field, nested] of Object.entries(value)) {
    if (/public_?key/i.test(field)) continue;
    const key = extractPrivateKey(nested, seen);
    if (key) return key;
  }
  return '';
}

function extractPassphrase(obj) {
  return firstString(obj, PASSPHRASE_FIELDS);
}

function normalizePrivateKey(value) {
  return valueToString(value)
    .replace(/\\r\\n/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .trim();
}

function normalizeProtocol(value) {
  const protocol = valueToString(value).trim().toLowerCase();
  if (!protocol) return 'ssh';
  if (protocol.includes('ssh')) return 'ssh';
  if (protocol.includes('telnet')) return 'telnet';
  if (protocol.includes('mosh')) return 'mosh';
  return protocol;
}

function normalizeTags(value) {
  if (value === undefined || value === null) return '';
  if (Array.isArray(value)) return [...new Set(value.map(item => valueToString(item).trim()).filter(Boolean))].join(',');
  return valueToString(value).trim();
}

function makeUniqueLabel(map, preferredLabel, fallbackPrefix) {
  const base = (preferredLabel || `${fallbackPrefix}_${map.size + 1}`).trim() || `${fallbackPrefix}_${map.size + 1}`;
  let label = base;
  let index = 2;
  while (map.has(label)) label = `${base}_${index++}`;
  return label;
}

function passwordFingerprint(password) {
  if (!password) return '';
  return `${password.length}:${crypto.createHash('sha256').update(password).digest('hex').slice(0, 12)}`;
}

const SECRET_FIELD_RE = /password|passphrase|private.?key|secret|token|credential/i;

module.exports = {
  BOM, LABEL_FIELDS, HOST_FIELDS, USERNAME_FIELDS, PASSWORD_FIELDS,
  PORT_FIELDS, PROTOCOL_FIELDS, PASSPHRASE_FIELDS, PRIVATE_KEY_FIELDS,
  RECORD_ID_FIELDS, DIRECT_REFERENCE_ID_FIELDS, NESTED_CREDENTIAL_FIELDS,
  CREDENTIAL_LABEL_FIELDS, SSH_CONFIG_FIELDS, KEY_ID_FIELDS,
  IDENTITY_ID_FIELDS, ID_FIELDS,
  PRIVATE_KEY_RE, PUBLIC_HOST_KEY_RE, ENCRYPTED_BLOCK_RE,
  valueToString, firstValue, firstString, csvCell, csvRow,
  addToListMap, collectRecordIds, collectIds,
  passwordValueToString, firstPasswordString,
  extractPasswordFromObject, extractNestedCredentialPassword,
  extractPrivateKey, extractPassphrase, normalizePrivateKey,
  normalizeProtocol, normalizeTags, makeUniqueLabel, passwordFingerprint,
  SECRET_FIELD_RE
};
