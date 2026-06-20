'use strict';

const {
  LABEL_FIELDS, HOST_FIELDS, USERNAME_FIELDS, PASSWORD_FIELDS,
  PORT_FIELDS, PROTOCOL_FIELDS, SSH_CONFIG_FIELDS, RECORD_ID_FIELDS,
  DIRECT_REFERENCE_ID_FIELDS, NESTED_CREDENTIAL_FIELDS, CREDENTIAL_LABEL_FIELDS,
  PRIVATE_KEY_FIELDS, PRIVATE_KEY_RE, PUBLIC_HOST_KEY_RE,
  firstString, firstValue, valueToString, firstPasswordString,
  extractPasswordFromObject, extractPrivateKey, normalizePrivateKey,
  extractPassphrase, addToListMap, collectRecordIds, collectIds,
  makeUniqueLabel, normalizeProtocol, normalizeTags, passwordValueToString
} = require('./utils');

const FIELD_LEVEL_RECORD_PARTS = new Set([
  'label', 'username', 'user_name', 'password', 'address', 'hostname',
  'host', 'hostname_ip', 'ip', 'title', 'port', 'ssh_port',
  'connection_type', 'protocol'
]);

function parseDecryptedData(results) {
  const identities = [];
  const identitiesByUser = new Map();
  const identitiesById = new Map();
  const identitiesByLabel = new Map();
  const keysByLabel = new Map();
  const groupsById = new Map();
  const connections = [];
  const sshConfigs = [];
  const hostDefinitions = [];
  const snippets = new Map();
  const knownHostKeys = new Map();
  const portForwards = [];
  const fieldParts = [];
  const unknown = [];

  results.forEach((result, index) => {
    const raw = result.text.trim();
    const meta = result.meta || {};
    if (!raw) return;

    if (!isJSON(raw)) {
      if (FIELD_LEVEL_RECORD_PARTS.has(meta.encryptedField)) {
        fieldParts.push({
          field: meta.encryptedField, value: raw, meta,
          file: result.file || '', sequence: result.sequence,
          recordIndex: index, valueIndex: result.index
        });
        return;
      }
      addKey(keysByLabel, raw, '', 'raw');
      return;
    }

    try {
      const parsed = JSON.parse(raw);
      const objects = Array.isArray(parsed) ? parsed : [parsed];

      objects.forEach(obj => {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
        applyMetaIds(obj, meta);

        if (isPortForwardRecord(obj)) { portForwards.push(obj); return; }
        if (isIdentityRecord(obj)) {
          const username = firstString(obj, USERNAME_FIELDS);
          identities.push(obj);
          addToListMap(identitiesByUser, username, obj);
          const label = firstString(obj, LABEL_FIELDS);
          addToListMap(identitiesByLabel, label, obj);
          collectRecordIds(obj).forEach(id => {
            if (!identitiesById.has(id) || extractPasswordFromObject(obj, { nested: true })) {
              identitiesById.set(id, obj);
            }
          });
        }

        addKey(keysByLabel, obj, firstString(obj, LABEL_FIELDS) || `key_${index + 1}`, 'json');
        if (isKnownHostKeyRecord(obj)) knownHostKeys.set(obj.key, obj);

        if (isGroupRecord(obj)) groupsById.set(collectRecordIds(obj)[0], obj);
        if (isConnectionRecord(obj)) connections.push(obj);

        if (isSshConfigRecord(obj) && !sshConfigs.includes(obj)) sshConfigs.push(obj);
        if (isHostDefinitionRecord(obj) && !hostDefinitions.includes(obj)) hostDefinitions.push(obj);

        if (obj.script && firstString(obj, LABEL_FIELDS)) snippets.set(firstString(obj, LABEL_FIELDS), obj);
      });
    } catch { unknown.push(raw); }
  });

  const data = {
    identities, identitiesByUser, identitiesById, identitiesByLabel,
    keysByLabel, groupsById, connections, sshConfigs, hostDefinitions,
    snippets, knownHostKeys, portForwards
  };

  attachPasswordFragmentsById(data, fieldParts);
  attachFieldLevelIdentities(data, fieldParts);
  return data;
}

function isJSON(text) {
  const t = text.trim();
  return t.startsWith('{') || t.startsWith('[');
}

function applyMetaIds(obj, meta) {
  if (!obj || typeof obj !== 'object' || !meta) return obj;
  if (meta.id) obj.__termius_id = meta.id;
  if (meta.local_id) obj.__termius_local_id = meta.local_id;
  if (meta.host_id) obj.__termius_host_id = meta.host_id;
  if (meta.visible_identity_id) obj.__termius_visible_identity_id = meta.visible_identity_id;
  if (Array.isArray(meta.identity_object_ids) && meta.identity_object_ids.length) {
    obj.__termius_identity_object_id = meta.identity_object_ids.at(-1);
    obj.__termius_identity_object_ids = meta.identity_object_ids;
  }
  if (Array.isArray(meta.identity_object_local_ids) && meta.identity_object_local_ids.length) {
    obj.__termius_identity_object_local_id = meta.identity_object_local_ids.at(-1);
    obj.__termius_identity_object_local_ids = meta.identity_object_local_ids;
  }
  if (Array.isArray(meta.identity_object_refs) && meta.identity_object_refs.length) {
    obj.__termius_identity_object_refs = meta.identity_object_refs;
  }
  if (Array.isArray(meta.ssh_config_object_ids) && meta.ssh_config_object_ids.length) {
    obj.__termius_ssh_config_object_id = meta.ssh_config_object_ids.at(-1);
    obj.__termius_ssh_config_object_ids = meta.ssh_config_object_ids;
  }
  if (Array.isArray(meta.ssh_config_object_local_ids) && meta.ssh_config_object_local_ids.length) {
    obj.__termius_ssh_config_object_local_id = meta.ssh_config_object_local_ids.at(-1);
    obj.__termius_ssh_config_object_local_ids = meta.ssh_config_object_local_ids;
  }
  if (Array.isArray(meta.ssh_config_object_refs) && meta.ssh_config_object_refs.length) {
    obj.__termius_ssh_config_object_refs = meta.ssh_config_object_refs;
  }
  if (Array.isArray(meta.nearby_ids)) obj.__termius_nearby_ids = meta.nearby_ids;
  if (meta.encryptedField) obj.__termius_encrypted_field = meta.encryptedField;
  return obj;
}

function isConnectionRecord(obj) {
  const host = firstString(obj, HOST_FIELDS);
  if (!host) return false;
  return Boolean(firstString(obj, USERNAME_FIELDS) || firstString(obj, PROTOCOL_FIELDS) || firstString(obj, PORT_FIELDS));
}

function isIdentityRecord(obj) {
  if (isConnectionRecord(obj)) return false;
  return Boolean(firstString(obj, USERNAME_FIELDS) && extractPasswordFromObject(obj, { nested: true }) && !extractPrivateKey(obj));
}

function isGroupRecord(obj) {
  if (isConnectionRecord(obj)) return false;
  const id = collectRecordIds(obj)[0];
  const label = firstString(obj, LABEL_FIELDS);
  if (!id || !label) return false;
  const type = firstString(obj, ['type', 'entity_type', 'entityType', 'record_type', 'recordType', 'kind', 'collection']);
  return /group|folder/i.test(type) || obj.parent_id !== undefined || obj.parentId !== undefined;
}

function isSshConfigRecord(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  if (isConnectionRecord(obj) || isKnownHostKeyRecord(obj) || isIdentityRecord(obj)) return false;
  return SSH_CONFIG_FIELDS.some(f => Object.prototype.hasOwnProperty.call(obj, f)) ||
    (Array.isArray(obj.__termius_identity_object_refs) && obj.__termius_identity_object_refs.length);
}

function isHostDefinitionRecord(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  if (isConnectionRecord(obj) || isKnownHostKeyRecord(obj) || isIdentityRecord(obj)) return false;
  return Boolean(firstString(obj, ['address', 'hostname']) && (firstString(obj, LABEL_FIELDS) || Array.isArray(obj.__termius_ssh_config_object_refs)));
}

function isKnownHostKeyRecord(obj) {
  return Boolean(obj && typeof obj === 'object' && !Array.isArray(obj) &&
    typeof obj.key === 'string' && PUBLIC_HOST_KEY_RE.test(obj.key.trim()) &&
    (obj.hostnames !== undefined || obj.hostname !== undefined));
}

function isPortForwardRecord(obj) {
  return obj && typeof obj === 'object' && firstString(obj, ['pf_type', 'pfType', 'forward_type', 'forwardType']);
}

function addKey(keysByLabel, keyData, preferredLabel, source) {
  const privateKey = extractPrivateKey(keyData);
  if (!privateKey) return false;
  for (const existing of keysByLabel.values()) {
    if (existing.private_key === privateKey) return false;
  }
  const label = makeUniqueLabel(keysByLabel, preferredLabel, 'ssh_key');
  keysByLabel.set(label, {
    ...((keyData && typeof keyData === 'object' && !Array.isArray(keyData)) ? keyData : {}),
    label, source, private_key: privateKey
  });
  return true;
}

function attachPasswordFragmentsById(data, fieldParts) {
  data.passwordsById = data.passwordsById || new Map();
  fieldParts.forEach(part => {
    if (part.field !== 'password' || !part.meta?.id) return;
    const password = passwordValueToString(part.value);
    if (!password) return;
    if (!data.passwordsById.has(part.meta.id)) data.passwordsById.set(part.meta.id, new Set());
    data.passwordsById.get(part.meta.id).add(password);
  });
}

function attachFieldLevelIdentities(data, fieldParts) {
  const byId = new Map();
  fieldParts.forEach(part => {
    const keys = collectFieldPartKeys(part);
    keys.forEach(key => {
      if (!byId.has(key.key)) {
        byId.set(key.key, { __termius_nearby_id_entries: [], __termius_field_identity: true, __termius_field_order: part.recordIndex });
      }
      const record = byId.get(key.key);
      applyFieldPartKey(record, key);
      record.__termius_field_order = Math.min(record.__termius_field_order ?? part.recordIndex, part.recordIndex);
      if (!record[part.field]) record[part.field] = part.value;
      if (Array.isArray(part.meta.nearby_id_entries)) record.__termius_nearby_id_entries.push(...part.meta.nearby_id_entries);
    });
  });

  const records = [...byId.values()];
  records.forEach(r => {
    if (Array.isArray(r.__termius_nearby_id_entries)) {
      r.__termius_nearby_ids = r.__termius_nearby_id_entries.map(e => e.value);
    }
  });
  pairFieldLevelHostCredentials(records);
  records.forEach(r => {
    addFieldIdentityCandidate(data, identityFromFieldRecord(r));
    addFieldHostDefinitionCandidate(data, r);
  });
}

function collectFieldPartKeys(part) {
  const meta = part.meta || {};
  const keys = [];
  if (meta.id) keys.push({ type: 'id', value: meta.id, key: `id:${meta.id}` });
  if (meta.local_id) keys.push({ type: 'local_id', value: meta.local_id, key: `local:${meta.local_id}` });
  if (!keys.length) {
    const source = part.file && part.sequence !== undefined ? `${part.file}:${part.sequence}` : `idx:${part.recordIndex ?? ''}`;
    keys.push({ type: 'source', value: source, key: `source:${source}` });
  }
  return keys;
}

function applyFieldPartKey(record, key) {
  if (key.type === 'id' && !record.__termius_id) record.__termius_id = key.value;
  if (key.type === 'local_id' && !record.__termius_local_id) record.__termius_local_id = key.value;
}

function identityFromFieldRecord(record) {
  const identity = { __termius_field_identity: true };
  if (record.__termius_id) identity.__termius_id = record.__termius_id;
  if (record.__termius_local_id) identity.__termius_local_id = record.__termius_local_id;
  const label = firstString(record, ['label', 'title']);
  const username = firstString(record, USERNAME_FIELDS);
  const password = firstPasswordString(record);
  if (label) identity.label = label;
  if (username) identity.username = username;
  if (password) identity.password = password;
  return identity;
}

function addFieldIdentityCandidate(data, identity) {
  if (!isIdentityRecord(identity)) return;
  data.identities.push(identity);
  addToListMap(data.identitiesByUser, firstString(identity, USERNAME_FIELDS), identity);
  addToListMap(data.identitiesByLabel, firstString(identity, LABEL_FIELDS), identity);
  collectRecordIds(identity).forEach(id => {
    if (!data.identitiesById.has(id) || extractPasswordFromObject(identity, { nested: true })) {
      data.identitiesById.set(id, identity);
    }
  });
}

function addFieldHostDefinitionCandidate(data, record) {
  const host = firstString(record, ['address', 'hostname', ...HOST_FIELDS]);
  if (!host) return;
  const username = firstString(record, USERNAME_FIELDS);
  const label = firstString(record, ['label', 'title']) || host;
  const protocol = normalizeProtocol(firstString(record, PROTOCOL_FIELDS));
  const port = firstString(record, PORT_FIELDS) || (protocol === 'ssh' ? '22' : '');
  const password = firstPasswordString(record);
  if (!label && !username && !password) return;
  data.hostDefinitions.push({ ...record, address: host, label, username, password, protocol, port, __termius_field_host_definition: true });
}

function pairFieldLevelHostCredentials(records) {
  const ordered = records.slice().sort((a, b) => (a.__termius_field_order ?? 0) - (b.__termius_field_order ?? 0));
  const hosts = ordered.filter(r => firstString(r, ['address', 'hostname', ...HOST_FIELDS]));
  const credentials = ordered.filter(r => !firstString(r, ['address', 'hostname', ...HOST_FIELDS]) && (firstPasswordString(r) || firstString(r, USERNAME_FIELDS)));

  credentials.forEach(cred => {
    const host = findNearestBefore(ordered, cred, hosts) || findNearestAfter(ordered, cred, hosts);
    if (!host) return;
    const username = firstString(cred, USERNAME_FIELDS);
    const password = firstPasswordString(cred);
    if (username && !firstString(host, USERNAME_FIELDS)) host.username = username;
    if (password && !firstPasswordString(host)) host.password = password;
  });
}

function findNearestBefore(ordered, ref, candidates) {
  const idx = ordered.indexOf(ref);
  let best = null, bestDist = Infinity;
  candidates.forEach(h => {
    const hi = ordered.indexOf(h);
    if (hi >= 0 && hi < idx && (idx - hi) < bestDist && !firstPasswordString(h)) {
      best = h; bestDist = idx - hi;
    }
  });
  return bestDist <= 8 ? best : null;
}

function findNearestAfter(ordered, ref, candidates) {
  const idx = ordered.indexOf(ref);
  let best = null, bestDist = Infinity;
  candidates.forEach(h => {
    const hi = ordered.indexOf(h);
    if (hi >= 0 && hi > idx && (hi - idx) < bestDist && !firstPasswordString(h)) {
      best = h; bestDist = hi - idx;
    }
  });
  return bestDist <= 8 ? best : null;
}

function buildHostConfig(data) {
  const selected = selectHostDefinitions(data);
  if (selected.hostDefinitions.length) {
    return buildFromHostDefinitions(data, selected.hostDefinitions);
  }
  return buildFromConnections(data);
}

function selectHostDefinitions(data) {
  const structured = data.hostDefinitions.filter(hd => !hd.__termius_field_host_definition);
  if (structured.length) return { hostDefinitions: structured, source: 'hostDefinitions' };
  const field = data.hostDefinitions.filter(hd => hd.__termius_field_host_definition);
  if (field.length) return { hostDefinitions: field, source: 'fieldHostDefinitions' };
  return { hostDefinitions: [], source: '' };
}

function buildFromHostDefinitions(data, hostDefinitions) {
  const hostMap = new Map();
  hostDefinitions.forEach(hd => {
    const host = firstString(hd, ['address', 'hostname', ...HOST_FIELDS]);
    if (!host) return;
    const label = firstString(hd, LABEL_FIELDS) || host;
    const username = firstString(hd, USERNAME_FIELDS);
    const password = firstPasswordString(hd);
    const protocol = normalizeProtocol(firstString(hd, PROTOCOL_FIELDS));
    const port = firstString(hd, PORT_FIELDS) || (protocol === 'ssh' ? '22' : '');
    const tags = normalizeTags(firstValue(hd, ['tags', 'tag_names', 'tagNames', 'tag']));

    let resolvedPassword = password;
    let pwSource = '';
    if (!resolvedPassword) {
      const r = resolveHostPassword(data, hd, username);
      resolvedPassword = r.password;
      pwSource = r.source;
    }

    hostMap.set(label, { groups: resolveGroupPath(hd, data.groupsById), label, tags, host, protocol, port, username, password: resolvedPassword, passwordSource: pwSource, _raw: hd });
  });
  return hostMap;
}

function buildFromConnections(data) {
  const hostMap = new Map();
  const seen = new Set();
  data.connections.forEach(conn => {
    const host = firstString(conn, HOST_FIELDS);
    if (!host || seen.has(host)) return;
    seen.add(host);
    const r = resolvePassword(conn, data);
    hostMap.set(host, {
      groups: resolveGroupPath(conn, data.groupsById) || '',
      label: firstString(conn, LABEL_FIELDS) || host,
      tags: normalizeTags(firstValue(conn, ['tags', 'tag_names', 'tagNames', 'tag'])),
      host, protocol: normalizeProtocol(firstString(conn, PROTOCOL_FIELDS)),
      port: firstString(conn, PORT_FIELDS) || '22',
      username: firstString(conn, USERNAME_FIELDS) || '',
      password: r.password,
      passwordSource: r.source,
      _raw: conn
    });
  });
  return hostMap;
}

function resolveHostPassword(data, hd, preferredUsername) {
  const direct = firstPasswordString(hd);
  if (direct) return { password: direct, source: 'direct' };

  const nested = extractNestedCredentialPassword(hd);
  if (nested) return { password: nested, source: 'nested' };

  const sshConfigs = sshConfigsForHostDefinition(data, hd);
  const identityIds = [];

  sshConfigs.forEach(sc => {
    const refs = Array.isArray(sc.__termius_identity_object_refs)
      ? sc.__termius_identity_object_refs : [];
    refs.forEach(ref => {
      (ref.ids || []).forEach(id => identityIds.push(String(id)));
      (ref.localIds || []).forEach(id => identityIds.push(String(id)));
    });

    const objIds = Array.isArray(sc.__termius_identity_object_ids)
      ? sc.__termius_identity_object_ids : [];
    objIds.forEach(id => identityIds.push(String(id)));

    DIRECT_REFERENCE_ID_FIELDS.forEach(f => collectIds(sc[`_${f}`] || sc[f], DIRECT_REFERENCE_ID_FIELDS, identityIds));
  });

  for (const id of identityIds) {
    const identity = identityForExactId(data, id, preferredUsername);
    if (identity) {
      const pw = extractPasswordFromObject(identity, { nested: true });
      if (pw) return { password: pw, source: 'sshConfigIdentity' };
    }
  }

  return { password: '', source: 'missing' };
}

function extractNestedCredentialPassword(obj) {
  for (const field of NESTED_CREDENTIAL_FIELDS) {
    const value = obj[field];
    if (!value || typeof value !== 'object') continue;
    const candidates = Array.isArray(value) ? value : [value];
    for (const c of candidates) {
      const pw = extractPasswordFromObject(c, { nested: true });
      if (pw) return pw;
    }
  }
  return '';
}

function sshConfigsForHostDefinition(data, hd) {
  const refs = Array.isArray(hd.__termius_ssh_config_object_refs)
    ? hd.__termius_ssh_config_object_refs : [];

  const objectIds = Array.isArray(hd.__termius_ssh_config_object_ids)
    ? hd.__termius_ssh_config_object_ids : [];

  const ids = new Set([
    ...refs.flatMap(ref => ref.ids),
    ...refs.flatMap(ref => ref.localIds),
    ...objectIds
  ].map(String));

  if (!ids.size) {
    if (Array.isArray(hd.__termius_nearby_ids)) {
      const nearbyIds = new Set(hd.__termius_nearby_ids.map(String));
      return data.sshConfigs.filter(sc => {
        if (Array.isArray(sc.__termius_nearby_ids)) {
          return sc.__termius_nearby_ids.some(id => nearbyIds.has(String(id)));
        }
        return false;
      });
    }
    return data.sshConfigs;
  }

  return data.sshConfigs.filter(sc => collectRecordIds(sc).some(id => ids.has(id)));
}

function identityForExactId(data, id, username) {
  const identity = data.identitiesById.get(valueToString(id).trim());
  if (!identity) return null;
  if (username && firstString(identity, USERNAME_FIELDS) && firstString(identity, USERNAME_FIELDS) !== username) return null;
  return identity;
}

function resolvePassword(conn, data) {
  const { password, source } = resolvePasswordCore(conn, data);
  return { password, source };
}

function resolvePasswordCore(conn, data) {
  const direct = firstPasswordString(conn);
  if (direct) return { password: direct, source: 'direct' };

  const nested = extractNestedCredentialPassword(conn);
  if (nested) return { password: nested, source: 'nested' };

  const refIds = collectReferenceIds(conn);
  const username = firstString(conn, USERNAME_FIELDS);
  for (const id of refIds) {
    const identity = identityForExactId(data, id, username);
    if (identity) {
      const pw = extractPasswordFromObject(identity, { nested: true });
      if (pw) return { password: pw, source: 'referenced' };
    }
  }

  for (const label of collectReferenceLabels(conn)) {
    if (data.identitiesByLabel.has(label)) {
      const pw = uniquePassword(data.identitiesByLabel.get(label));
      if (pw) return { password: pw, source: 'label' };
    }
  }

  if (username && data.identitiesByUser.has(username)) {
    const pw = uniquePassword(data.identitiesByUser.get(username));
    if (pw) return { password: pw, source: 'usernameFallback' };
  }

  return { password: '', source: 'missing' };
}

function collectReferenceIds(conn) {
  return [...new Set(collectReferenceEntries(conn).map(e => e.id))];
}

function collectReferenceEntries(conn) {
  const ids = new Set();
  const entries = [];
  const add = (source, fields) => {
    const before = new Set(ids);
    fields.forEach(f => collectIds(conn[f], DIRECT_REFERENCE_ID_FIELDS, ids));
    [...ids].filter(id => !before.has(id)).forEach(id => entries.push({ id, source }));
  };
  add('direct', DIRECT_REFERENCE_ID_FIELDS);
  NESTED_CREDENTIAL_FIELDS.forEach(f => {
    const val = conn[f];
    if (val && typeof val === 'object') {
      const before = new Set(ids);
      collectIds(val, DIRECT_REFERENCE_ID_FIELDS, ids);
      [...ids].filter(id => !before.has(id)).forEach(id => entries.push({ id, source: `nested:${f}` }));
    }
  });
  return entries;
}

function collectReferenceLabels(conn) {
  const labels = new Set();
  CREDENTIAL_LABEL_FIELDS.forEach(f => {
    const val = conn[f];
    if (val === undefined || val === null) return;
    if (Array.isArray(val)) val.forEach(v => {
      const lbl = typeof v === 'object' ? firstString(v, LABEL_FIELDS) : valueToString(v).trim();
      if (lbl) labels.add(lbl);
    });
    else {
      const lbl = typeof val === 'object' ? firstString(val, LABEL_FIELDS) : valueToString(val).trim();
      if (lbl) labels.add(lbl);
    }
  });
  return [...labels];
}

function uniquePassword(identities) {
  const passwords = [...new Set(identities.map(id => extractPasswordFromObject(id, { nested: true })).filter(Boolean))];
  return passwords.length === 1 ? passwords[0] : '';
}

function resolveGroupPath(obj, groupsById) {
  const direct = firstString(obj, ['group_path', 'groupPath', 'groups', 'group', 'folder_path', 'folderPath', 'folder', 'folder_name', 'folderName', 'group_name', 'groupName']);
  if (direct) return direct;
  const groupId = firstString(obj, ['group_id', 'groupId', 'folder_id', 'folderId', 'parent_id', 'parentId']);
  return groupId ? buildGroupPath(groupId, groupsById) : '';
}

function buildGroupPath(groupId, groupsById) {
  const labels = [];
  const visited = new Set();
  let currentId = groupId;
  while (currentId && groupsById.has(currentId) && !visited.has(currentId)) {
    visited.add(currentId);
    const group = groupsById.get(currentId);
    const label = firstString(group, LABEL_FIELDS);
    if (label) labels.unshift(label);
    currentId = firstString(group, ['parent_id', 'parentId', 'folder_id', 'folderId']);
  }
  return labels.join('/');
}

module.exports = { parseDecryptedData, buildHostConfig };
