'use strict';

const sodium = require('libsodium-wrappers');
const { ENCRYPTED_BLOCK_RE, extractPasswordFromObject, extractPassphrase, extractPrivateKey, normalizePrivateKey, passwordValueToString, PRIVATE_KEY_RE, PRIVATE_KEY_FIELDS, firstString, LABEL_FIELDS, SSH_CONFIG_FIELDS, PORT_FIELDS, firstPasswordString } = require('./utils');

const CONTEXT_RADIUS = 900;
const NEARBY_ID_RADIUS = 360;

async function decryptEncryptedBlocks(results, key) {
  await sodium.ready;
  let encryptedCount = 0;
  let decryptedCount = 0;
  const decryptCache = new Map();
  const output = [];

  results.forEach(record => {
    const buffer = record.value;
    const text = buffer.toString('latin1');
    let match;

    ENCRYPTED_BLOCK_RE.lastIndex = 0;
    while ((match = ENCRYPTED_BLOCK_RE.exec(text))) {
      encryptedCount++;
      const base64Data = match[0];
      const blockIndex = match.index;

      let decrypted;
      if (decryptCache.has(base64Data)) {
        decrypted = decryptCache.get(base64Data);
      } else {
        decrypted = decryptBlock(base64Data, key);
        decryptCache.set(base64Data, decrypted);
      }

      const meta = buildMeta(buffer, blockIndex, blockIndex + base64Data.length);
      const hasPlaintext = decrypted && decrypted.trim().length > 0;
      if (hasPlaintext) decryptedCount++;

      output.push({
        text: decrypted || '',
        encrypted: true,
        file: record.file || '',
        index: blockIndex,
        sequence: record.sequence,
        meta,
        encryptedText: base64Data
      });
    }
  });

  return { output, encryptedCount, uniqueBlocks: decryptCache.size, decryptedCount };
}

function decryptBlock(base64Data, key) {
  try {
    const data = Buffer.from(base64Data, 'base64');
    if (data[0] !== 4) return null;
    const versionOptions = data[1];
    const nonce = data.slice(2, 26);
    const ciphertext = data.slice(26);
    const decrypted = sodium.crypto_secretbox_open_easy(
      new Uint8Array(ciphertext),
      new Uint8Array(nonce),
      new Uint8Array(key)
    );
    return Buffer.from(decrypted).toString('utf8');
  } catch {
    return null;
  }
}

function buildMeta(buffer, encryptedStart, encryptedEnd) {
  const contextStart = Math.max(0, encryptedStart - CONTEXT_RADIUS);
  const contextEnd = Math.min(buffer.length, encryptedEnd + CONTEXT_RADIUS);
  const context = buffer.subarray(contextStart, contextEnd);
  const relStart = encryptedStart - contextStart;
  const relEnd = encryptedEnd - contextStart;

  return {
    encryptedField: nearestFieldName(context, relStart),
    id: nearestFieldInteger(context, relStart, relEnd, 'id'),
    local_id: nearestFieldInteger(context, relStart, relEnd, 'local_id'),
    host_id: nearestFieldInteger(context, relStart, relEnd, 'host_id'),
    visible_identity_id: nearestFieldInteger(context, relStart, relEnd, 'visible_identity_id'),
    nearby_ids: readNearbyVarints(context, relStart, relEnd).map(e => e.value),
    nearby_id_entries: readNearbyVarints(context, relStart, relEnd).map(e => ({ value: e.value, distance: e.distance, side: e.side }))
  };
}

function nearestFieldName(buffer, encryptedStart) {
  let last = '';
  const start = Math.max(0, encryptedStart - 80);
  for (let i = start; i < encryptedStart - 2; i++) {
    if (buffer[i] !== 0x22) continue;
    const length = buffer[i + 1];
    if (length < 1 || length > 40 || i + 2 + length > buffer.length) continue;
    const name = buffer.subarray(i + 2, i + 2 + length).toString('utf8');
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) last = name;
  }
  return last;
}

function extractFieldIntegers(buffer, fieldName) {
  const name = Buffer.from(fieldName);
  const values = [];
  for (let i = 0; i < buffer.length - name.length - 4; i++) {
    if (buffer[i] !== 0x22 || buffer[i + 1] !== name.length) continue;
    if (!buffer.subarray(i + 2, i + 2 + name.length).equals(name)) continue;
    const pos = i + 2 + name.length;
    if (buffer[pos] !== 0x49) continue;
    const parsed = readVarintSmall(buffer, pos + 1);
    if (parsed) values.push({ pos: i, value: String(decodeZigZag(parsed.value)) });
  }
  return values;
}

function nearestFieldInteger(buffer, encryptedStart, encryptedEnd, fieldName, maxDist = NEARBY_ID_RADIUS) {
  const entries = extractFieldIntegers(buffer, fieldName)
    .filter(e => {
      const d = distance(e.pos, encryptedStart, encryptedEnd);
      return d.side !== 'inside' && d.dist <= maxDist;
    })
    .map(e => ({ ...e, ...distance(e.pos, encryptedStart, encryptedEnd) }))
    .sort((a, b) => a.dist - b.dist || (a.side === 'before' ? -1 : 1));
  return entries[0]?.value || '';
}

function readNearbyVarints(buffer, encryptedStart, encryptedEnd, maxDist = NEARBY_ID_RADIUS) {
  const values = [];
  const start = Math.max(0, encryptedStart - maxDist);
  const end = Math.min(buffer.length, encryptedEnd + maxDist);
  for (let i = start; i < end; i++) {
    if (i >= encryptedStart && i < encryptedEnd) { i = encryptedEnd - 1; continue; }
    const parsed = readVarintSmall(buffer, i);
    if (!parsed || parsed.end <= i) continue;
    if (i < encryptedStart && parsed.end > encryptedStart) continue;
    if (i >= encryptedEnd && parsed.end > end) continue;
    const value = decodeZigZag(parsed.value);
    if (Number.isSafeInteger(value) && value > 1000 && value < 1_000_000_000_000) {
      const d = distance(i, encryptedStart, encryptedEnd);
      values.push({ pos: i, value: String(value), dist: d.dist, side: d.side });
    }
  }
  return dedupeByValue(values).slice(0, 80);
}

function readVarintSmall(buf, pos) {
  let result = 0;
  let shift = 0;
  for (let i = pos; i < Math.min(buf.length, pos + 10); i++) {
    const byte = buf[i];
    result += (byte & 0x7f) * Math.pow(2, shift);
    if ((byte & 0x80) === 0) return { value: result, end: i + 1 };
    shift += 7;
  }
  return null;
}

function decodeZigZag(value) {
  return value % 2 === 0 ? value / 2 : -((value + 1) / 2);
}

function distance(pos, start, end) {
  if (pos < start) return { dist: start - pos, side: 'before' };
  if (pos >= end) return { dist: pos - end, side: 'after' };
  return { dist: 0, side: 'inside' };
}

function dedupeByValue(entries) {
  const best = new Map();
  entries.forEach(e => {
    const cur = best.get(e.value);
    if (!cur || e.dist < cur.dist) best.set(e.value, e);
  });
  return [...best.values()].sort((a, b) => a.dist - b.dist || a.value.localeCompare(b.value));
}

module.exports = { decryptEncryptedBlocks };
