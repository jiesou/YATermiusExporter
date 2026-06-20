'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const snappy = require('snappyjs');

function readVarint(buf, offset) {
  let result = 0n;
  let shift = 0n;
  for (let i = offset; i < Math.min(buf.length, offset + 10); i++) {
    const byte = BigInt(buf[i]);
    result |= (byte & 0x7fn) << shift;
    if ((byte & 0x80n) === 0n) return { value: Number(result), next: i + 1 };
    shift += 7n;
  }
  return null;
}

function readLengthPrefixedSlice(buf, offset) {
  const length = readVarint(buf, offset);
  if (!length) return null;
  const end = length.next + length.value;
  if (end > buf.length) return null;
  return { value: buf.subarray(length.next, end), next: end };
}

function readBlockHandle(buf, offset) {
  const blockOffset = readVarint(buf, offset);
  if (!blockOffset) return null;
  const blockSize = readVarint(buf, blockOffset.next);
  if (!blockSize) return null;
  return { offset: blockOffset.value, size: blockSize.value, next: blockSize.next };
}

function readBlock(fileBuffer, handle) {
  const blockEnd = handle.offset + handle.size;
  if (blockEnd + 5 > fileBuffer.length) return null;
  const raw = fileBuffer.subarray(handle.offset, blockEnd);
  const compressionType = fileBuffer[blockEnd];
  if (compressionType === 0) return raw;
  if (compressionType === 1) return Buffer.from(snappy.uncompress(raw));
  return null;
}

function parseBlockEntries(block) {
  if (!block || block.length < 4) return [];
  const restartCount = block.readUInt32LE(block.length - 4);
  const entriesEnd = block.length - 4 - restartCount * 4;
  if (entriesEnd < 0 || entriesEnd > block.length) return [];

  const entries = [];
  let pos = 0;
  let key = Buffer.alloc(0);

  while (pos < entriesEnd) {
    const shared = readVarint(block, pos);
    if (!shared) break;
    pos = shared.next;
    const nonShared = readVarint(block, pos);
    if (!nonShared) break;
    pos = nonShared.next;
    const valueLength = readVarint(block, pos);
    if (!valueLength) break;
    pos = valueLength.next;

    if (shared.value > key.length || pos + nonShared.value + valueLength.value > entriesEnd) break;

    key = Buffer.concat([key.subarray(0, shared.value), block.subarray(pos, pos + nonShared.value)]);
    pos += nonShared.value;
    const value = block.subarray(pos, pos + valueLength.value);
    pos += valueLength.value;
    entries.push({ key, value });
  }

  return entries;
}

function internalKeyInfo(internalKey) {
  if (!internalKey || internalKey.length < 8) return null;
  const trailer = internalKey.readBigUInt64LE(internalKey.length - 8);
  return {
    userKey: internalKey.subarray(0, internalKey.length - 8),
    sequence: Number(trailer >> 8n),
    valueType: Number(trailer & 0xffn)
  };
}

function recordLatestValue(records, userKey, sequence, valueType, value, file) {
  if (!userKey || !Number.isSafeInteger(sequence)) return;
  const key = userKey.toString('hex');
  const existing = records.get(key);
  if (existing && existing.sequence > sequence) return;
  records.set(key, { sequence, valueType, value: valueType === 1 ? value : null, file });
}

function readTableEntries(filePath, records) {
  const fileBuffer = fs.readFileSync(filePath);
  if (fileBuffer.length < 48) return;

  const footer = fileBuffer.subarray(fileBuffer.length - 48);
  const magic = footer.subarray(40, 48).toString('hex');
  if (magic !== '57fb808b247547db') return;

  const metaIndex = readBlockHandle(footer, 0);
  if (!metaIndex) return;
  const index = readBlockHandle(footer, metaIndex.next);
  if (!index) return;

  const indexBlock = readBlock(fileBuffer, index);
  const indexEntries = parseBlockEntries(indexBlock);

  indexEntries.forEach(indexEntry => {
    const dataHandle = readBlockHandle(indexEntry.value, 0);
    if (!dataHandle) return;
    const dataBlock = readBlock(fileBuffer, dataHandle);
    parseBlockEntries(dataBlock).forEach(entry => {
      const info = internalKeyInfo(entry.key);
      if (!info) return;
      recordLatestValue(records, info.userKey, info.sequence, info.valueType, entry.value, path.basename(filePath));
    });
  });
}

function logPhysicalRecords(buffer) {
  const records = [];
  const blockSize = 32768;
  let blockStart = 0;
  let fragment = [];

  while (blockStart < buffer.length) {
    const blockEnd = Math.min(buffer.length, blockStart + blockSize);
    let pos = blockStart;
    while (pos + 7 <= blockEnd) {
      const length = buffer.readUInt16LE(pos + 4);
      const type = buffer[pos + 6];
      pos += 7;
      if (length === 0 && type === 0) break;
      if (pos + length > blockEnd) break;
      const payload = buffer.subarray(pos, pos + length);
      pos += length;
      if (type === 1) { records.push(payload); fragment = []; }
      else if (type === 2) { fragment = [payload]; }
      else if (type === 3 && fragment.length) { fragment.push(payload); }
      else if (type === 4 && fragment.length) { fragment.push(payload); records.push(Buffer.concat(fragment)); fragment = []; }
    }
    blockStart += blockSize;
  }
  return records;
}

function readLogEntries(filePath, records) {
  const buffer = fs.readFileSync(filePath);
  logPhysicalRecords(buffer).forEach(batch => {
    if (batch.length < 12) return;
    const startSequence = batch.readBigUInt64LE(0);
    const count = batch.readUInt32LE(8);
    let pos = 12;
    for (let index = 0; index < count && pos < batch.length; index++) {
      const valueType = batch[pos++];
      const key = readLengthPrefixedSlice(batch, pos);
      if (!key) break;
      pos = key.next;
      let value = null;
      if (valueType === 1) {
        const parsedValue = readLengthPrefixedSlice(batch, pos);
        if (!parsedValue) break;
        value = parsedValue.value;
        pos = parsedValue.next;
      } else if (valueType !== 0) break;
      const sequence = Number(startSequence + BigInt(index));
      recordLatestValue(records, key.value, sequence, valueType, value, path.basename(filePath));
    }
  });
}

function applyVersionEdit(edit, liveFiles) {
  let pos = 0;
  while (pos < edit.length) {
    const tag = readVarint(edit, pos);
    if (!tag) return;
    pos = tag.next;
    if (tag.value === 1) { const c = readLengthPrefixedSlice(edit, pos); if (!c) return; pos = c.next; continue; }
    if ([2, 3, 4, 9].includes(tag.value)) { const v = readVarint(edit, pos); if (!v) return; pos = v.next; continue; }
    if (tag.value === 5) {
      const level = readVarint(edit, pos); if (!level) return;
      const key = readLengthPrefixedSlice(edit, level.next); if (!key) return; pos = key.next;
      continue;
    }
    if (tag.value === 6) {
      const level = readVarint(edit, pos); if (!level) return;
      const file = readVarint(edit, level.next); if (!file) return;
      liveFiles.delete(`${level.value}:${file.value}`); pos = file.next;
      continue;
    }
    if (tag.value === 7) {
      const level = readVarint(edit, pos); if (!level) return;
      const file = readVarint(edit, level.next); if (!file) return;
      const size = readVarint(edit, file.next); if (!size) return;
      const smallest = readLengthPrefixedSlice(edit, size.next); if (!smallest) return;
      const largest = readLengthPrefixedSlice(edit, smallest.next); if (!largest) return;
      liveFiles.set(`${level.value}:${file.value}`, { level: level.value, file: file.value, size: size.value });
      pos = largest.next;
      continue;
    }
    return;
  }
}

function readManifestLiveFiles(snapshotDir) {
  const currentPath = path.join(snapshotDir, 'CURRENT');
  if (!fs.existsSync(currentPath)) return null;
  const manifestName = fs.readFileSync(currentPath, 'utf8').trim();
  if (!manifestName) return null;
  const manifestPath = path.join(snapshotDir, manifestName);
  if (!fs.existsSync(manifestPath)) return null;
  const liveFiles = new Map();
  logPhysicalRecords(fs.readFileSync(manifestPath)).forEach(edit => applyVersionEdit(edit, liveFiles));
  return new Set([...liveFiles.values()].map(entry => entry.file));
}

function extractCurrentValues(sourceDir) {
  const snapshotDir = copySnapshot(sourceDir);
  const records = new Map();

  try {
    const files = fs.readdirSync(snapshotDir);
    const liveTableFiles = readManifestLiveFiles(snapshotDir);

    files.filter(f => f.endsWith('.ldb')).filter(f => {
      if (!liveTableFiles || !liveTableFiles.size) return true;
      return liveTableFiles.has(Number(path.basename(f, '.ldb')));
    }).sort().forEach(f => readTableEntries(path.join(snapshotDir, f), records));

    files.filter(f => f.endsWith('.log')).sort().forEach(f => readLogEntries(path.join(snapshotDir, f), records));

    return [...records.values()]
      .filter(r => r.valueType === 1 && r.value && r.value.length)
      .map(r => ({ value: r.value, file: r.file, sequence: r.sequence }));
  } finally {
    fs.rmSync(snapshotDir, { recursive: true, force: true });
  }
}

function copySnapshot(sourceDir) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'termius-leveldb-'));
  fs.cpSync(sourceDir, tmpDir, { recursive: true });
  return tmpDir;
}

module.exports = {
  readVarint, readLengthPrefixedSlice, readBlockHandle, readBlock,
  parseBlockEntries, internalKeyInfo, recordLatestValue,
  readTableEntries, logPhysicalRecords, readLogEntries,
  extractCurrentValues
};
