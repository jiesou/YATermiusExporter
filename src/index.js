'use strict';

const fs = require('fs');
const path = require('path');
const { getEncryptionKey } = require('./keystore');
const { extractCurrentValues } = require('./leveldb');
const { decryptEncryptedBlocks } = require('./decrypt');
const { parseDecryptedData, buildHostConfig } = require('./parser');
const { runAllExporters, printSummary } = require('./exporters');

async function run(flags, outDir) {
  const dbPath = resolveDbPath(flags);
  console.error('[1/3] Reading LevelDB from:', dbPath);

  const key = await getEncryptionKey(flags);
  console.error('[2/3] Key OK (' + key.length + ' bytes)');

  const records = extractCurrentValues(dbPath);
  const { output, encryptedCount, decryptedCount } = await decryptEncryptedBlocks(records, key);
  console.error('     encrypted blocks:', encryptedCount, '/ decrypted:', decryptedCount);

  const data = parseDecryptedData(output);
  console.error('     hosts:', data.hostDefinitions.length, '/ connections:', data.connections.length,
    '/ identities:', data.identities.length, '/ keys:', data.keysByLabel.size,
    '/ snippets:', data.snippets.size, '/ forwards:', data.portForwards.length);

  const hostMap = buildHostConfig(data);

  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  outDir = path.resolve(outDir);

  const result = runAllExporters(data, hostMap, outDir, output);
  printSummary(result);
  console.error('\nDone:', outDir);
}

function resolveDbPath(flags) {
  if (flags.dbPath) {
    const p = path.resolve(flags.dbPath);
    if (!fs.existsSync(p)) throw new Error('DB path not found: ' + p);
    return p;
  }

  if (flags.autoFlatpak) {
    const p = path.join(
      require('os').homedir(),
      '.var/app/com.termius.Termius/config/Termius/IndexedDB/file__0.indexeddb.leveldb'
    );
    if (!fs.existsSync(p)) throw new Error('Flatpak DB not found at: ' + p);
    return p;
  }

  throw new Error(
    'Termius database path is required.\n' +
    'Provide it via:  --db-path <dir>\n' +
    'See README for instructions on locating your Termius IndexedDB database.'
  );
}

module.exports = { run };
