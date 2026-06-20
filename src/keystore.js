'use strict';

const fs = require('fs');
const path = require('path');

function readKeyFile(filePath) {
  const raw = fs.readFileSync(path.resolve(filePath), 'utf8').trim();
  return raw;
}

function findKeyInLocalStorage(leveldbDir) {
  if (!fs.existsSync(leveldbDir)) return null;
  const files = fs.readdirSync(leveldbDir);
  for (const file of files) {
    const fpath = path.join(leveldbDir, file);
    let buf;
    try { buf = fs.readFileSync(fpath); } catch { continue; }

    const idx = buf.indexOf(Buffer.from('localKey'));
    if (idx < 0) continue;

    const region = buf.subarray(idx, Math.min(buf.length, idx + 200)).toString('binary');
    const m = region.match(/"((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)"/);
    if (m) return m[1];
  }
  return null;
}

function localStoragePathFromDbPath(dbPath) {
  const resolved = path.resolve(dbPath);
  return path.resolve(resolved, '../../Local Storage/leveldb');
}

async function getEncryptionKey(flags) {
  if (flags.key) {
    return Buffer.from(flags.key, 'base64');
  }

  if (flags.keyFile) {
    return Buffer.from(readKeyFile(flags.keyFile), 'base64');
  }

  if (flags.keyInDb || flags.autoFlatpak) {
    const lsDir = flags.dbPath
      ? localStoragePathFromDbPath(flags.dbPath)
      : path.join(require('os').homedir(),
          '.var/app/com.termius.Termius/config/Termius/Local Storage/leveldb');

    if (!fs.existsSync(lsDir)) {
      throw new Error('Local Storage not found at: ' + lsDir + '\n' +
        '--key-is-in-db requires the Local Storage LevelDB alongside the IndexedDB.');
    }

    const key = findKeyInLocalStorage(lsDir);
    if (!key) {
      throw new Error('Failed to extract key from Local Storage.\n' +
        'Try running Termius once to initialize the key.');
    }
    return Buffer.from(key, 'base64');
  }

  throw new Error(
    'Encryption key is required.\n' +
    'Provide it via:  --key <base64>  |  --key-file <path>  |  --key-is-in-db\n' +
    'See README for instructions.'
  );
}

module.exports = { getEncryptionKey };
