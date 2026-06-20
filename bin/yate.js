#!/usr/bin/env node
'use strict';

const path = require('path');

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  console.log(`
YATermiusExporter — Yet Another Termius Exporter

https://github.com/jiesou/YATermiusExporter

Usage:
  yate --db-path <dir>  --key <base64>  [output-dir]
  yate --db-path <dir>  --key-file <path>  [output-dir]
OR:
  yate --auto-flatpak  [output-dir]
  Auto-extract from Flatpak default installation

DB source:
  --db-path <dir>       file__0.indexeddb.leveldb folder
Key sources (pick one):
  --key <base64>        Encryption key as a base64 string
  --key-file <path>     File containing the base64 key
  --key-is-in-db        Key is already stored inside the db directory
`);
  process.exit(0);
}

if (args.includes('--version') || args.includes('-v')) {
  console.log(require('../package.json').version);
  process.exit(0);
}

const flags = { dbPath: null, key: null, keyFile: null, keyInDb: false, autoFlatpak: false };
let positional = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  let value;

  if (arg.startsWith('--') && arg.includes('=')) {
    const eq = arg.indexOf('=');
    const name = arg.slice(0, eq);
    value = arg.slice(eq + 1);
    if (name === '--db-path') { flags.dbPath = value; continue; }
    if (name === '--key') { flags.key = value; continue; }
    if (name === '--key-file') { flags.keyFile = value; continue; }
  }

  switch (arg) {
    case '--db-path':
      if (i + 1 >= args.length) throw new Error('--db-path requires a value');
      flags.dbPath = args[++i]; break;
    case '--key':
      if (i + 1 >= args.length) throw new Error('--key requires a value');
      flags.key = args[++i]; break;
    case '--key-file':
      if (i + 1 >= args.length) throw new Error('--key-file requires a value');
      flags.keyFile = args[++i]; break;
    case '--key-is-in-db': flags.keyInDb = true; break;
    case '--auto-flatpak': flags.autoFlatpak = true; break;
    default:
      if (!arg.startsWith('-')) positional.push(arg);
  }
}

const outDir = positional.length > 0
  ? path.resolve(positional[positional.length - 1])
  : path.resolve('output');

require('../src/index').run(flags, outDir).catch(err => {
  console.error('\nError:', err.message);
  process.exit(1);
});
