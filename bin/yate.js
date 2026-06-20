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
  switch (args[i]) {
    case '--db-path': flags.dbPath = args[++i]; break;
    case '--key':     flags.key = args[++i]; break;
    case '--key-file': flags.keyFile = args[++i]; break;
    case '--key-is-in-db': flags.keyInDb = true; break;
    case '--auto-flatpak': flags.autoFlatpak = true; break;
    default:
      if (!args[i].startsWith('-')) positional.push(args[i]);
  }
}

const outDir = positional.length > 0
  ? path.resolve(positional[positional.length - 1])
  : path.resolve('output');

require('../src/index').run(flags, outDir).catch(err => {
  console.error('\nError:', err.message);
  process.exit(1);
});
