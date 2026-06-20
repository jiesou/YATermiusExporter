# Yet Another Termius Exporter

Export hosts, SSH keys, snippets, port forwards, SSH configs, and connection history from a Termius local database.

Ony tested on Linux (Flatpak).

Should also works on Linux (including .deb install), macOS, and Windows.

---

## Usage

Download from [Releases](https://github.com/jiesou/YATermiusExporter/releases) (pre-compiled by Bun).

Or run via Node:

```
$ git clone https://github.com/jiesou/YATermiusExporter
$ npm install
$ node bin/yate.js --help

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
```

**Linux Flatpak only**:
```
./yate --auto-flatpak
```
With Linux's default Flatpak installation, you should be able to use `--auto-flatpak` and skip all the following descriptions.

`--auto-flatpak` implies `--db-path .var/app/com.termius.Termius/config/Termius/IndexedDB/file__0.indexeddb.leveldb --key-is-in-db`

### 1. Get the IndexedDB LevelDB

Copy the whole `file__0.indexeddb.leveldb` folder somewhere (Termius must be closed first).

**Linux (Flatpak)**
```
~/.var/app/com.termius.Termius/config/Termius/IndexedDB/file__0.indexeddb.leveldb/
```

Other platforms might look like:

**Linux (.deb install)**
```
~/.config/Termius/IndexedDB/file__0.indexeddb.leveldb/
```

**macOS**
```
~/Library/Application Support/Termius/IndexedDB/file__0.indexeddb.leveldb/
```

**Windows**
```
%APPDATA%/Termius/IndexedDB/file__0.indexeddb.leveldb/
```

### 2. Get the encryption key

Termius encrypts its IndexedDB with **XSalsa20-Poly1305**. The key is preferred stored in the system keyring:

| Platform | Key storage |
|----------|-------------|
| Windows | Credential Manager |
| macOS | Keychain |
| Linux (native) | libsecret (GNOME Keyring) |
| Linux (Flatpak) | inside the db |

**Why `--key-is-in-db` exists:** When Termius cannot find a system keyring (e.g. In Flatpak w/o D-Bus Secret Service), it falls back to storing the encryption key inside db directory

Other platforms might look like:

**Linux (.deb install)**
```
secret-tool lookup service Termius account localKey
```
Or try to use [Seahorse](https://gitlab.gnome.org/GNOME/seahorse) GUI on GNOME.

**macOS**
```
security find-generic-password -a "localKey" -s "Termius" -w
```

**Windows (PowerShell)**
```
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
    (Get-StoredCredential -Target "Termius:localKey").Password
  )
)
```

Save the output to a file, then pass it with `--key-file`.

### 3. Run

```bash
./yate --db-path ./termius-leveldb --key-file ./key.txt ./output
```

---

## Output

```
./output/
├── hosts.csv             hosts with credentials (Termius-importable CSV)
├── ssh_keys/             SSH key pairs (.pem private + .pub public)
├── snippets.txt          saved command snippets
├── port_forwards.csv     port forwarding rules
├── ssh_config            OpenSSH config (~/.ssh/config format, with ForwardAgent, ProxyJump, IdentityFile)
├── connections.csv       full connection history
├── session-logs/         session log files (encrypted)
├── session_logs.json     session log metadata (host, username, secretKey mapping)
├── dump.json             all decrypted records as-is (raw dump)
└── summary.json          export metadata
```

---

## Credits

- **[ZacharyZcR/termius-exporter](https://github.com/ZacharyZcR/termius-exporter)** — original Termius encryption analysis and LevelDB format
- **[LXiuu/termius-data-exporter](https://github.com/LXiuu/termius-data-exporter)** — updated fork for Termius 9.x, LevelDB parser, and identity matching

---

## License

MIT
