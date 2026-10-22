# UNLOCKTOOL ALBASHAA — reverse-engineering reproduction

A verified reproduction of the parts of *UNLOCKTOOL ALBASHAA* (`ColokTool.exe`)
that can be established from the artefacts alone, plus an honest account of
what cannot.

The supplied archive contained an Inno Setup 6.7.0 installer, not the tool.
Everything here starts by taking that installer apart.

## What this is

| Layer | Reproduced | Evidence tier |
|---|---|---|
| Inno Setup 6.7.0 container (blocks, CRCs, LZMA, call-instruction transform) | `src/unlocktool_re/inno.py`, `setup0.py`, `installer.py` | verified |
| `programs.bin` AES-256-CBC payload encryption | `src/unlocktool_re/crypto.py` | verified |
| Offline data tree (brand XML, model folders, operation scripts) | `src/unlocktool_re/datatree.py`, `firehose.py` | verified |
| Operation dispatch (55 operation names → workflow families) | `src/unlocktool_re/dispatch.py` | verified |
| Plan building and ordered execution | `src/unlocktool_re/plan.py` | verified |
| Local account / licence check | `src/unlocktool_re/auth.py` | verified |
| MediaTek xflash command framing | `src/unlocktool_re/mtk.py` | verified (client side) |
| Device side of both protocol families | `src/unlocktool_re/mockdevice.py` | **simulated** |

172 tests, 0 failures. `docs/validation-report.md` separates what is verified,
what is simulated and what is merely inferred.

## Quick start

```sh
# 1. take the installer apart (needs the .7z contents; 2.3 GB)
python3 scripts/split_installer.py "/path/to/UNLOCKTOOL OFFLINE.exe" parts/
python3 scripts/extract_tree.py parts/part* --out artifacts/tree --max-size 0

# 2. build the compatibility matrix
PYTHONPATH=src python3 scripts/build_matrix.py

# 3. run the tests
python3 -m unittest discover -s tests -v
```

The installer pieces are located via `UNLOCKTOOL_CHUNKS` (a directory
containing `ut.part*`) or `UNLOCKTOOL_INSTALLER` (a single file). Without
either, the integration tests skip and the unit tests still run.

## Headline measurements

All from the shipped artefacts; see `docs/compatibility-matrix.md`.

| | |
|---|---|
| Payload files in the installer | 7 387 |
| Payload bytes | 4 322 930 069 (4.03 GiB) |
| Brand indexes | 16 |
| Indexed devices | 1 559 |
| Devices with a payload folder | 746 |
| `programs.bin` loaders present | 528 |
| Loaders that decrypt to ELF | 495 |
| Advertised operation slots | 2 230 |
| Operation scripts present | 989 |
| Scripts that parse | 968 |
| Advertised operations that build a complete plan | **841** |
| Steps across those plans | 46 447 |
| Loaders that are an ARM pre-loader container, not ELF | 6 |
| Loaders that are a correctly-encrypted empty file | 2 |
| Foreign payload layouts merged into `data/` that the binary never reads | 4 |
| `_auth_sv5.auth` files that are MMM containers vs MotoKingPro blobs | 2 vs 40 |
| Loaders with one corrupted byte | 2 |
| Distinct undetermined loader files | 4 (copied into 23 folders) |

## The one thing worth knowing first

`data/OFFLINE-DATA-README.md` documents the payload key derivation as

```
key = SHA256(ASCII(password))
     -> Rfc2898DeriveBytes(key, salt, 1000).GetBytes(32) = AES key
```

Read literally that makes the SHA-256 digest the PBKDF2 *password*, which is
correct — but the README's own code block reads as if `key` were the ASCII
string. Using the string directly produces a key that decrypts **nothing**.
The IL (`Loader_Thread::Encryption`) SHA-256s the password first and passes the
digest to `Rfc2898DeriveBytes`. With the digest, 543 of 606 payloads decrypt to
ELF; with the raw string, 0 do. See `docs/protocol-report.md` §3.3.

## Layout

```
src/unlocktool_re/
  inno.py         Inno Setup blocks, CRCs, LZMA, TransformCallInstructions
  setup0.py       TSetupHeader / TSetupFileEntry / TSetupFileLocationEntry
  installer.py    open an installer, enumerate and extract payload files
  crypto.py       programs.bin AES-256-CBC (pure Python + OpenSSL fast path)
  datatree.py     brand XML indexes, model folders, audit
  firehose.py     Qualcomm rawprogram scripts (program/erase/patch)
  container.py    the second loader container (ARM pre-loader, not ELF)
  motoking.py     the MotoKingProS/R container (fifth vendor's auth blobs)
  dispatch.py     operation name -> workflow family -> action
  plan.py         operation script -> ordered steps -> execution
  mtk.py          MediaTek xflash framing
  mockdevice.py   mock target + client state machine
  auth.py         local account/licence check

docs/
  architecture.md          components, execution flow, dependencies
  oem-capability-matrix.md per-brand summary and loader classification
  compatibility-matrix.md  generated per-device tables
  protocol-report.md       both protocol families, encryption, auth
  data-layouts.md          the four payload layouts merged into data/
  research-registry.md     30 hypotheses with status
  validation-report.md     verified vs simulated vs inferred
  remaining-work.md        blockers and next experiments

tools/
  ildump.py           CLI for the IL reader (--summary/--il/--method/--rva)
  il/                 dependency-free ECMA-335 metadata + IL reader

scripts/
  split_installer.py  split a >1 GB file into pieces
  extract_tree.py     extract the data tree from the installer
  build_matrix.py     regenerate docs/compatibility-matrix.md

tests/                172 tests
artifacts/tree/       extracted data tree (485 MB, git-ignored)
```

## Scope

This is static analysis of software the operator supplied, plus a
reproduction that runs entirely against local files and mocks. It contains no
code that talks to a device, a licence server or any remote endpoint. The four
URLs found in the binary are documented as strings in
`docs/protocol-report.md`; none were contacted.

The tool's own account check is a local file, which is a property of this
offline build. That fact is documented, not exploited: the reproduction models
the check so its behaviour can be tested, and nothing here forges credentials
or bypasses a remote authorization service.
