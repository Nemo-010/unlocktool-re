# Research registry

One row per research route. Status vocabulary:

| Status | Meaning |
|---|---|
| `validated` | Reproduced and covered by a test that fails if the finding is wrong |
| `promising` | Strong evidence, not yet fully exercised by a test |
| `blocked` | Further work would repeat what was already done |
| `disproven` | An experiment falsified the hypothesis |
| `insufficient-evidence` | Not enough data either way; distinct from disproven |

"Evidence" means an artefact or an observation with a citation (file offset,
method RID, byte range), never "it looks like".

---

## R1 — Outer container is an Inno Setup 6.7.0 installer

- **Hypothesis**: the supplied `UNLOCKTOOL OFFLINE.exe` is not the tool; it is
  an Inno Setup installer whose payload contains the tool.
- **Artefacts**: `SetupID` string at file offset `0x8A9C1D1E`;
  `TSetupLdrOffsetTable` in RCDATA resource 11111; two LZMA1 blocks.
- **Experiments**: decoded the loader offset table by hand; parsed both header
  blocks; confirmed both are consumed to the exact byte (trailing = 0).
- **Confirmed**: yes. Version string `Inno Setup Setup Data (6.7.0)`,
  `offset0 = 0x8A9C1D1E`, `offset1 = 0x105200`, total size `2327092946`.
- **Status**: `validated` — `tests/test_real_installer.py::TestContainer`.

## R2 — The installer is not encrypted

- **Hypothesis**: setup-0 blocks are plaintext LZMA1, so no Inno password is
  needed to reach the payload.
- **Artefacts**: `TSetupEncryptionHeader.EncryptionUse == 0`;
  `KDFIterations == 220000` present but unused.
- **Status**: `validated` (`test_no_setup_encryption`).

## R3 — Extracted payload needs `TransformCallInstructions` reversed

- **Hypothesis**: `ColokTool.exe` as extracted from the data slice is *not* a
  valid image; Inno Setup post-processed it and Setup reverses it at install
  time.
- **Artefacts**: 68 of 4101 `MethodDef` RVAs fall outside every section until
  the transform is inverted; zero after.
- **Experiments**: implemented `TransformCallInstructions(encode=False)` from
  `Compression.Base.pas`; ran it over the whole file; compared with an
  independent reference decode — byte-identical.
- **Confirmed**: yes.
- **Status**: `validated` — `tests/test_inno670.py::TestCallInstructionTransform`
  plus the byte-identical cross-check recorded in `docs/validation-report.md`.

## R4 — The tool is a single managed (.NET) assembly

- **Hypothesis**: no separate native tool binary; the functionality lives in
  `ColokTool.exe` (PE32, .NET, `v4.0.30319`) plus four native DLLs it
  P/Invokes.
- **Artefacts**: CLI header at `0x2008`; 339 `TypeDef`, 4101 `MethodDef`;
  21 `AssemblyRef`; 6 `ModuleRef`; 89 `ImplMap`.
- **Status**: `validated` (metadata read directly; see `docs/architecture.md`).

## R5 — Payload AES key is derivable and matches the vendor's claim

- **Hypothesis**: `programs.bin` is AES-256-CBC under
  `Rfc2898DeriveBytes(SHA256(password), salt, 1000)`.
- **Artefacts**: `Loader_Thread::Encryption` IL; `saltBytes` and `key`
  initialised from `FieldRVA` arrays; 543/606 payloads decrypt to ELF.
- **Confirmed**: yes, and the vendor README omits the SHA-256 step (see R6).
- **Status**: `validated` — `tests/test_crypto.py`, and
  `test_majority_of_payloads_decrypt` in `tests/test_real_installer.py`.

## R6 — `OFFLINE-DATA-README.md` misdescribes the key derivation

- **Hypothesis**: the README's `key = SHA256(ASCII(password))` is wrong; the
  PBKDF2 password is the SHA-256 *digest*, not the ASCII string.
- **Experiments**: both derivations computed; only the digest form yields
  `7F 45 4C 46` on real payloads.
- **Confirmed**: yes — a documentation defect, not a code defect.
- **Status**: `validated` (`test_sha256_step_matters`).

## R7 — Second password `RDAXTEAMSEC2025` does not open these payloads

- **Hypothesis**: the README implies both passwords are interchangeable.
- **Experiments**: 0 of 606 payloads decrypt to ELF with the second password.
- **Confirmed**: yes.
- **Status**: `validated` (`test_second_password_not_interchangeable`).

## R8 — 63 `programs.bin` payloads do not decrypt with either password

- **Hypothesis**: a third key, or payloads that are not ELF at all.
- **Artefacts**: 17 distinct ciphertext prefixes; after decryption with the
  known key some begin `01 45 4C 46` ("\x01ELF"), `64 61 74 61` ("data"),
  `10 10 10 10` (PKCS#7-like), one is all zeroes.
- **Status**: `blocked`. Next experiment: search the whole 2.3 GB image for a
  third ASCII password literal, and check whether the `01 45 4C 46` prefix is
  a length-prefixed ELF written by a different loader path.

## R9 — Device identification is table-driven, not probed

- **Hypothesis**: USB VID/PID triples in `usb_ids.default_ids` classify a
  port; there is no protocol-level identification.
- **Artefacts**: 11 triples (`0E8D:0003/6000/2000/2001/20FF`,
  `1004:6000`, `22D9:0006`, `0FCE:F200/D1E9/D1E2/D1EC`).
- **Confirmed**: yes for the table. The runtime consumer of `default_ids` was
  not found by static analysis (see R10).
- **Status**: `promising`.

## R10 — Who reads `usb_ids.default_ids`

- **Hypothesis**: some port-scanner compares `Win32_PnPEntity` device IDs
  against the list.
- **Experiments**: exhaustive call-graph scan for any reference to the
  `default_ids` field — the only reference is the `.cctor` that fills it.
- **Status**: `insufficient-evidence`. The table is `private static`, so a
  reference could be reached only through a generated accessor we did not
  locate; equally likely, the list is dead code in this build. Not disproven.

## R11 — OEM dispatch happens through `data/{BRAND}/{brand}.xml`

- **Hypothesis**: the brand XML is the only dispatch input.
- **Artefacts**: `Main::LoadXmlFolder` (XmlReader over `<program>`),
  `Main::Buttonlist` (`info.Devices.Contains(brand & " " & model)`),
  `Loader_Thread::OperationSupported` (`\\operations.xml`, `<operation name=>`).
- **Status**: `validated` (`tests/test_datatree.py::TestBrandIndex`).

## R12 — A model folder name must equal `<name Devices> + " " + <name Models>`

- **Hypothesis**: this is the join key between index and payload.
- **Experiments**: measured across all 16 brand indexes: 608 of 1559 indexed
  devices have a folder with exactly that name.
- **Status**: `validated` (`test_model_key_is_devices_plus_models`,
  `test_script_inventory_is_stable`).

## R13 — Operation scripts are Qualcomm rawprogram XML, four element kinds

- **Hypothesis**: only `<program>` exists.
- **Experiments**: tag census over all 989 scripts: 46214 `<patch>`, 991
  `<program>`, 400 `<patches>`, 196 `<erase>`.
- **Status**: `validated` (`test_known_good_scripts_have_expected_entries`).

## R14 — 21 operation scripts are structurally broken

- **Hypothesis**: the tree is clean.
- **Experiments**: 8 scripts are zero bytes, 8 end with the literal text
  `EndCF` after the root element, 5 are truncated mid-document.
- **Status**: `validated` (`test_broken_scripts_are_the_known_three_kinds`).

## R15 — 1241 advertised operations have no script file at all

- **Hypothesis**: every `method` slot names a file that exists.
- **Experiments**: counted over the shipped tree: 2230 slots, 989 present,
  1241 missing. `XIAOMItyu` advertises 533 operations and has 0 files.
- **Status**: `validated` (`test_script_inventory_is_stable`).

## R16 — Login is entirely local in this build

- **Hypothesis**: `Btn_Login_Click` contacts a licence server.
- **Artefacts**: `UserReg::GetserverTime` is a stub that records the local
  clock and returns `true`; `UserReg::Check00` reads
  `data/accounts/accounts.json`; `config.ini` holds the saved user/pass.
- **Confirmed**: yes for the offline build.
- **Status**: `validated` (`tests/test_auth.py`).

## R17 — Some remote endpoints still exist in the code

- **Hypothesis**: the "offline" build contains no network code.
- **Artefacts**: `LoaderIP::GetActivationRecordFromServer` builds
  `https://pentaboy.my.id/ios/iOS16Act.php?udid=...`;
  `Passcode::uploadBackup` does a `WebClient.UploadFile`;
  `LoaderIP::downloadhello` downloads three files; `Loader_Thread.server`
  is the placeholder `https:///`.
- **Confirmed**: yes. These are iOS-side paths, not the Android workflows.
- **Status**: `validated` (static only — we did not contact them).

## R18 — MTK command framing

- **Hypothesis**: `cmdformat`/`cmdread` build a fixed-size payload wrapped in
  an xflash frame.
- **Artefacts**: `xflash_lib::cmdformat`, `cmdread`, `xsend4`, `ForMatSector`;
  `utils::applyshiftKiri2`, `penggenapan8`.
- **Experiments**:
  1. `ForMatSector` writes the frame header with length `0x38` = 56 directly
     (IL_00AF), pinning the payload at 56 bytes: `cmd(4) + selector(4) +
     start(8) + length(8) + reserved(32)`.
  2. `applyshiftKiri2` reverses the *byte order* of the hex text and keeps the
     width — it is not a shift. `penggenapan8` right-pads to 8 **bytes** (16
     hex chars), despite its name.
  3. The pair round-trips: `Hex(8584*512) = "431000"` →
     `applyshiftKiri2` → `"001043"` → `penggenapan8` → `"0010430000000000"` →
     read little-endian → `0x431000` = 4 395 008. So the reversal is correct,
     not a bug. My first reading of it (as `<< 2`) was **wrong** and the
     implementation was corrected.
- **Confirmed**: yes for the *client* side, against the IL and against
  mtkclient's `xflash_param.py` (`Cmd.MAGIC = 0xFEEEEEEF`, matching the frame).
- **Status**: `validated` for framing; `blocked` for the device side.

## R21 — The callers hard-code a 512-byte sector

- **Hypothesis**: the address the tool sends matches the script's
  `start_sector * SECTOR_SIZE_IN_BYTES`.
- **Artefacts**: `thread_handling.FormatFRP` and `xflash_lib.ReadSector` both
  pass `Conversions.ToString(ToDouble(start_sector) * 512.0)`, with 512
  literal.
- **Experiments**: for the ASUS ROG Phone 2 FRP script the declared sector
  size is 4096 and `start_sector` is 8584, so the tool sends 4 395 008 where
  the script means 35 160 064 — 8x short.
- **Confirmed**: yes, as a defect in the tool.  All scripts declaring
  `SECTOR_SIZE_IN_BYTES="512"` are unaffected; the 4096 ones are not.
- **Status**: `validated` (`mtk.wire_address(8584)` vs
  `mtk.wire_address(8584, 4096)`).

## R22 — The EDL path never touches the network

- **Hypothesis**: the `[EDL]` workflow downloads `programs.bin` and the
  operation script from `Loader_Thread.server`.
- **Artefacts**: `Loader_Thread.DownloadBytes(string)` is
  `try { return OfflineData.ReadAllBytes(path); } catch { return new byte[0]; }`
  — no HTTP at all. `server`/`server2` are the literal `https:///` and are
  never read by `DownloadBytes`.
- **Confirmed**: yes. A missing payload yields a zero-length array, which is
  why the tool then says "Loader Data File corrupt" / "Invalid Loader Data"
  rather than reporting a network error.
- **Status**: `validated` (IL read directly; `DownloadBytes` has no other
  branch).

## R23 — The operation-script resolution order

- **Hypothesis**: the tool reads the script from
  `data/{Brand}/{Model}/{operation}` and nothing else.
- **Artefacts**: `Loader_Thread.EMMCBootFlash` IL, in order:
  1. `File.Exists(root + "\\" + Brand + "\\" + Modelselect + "\\" + operation)`
  2. if missing: `OperationSupported(root + "\\" + Brand + "\\" + Modelselect)`
     — reads `{folder}\\operations.xml` and matches `<operation name=...>`
     against `Qctool.operation`
  3. if that returns non-empty → "Operation payload missing for this model",
     else → "Operation not supported by this model"
  4. otherwise `StringXml = UTF8.GetString(DownloadBytes(Brand + "/" + Model +
     "/" + operation))`
- **Confirmed**: yes. This is why the `method` slot, the `operations.xml`
  entry and the script filename have to be the same string, and why a model
  can have a working loader yet still refuse an operation.
- **Status**: `validated` (IL order is unambiguous).

## R19 — The device-side reply magic is a compile-time constant

- **Hypothesis**: `Port.magichex` is a literal we can read out of the image.
- **Experiments**: `magichex` is a `private static string` assigned at
  runtime by the DA handshake; no literal assignment found in the IL.
- **Status**: `disproven` for the hypothesis as stated; the mock in
  `mockdevice.py` therefore declares itself an assumption.

## R20 — No reference to `default_ids` outside its own initialiser

Covered by R10; kept as a separate row because it is the one place where
"absent from the call graph" could mean either dead code or an indirection we
could not see. We do not claim either.

## R24 — `data/` is a merge of four different tools' payload layouts

- **Hypothesis**: the data tree is one tool's tree, as `OFFLINE-DATA-README.md`
  describes.
- **Artefacts**: `data/SAMSUNG/` alone holds 202 model folders in five
  incompatible shapes:
  - **ColokTool**: `programs.bin` (+ `Reset FRP`, `operations.xml`) — 108
  - **PrimeToolX**: `device_info.txt` + `model.json` + `qualcomm.pyd` — 44
  - **MTK DA pair**: `<Model>_DA_BR.bin` + `_auth_sv5.auth` — 23 (+23 nested)
  - **auth.auth only** — 23
  - **Unisoc**: `fdl1.bin` + `fdl2.bin` — 2
- **Evidence the merge is real**: `_MERGE-BACKUP/` has 9 snapshots from
  2026-09-29; SAMSUNG's index goes 11 → 201 `<program>` rows across them, and
  XIAOMI is absent from the first six snapshots and present in the last three.
  `data/SAMSUNG/SM-X826B.B2.mt6989_DA_BR/samsung.xml` is a third brand index
  inside a DA-pair folder, i.e. a whole directory tree was copied wholesale.
- **Confirmed**: yes.
- **Status**: `validated` — `docs/data-layouts.md`.
- **Consequence**: the compatibility matrix counts only layout E, which is
  correct for *this binary* but understates what is shipped.

## R25 — The loader check is a substring test, not an ELF test

- **Hypothesis**: the tool validates a loader by checking the ELF magic.
- **Artefacts**: `EMMCBootFlash` and `EMMCBootPLUS` both do
  `Encoding.UTF8.GetString(loader, 0, 20).ToUpper().Contains("ELF")`.
- **Experiments**: re-implemented that predicate and compared it with
  `loader[:4] == b'\x7fELF'` across all 528 shipped loaders — 495 accept, 495
  ELF, **zero disagreements**.
- **Confirmed**: the tool's check is looser than an ELF check, but on this
  data set the two agree exactly, so the looseness is not exploitable here.
- **Status**: `validated`.

## R26 — The 33 rejected loaders split into four distinct causes

- **Hypothesis**: the 33 non-ELF loaders are all a wrong key.
- **Artefacts** (after decrypting with the documented key and stripping
  padding):
  - 6 × `d1 dc 4b 84 …` — **solved: a second, self-describing container**.
    After PKCS#7 strip the header is

        off 0x00  u32 magic     0x844BDCD1
        off 0x04  u32 magic2    0x73D71034
        off 0x08  u32 count     13 or 21
        off 0x0c  u32[2]        0xFFFFFFFF (unused)
        off 0x14  u32 hdr_len   0x50
        off 0x18  u32 load_addr e.g. 0xF800C000
        off 0x1c  u32 payload_len

    and `payload_len == len(file) - hdr_len` holds exactly for **all six**
    files. The remaining header words look like a second (load, len) pair
    (`0x00049000, 0xF8055000`), a sector size (`0x100`), a chunk size
    (`0x1800`) and two flag words.

    The payload is ARM code, in two flavours: five are ARM32 (`EA000006`
    branch trampolines, then `E321F0D3` = `MSR CPSR_c, #0xD3`, i.e. switch to
    supervisor mode and disable IRQ/FIQ) and one is ARM64 (`D51EC000`,
    `940002BA` BL, `D65F03C0` RET). This is a pre-loader / download-agent stub,
    not a firehose ELF, which is why it is not `\x7fELF` and why the tool's
    `Contains("ELF")` check rejects it.

    Implemented in `src/unlocktool_re/container.py`; the invariant above is
    the test (`tests/test_container.py`).
  - 2 × `7f 45 4c 45` — a real ELF whose 4th byte is `0x45` instead of `0x46`.
    Patched to `0x46`, the OPPO A71 header parses as ELF32 `ET_EXEC`,
    `e_machine=0x28` (ARM), `e_phoff=52`, `e_phentsize=32`, `e_phnum=9`, and
    its first three program headers are all inside the file — so the rest of
    the image is intact and only byte 3 is wrong. (The XIAOMI Poco F1 one is
    ELF64 and also parses once byte 3 is fixed.) Cause: one corrupted byte in
    the source file, which the tool's `Contains("ELF")` check would *accept*
    and then fail on at load time.
  - 2 × `10 10 10 10` × 16 (16 bytes) — **proven empty files**.
    `crypto.encrypt_programs_bin(b'')` produces exactly
    `5e17fe6eafcebb035692b623e88d90ae`, which is byte-identical to what the
    shipped `Vivo iQOO 9 SE 5G [PD2154F]` and `Vivo iQOO Pro [PD1916]`
    payloads contain. So the vendor shipped a correctly-encrypted empty file
    in two folders; there is no missing key here at all.
  - 1 × `64 61 74 61 20 64 64 63 68` ("data ddch" then `5E 59 57 00`) —
    OPPO A77T. Starts with the literal ASCII `data ddch`, so it is a
    container whose magic is text, not a wrong key.
  - 1 × `aa 43 3b 30 …` (XIAOMI Poco F4) and 1 × `dc 7b bd 85 …` (XIAOMI
    Civi 2, 16 bytes) — two more distinct keys or formats.
  - 20 × `ae 91 a6 a9 …` — **one file, copied 20 times** (same sha256,
    661 280 bytes, across OPPO, REALME and VIVO).
- **Confirmed**: the causes are heterogeneous, and two of the five groups are
  now fully explained (empty files, one corrupted byte).
- **Status**: `validated` for the classification; `blocked` on the key for the
  remaining 23 (which are only 4 distinct files).

Final tally of all 528 shipped loaders, after decryption:

| Class | Count |
|---|---|
| ELF firehose loader | 495 |
| ARM pre-loader container (R26, `container.py`) | 6 |
| ELF with one corrupted byte | 2 |
| correctly-encrypted empty file | 2 |
| undetermined (4 distinct files) | 23 |

## R30 — There is no second AES key in `ColokTool.exe`

- **Hypothesis**: the 23 undetermined loaders (4 distinct files) use a second
  password that is also a literal in the binary.
- **Experiments**: enumerated all 18 `FieldRVA`-initialised byte arrays and
  extracted every printable run of 6–32 bytes from each. Candidates found:
  `RDAXTEAM2024`, `RDAXTEAMSEC2025`, `RDAXTEAM`, `gdKa!x5`, `v4.0.30319`.
  Tried all four plausible ones against the 4 distinct undetermined files
  through the full KDF + AES path. **Zero hits.**
- **Confirmed**: no second key is recoverable this way.
- **Status**: `disproven` for "the second key is a literal in this binary".
  The undetermined payloads must come from the *merged-in* tools (PrimeToolX /
  DA-pair), which are not part of this assembly.
- **Note**: this also means `Loader_Thread` has exactly one key, matching the
  IL, so the ColokTool path can never use those 23 files.

## R27 — The `[EDL]` operation scripts are the firehose plan, not a partition map

- **Hypothesis**: the operation scripts are only used by the MTK path.
- **Artefacts**: `EMMCBootFlash` assigns
  `StringXml = UTF8.GetString(DownloadBytes(Brand + "/" + Model + "/" + operation))`
  and `ProcessQcomFlash` then walks `StringXml` with an `XmlTextReader`,
  reading `SECTOR_SIZE_IN_BYTES`, `num_partition_sectors`, `label`,
  `filename`, `physical_partition_number`, `start_sector` and calling
  `WriteFlash(sector_size, num_sectors, lun, filename, label)`.
- **Confirmed**: yes — the same file is the Qualcomm plan and (for MTK) a
  partition map.
- **Status**: `validated`.

## R28 — Samsung's "Odin" path shells out to `data/dn.exe`

- **Hypothesis**: `Tread_SAMSUNG` implements the Odin protocol in managed code.
- **Artefacts**: `Tread_SAMSUNG.ExecuteOdin` builds a
  `ProcessStartInfo { FileName = StartupPath + "/data/dn.exe",
  WorkingDirectory = StartupPath + "/data", Arguments = …, RedirectStandardOutput = true }`
  and parses the child's stdout with `DataReceivedEventHandler`.
  `OdinDetect` runs `data\dn.exe` with the verb `runas`.
- **Experiments**: `data/dn.exe` is **not in the installer** (no payload entry
  matches `dn.exe`).
- **Confirmed**: the Odin path is an external-binary wrapper, and the binary is
  absent, so the Samsung workflows cannot run from the shipped archive at all.
- **Status**: `validated` (absence confirmed against all 7 387 payload names).

## R29 — `data/dn.exe` and the four vendor DLLs are all absent

- **Hypothesis**: the installer is self-contained.
- **Artefacts**: cross-checked every `ImplMap`/`Process` target against the
  payload list: `dn.exe`, `QMSL_MSVC10R.dll`, `SPMETA_DLL.dll`,
  `spdio-1.0.dll` and `PhoneCommand.dll` are all missing. `data/Unisoc/` does
  not exist in the tree at all.
- **Confirmed**: yes.
- **Status**: `validated`. This is the single largest boundary on the whole
  investigation: five external dependencies are referenced and none ship.

## R31 — `_auth_sv5.auth` names two unrelated formats

- **Hypothesis**: the 42 `_auth_sv5.auth` files are one kind of thing.
- **Artefacts**: 2 are 2 256/2 272 bytes and are `MMM` containers; 40 are
  ~1 049 756 bytes and are `MotoKingProS`/`R` blobs.
- **Status**: `validated` (`tests/test_motoking.py::TestAuthInventory`).

## R32 — The `MMM` auth container: u16 length that includes the header

- **Hypothesis**: `MMM\x01` + u32 length + body (first reading).
- **Experiments**: that reading declares 329 535 bytes for a 2 272-byte file.
  Reading the length as **u16 at offset 4** gives 56, 1944, 16 — three blocks
  that tile the file exactly, followed by a 256-byte trailer:
  `FILE_INFO` / `MTK…` / zeros / signature.
- **Confirmed**: yes. The u32 reading was wrong and is retracted.
- **Status**: `validated`
  (`test_mmm_block_length_is_u16_and_includes_the_header`).
- **Note**: the 256-byte trailer matches `size_in_bytes="256"` in the `sig`
  request of `EMMCBootFlash`, suggesting a captured auth exchange.

## R33 — The 23 `auth.auth` files are ASCII-mangled and unrecoverable

- **Hypothesis**: they are a third format worth parsing.
- **Artefacts**: every one is 7-bit clean (`max(byte) <= 0x7F`) with `0x3F`
  in exactly the positions a high byte belonged — 509 of 2 269 bytes in the
  A15 file. The `MMM` magic survives, the length fields do not.
- **Confirmed**: they are text-channel-corrupted copies of the `MMM` container.
- **Status**: `validated` (`test_the_23_mangled_auth_auth_files_are_7bit_only`);
  recovery is `disproven` — the information is gone.

## R34 — `MotoKingProS` / `MotoKingProR`: a fifth vendor's container

- **Hypothesis**: the 40 large `_auth_sv5.auth` files are opaque.
- **Artefacts**: magic `MotoKingProS` (34) / `MotoKingProR` (6), **big-endian**
  version 4, three big-endian header fields, a truncated base64 filename, a
  6-byte marker `0C 00 3F 67 3D 00`, ~1 049 686 bytes of payload, and a
  4-byte zero tail.
- **Experiments**: the base64 field decodes to the original filename, e.g.
  `U00tQTE1NUYuQjUubXQ2Nzg5X2F1dGhfc3Y1Lm` → `SM-A155F.B5.mt6789_auth_sv5.`,
  which recovers the MTK chipset per model. Reading the header integers
  little-endian gives version 67 108 864, i.e. it is provably BE.
- **Confirmed**: yes. Implemented in `src/unlocktool_re/motoking.py`.
- **Status**: `validated` (`tests/test_motoking.py`).
- **Limitation**: the payload itself is not decoded. The `fields` triple
  varies with the magic revision and payload size class, which suggests it
  encodes a length/CRC rather than being a constant.

## R35 — Two `_DA_BR` folders have their contents swapped

- **Hypothesis**: each `_DA_BR` folder holds its own model's blobs.
- **Artefacts**: `SM-A156B.B5.mt6835_DA_BR/` contains
  `SM-A156E.B5.mt6789_auth_sv5.auth`, and `SM-A156E.B5.mt6789_DA_BR/` contains
  `SM-A156B.B5.mt6835_auth_sv5.auth`. The other 18 are self-consistent.
- **Confirmed**: provable, because the blob's own base64 field names the model
  it belongs to.
- **Status**: `validated` (`test_two_da_folders_hold_the_other_models_blob`).

## R36 — `EMMCBootFlash` honours `SECTOR_SIZE_IN_BYTES`; the MTK path does not

- **Hypothesis**: R21's hard-coded 512 is a whole-tool habit.
- **Artefacts**: `EMMCBootFlash` reads `SECTOR_SIZE_IN_BYTES` and maps
  `"512"` → `TypeMemory = "emmc"`, `"4096"` → `"ufs"`, and passes the script's
  sector size to `WriteFlash`. Only `thread_handling.FormatFRP` and
  `xflash_lib.ReadSector` hard-code `512.0`.
- **Confirmed**: the defect is confined to the MTK path; the firehose path is
  correct.
- **Status**: `validated`
  (`tests/test_ildump.py::test_firehose_path_reads_sector_size_from_the_script`
  and `test_mtk_callers_hardcode_512`).

## R37 — The exact firehose auth exchange

- **Hypothesis**: the tool only sends `ACK`/`NAK`-checked commands.
- **Artefacts**: `EMMCBootFlash` sends
  `<data><sig TargetName="sig" size_in_bytes="256" verbose="1"/></data>` when
  the device replies `Only nop and sig tag`, then expects `"ACK"` / `"NAK"` /
  `Signature Verification Failed` inside the response.
- **Confirmed**: yes, from the IL literal.
- **Status**: `validated` (`tests/test_ildump.py::TestOperationResolution`
  covers the surrounding control flow).
