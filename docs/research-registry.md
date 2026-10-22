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

- **Hypothesis**: `cmdformat`/`cmdread` build a 24-byte payload wrapped in an
  xflash frame.
- **Artefacts**: `xflash_lib::cmdformat`, `cmdread`, `xsend4`;
  `utils::applyshiftKiri2`, `penggenapan8`.
- **Confirmed**: yes for the *client* side.
- **Status**: `promising`. The device-side reply format is not recoverable
  statically (the magic is set at runtime), so it stays simulated.

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
