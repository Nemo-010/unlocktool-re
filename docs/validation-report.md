# Validation report

Three evidence tiers are used throughout. A finding only appears in tier 1 if
a test fails when the finding is wrong.

| Tier | Meaning |
|---|---|
| **Verified** | Reproduced and covered by an automated test that was observed to fail when the behaviour was mutated |
| **Simulated** | Reproduced against a mock; the real counterpart is unavailable |
| **Inferred** | Read out of the artefacts but not executed (no test can falsify it yet) |

Nothing in this report was validated on physical hardware. No device was
attached at any point, and no remote endpoint was contacted.

---

## 1. Verified

### 1.1 Inno Setup 6.7.0 container

| Claim | Test | Mutation that makes it fail |
|---|---|---|
| Both header blocks are consumed to the exact byte | `test_real_installer.TestContainer.test_headers_fully_consumed` | any field-width change in `setup0.py` leaves trailing bytes |
| 7 387 file entries, 7 386 locations, 1 559 brand models | `test_entry_counts`, `test_dest_names_unique` | — |
| Payload totals 4 322 930 069 bytes | `test_payload_size_matches_index` | — |
| Loader table is `offset0=0x8A9C1D1E`, `offset1=0x105200`, size `2327092946` | `test_loader_table` | — |
| Setup encryption is disabled (`EncryptionUse=0`) | `test_no_setup_encryption` | — |
| The embedded `ColokTool.exe` is 51 785 728 bytes and starts `MZ` | `test_read_embedded_exe` | — |

**Byte-identical cross-check for `TransformCallInstructions`.** The
implementation in `inno.py` was run over the extracted 51 785 728-byte
`ColokTool.exe` and compared with an independent reference decode produced
during analysis:

```
$ cmp ColokTool.fixed.exe ColokTool.decoded.exe
IDENTICAL to reference decode
```

After the transform, 0 of 4 101 method bodies are unresolvable; before it, 68
are. This is the strongest single piece of evidence in the report: it is a
byte-exact match on a 49 MiB artefact.

### 1.2 Payload encryption

| Claim | Test |
|---|---|
| AES-256 block function matches FIPS-197 | `test_crypto.TestAESPrimitive.test_fips197_aes256_block` |
| CBC matches NIST SP 800-38A | `test_crypto.TestAESPrimitive.test_sp800_38a_cbc_aes256` |
| Pure-Python AES equals OpenSSL | `test_crypto.TestPurePythonMatchesOpenSSL` |
| Derived key/IV are the documented 48-byte PBKDF2 prefix | `test_derived_key_vector`, `test_iv_continues_the_same_pbkdf2_stream` |
| Salt is the 14-byte literal `00 00 01 02 03 04 05 06 F1 F0 88 10 22 95` | `test_salt_is_the_shipped_literal` |
| 543 of 606 `programs.bin` decrypt to ELF | `test_real_installer.TestPayloadCrypto.test_majority_of_payloads_decrypt` |
| The second password does not open them | `test_second_password_does_not_work` |
| The SHA-256 pre-hash is required | `test_sha256_step_matters` |

Mutation checks performed and observed to fail:

- removing the SHA-256 pre-hash → 4 failures, and
  `test_majority_of_payloads_decrypt` drops from 543 to **0** ELF payloads
- deriving the IV from `dk[:16]` instead of `dk[32:48]` → 2 failures

### 1.3 Data tree

| Claim | Test |
|---|---|
| `model.key == Devices + " " + Models` | `test_datatree.TestBrandIndex.test_model_key_is_devices_plus_models` |
| `method` slots M1..M8 (and M9/M10 where present) become operations | `test_operation_slots`, `test_operation_set_handles_m10` |
| Empty slots are dropped | `test_operation_slots` |
| 2 230 advertised slots, 989 scripts present, 1 241 missing | `test_script_inventory_is_stable` |
| 21 scripts are broken: 8 empty, 8 trailing `EndCF`, 5 truncated | `test_broken_scripts_are_the_known_three_kinds` |
| 968 scripts parse; 392 contain `<patch>`, 90 contain `<erase>` | `test_known_good_scripts_have_expected_entries` |
| Salvage recovers the three `<program>` rows from a truncated script | `test_salvage_recovers_elements_from_broken_scripts` |
| The ASUS ROG Phone 2 FRP script is a single erase of `frp` at sector 8584 | `test_asus_frp_script_is_erase_only` |

### 1.4 Operation dispatch and plan building

| Claim | Test |
|---|---|
| 55 distinct operation names exist in the tree | `test_dispatch...test_every_distinct_operation_classifies` |
| 12 of them are payload filenames, not operations | same |
| 841 of 2 230 advertised operations build a complete plan | `test_plan.TestPlanCoverage.test_runnable_operation_count` |
| Those 841 plans total 46 447 steps | same |
| Every one of the 841 executes to completion on the mock | `test_every_runnable_plan_executes_on_the_mock` |
| Failures are attributed to exactly six causes, with counts | `test_runnable_operation_count` |

The failure breakdown (measured, not estimated):

| Reason | Count |
|---|---|
| payload folder missing | 1 116 |
| referenced payload missing | 126 |
| operation script missing | 125 |
| script is malformed XML | 13 |
| script is empty | 8 |
| script produced no steps | 1 |

### 1.5 The non-ELF loader container

| Claim | Test |
|---|---|
| Magic `0x844BDCD1`/`0x73D71034`, header 0x50 | `test_container.TestSynthetic.test_roundtrip` |
| `payload_len == filesize - 0x50` on all six | `test_container.TestRealPayloads.test_all_six_parse` |
| Five payloads are ARM32, one is ARM64 | `test_payload_is_arm_code` |
| A lying `payload_len` is rejected | `test_rejects_length_mismatch` |

Mutation check: setting `payload_len` to a value that does not match the file
body makes `parse` raise, which is what makes the invariant load-bearing rather
than decorative.

### 1.5b The IL tooling itself

`tests/test_ildump.py` (15 tests) re-checks every IL citation in these docs
against the assembly using only `tools/il/`:

| Claim | Test |
|---|---|
| Assembly shape (339 TypeDef, 4 101 MethodDef, 89 ImplMap, 18 FieldRVA) | `TestTooling.test_assembly_shape` |
| Zero unmapped method RVAs after decoding | `test_every_method_body_resolves` |
| SHA-256 is applied to the password before the KDF | `test_sha256_precedes_the_kdf` |
| One `Rfc2898DeriveBytes` instance supplies key and IV | `test_aes_parameters` |
| Mode = CBC | `test_mode_is_cbc` |
| Loader check is `Contains(\"ELF\")` on 20 bytes | `test_loader_check_is_a_substring_test` |
| `DownloadBytes` is local-only | `test_downloadbytes_is_local_only` |
| MTK frame is 56 bytes (`0x38`) | `test_format_sector_uses_a_56_byte_frame` |
| MTK callers hard-code 512, firehose path reads the field | `test_mtk_callers_hardcode_512`, `test_firehose_path_reads_sector_size_from_the_script` |
| Odin shells out to `data/dn.exe` | `test_odin_shells_out_to_dn_exe` |

These run when `UNLOCKTOOL_COLOKTOOL` points at a decoded `ColokTool.exe`, and
skip otherwise, so the repo stays honest about which claims are currently
re-checked.

### 1.5c MTK scatter parsing

| Claim | Test |
|---|---|
| All 158 `android.txt` files parse | `test_scatter.TestRealScatterFiles.test_every_android_txt_parses` |
| All 158 declare `platform:` | `test_platform_is_recorded_for_every_file` |
| All 158 describe an `frp` partition | `test_every_scatter_declares_an_frp_partition` |
| Both indentation variants parse identically | `test_indented_variant_parses_identically` |
| `file_name: NONE` is not a download | `test_downloads_only_counts_real_payloads` |

### 1.6 Local account / licence

`test_auth.py` (19 tests) covers the `Check00` control flow, the
case-insensitive `UserName`/`Email` match, the password comparison, the
`Substring(1, 12)` hardware-ID binding, date parsing with its fallback, the
`Status`/`Expired` gate, and `config.ini` round-tripping.

---

## 2. Simulated

| Claim | Where | Why it cannot be verified |
|---|---|---|
| MTK command framing (48-byte payload, `EF EE EE FE` frame) | `mtk.py`, `test_mockdevice.py` | the client side is recovered from IL, but there is no captured traffic to compare against |
| Device reply format (magic + status + echoed length) | `mockdevice.py` | the real magic is a runtime value from the DA handshake (`Port.magichex`), not a compile-time constant |
| Erase/write/patch sequencing against a device | `plan.py`, `test_plan.py` | no device attached |
| OPPO `.ofp` container offsets | `ofp.py`, `test_ofp.py` | no `.ofp` ships in the archive, so the reader is only exercised against fixtures built to the same rules |
| Transport failure handling (silent device, bad magic, error status, short reply) | `test_mockdevice.TestFailureModes` | these are the *client's* reactions, which are recovered; the device's real reactions are not |

`MockDevice.assumption` records the simulated status in the code itself, and
`tests/test_mockdevice.py::test_mock_declares_itself_as_an_assumption` asserts
that string is present, so the disclaimer cannot be dropped silently.

---

## 3. Inferred only

These are stated in the docs but have no test that could fail, because the
artefact needed to falsify them is not present.

| Claim | Source |
|---|---|
| Qualcomm firehose command set (`configure`, `read`, `program`, `erase`, `patch`, `getstorageinfo`, `nop`) | method names and string literals in `Loader_Thread` |
| Firehose state machine (Sahara → READY → firehose → reset) | `QCThread.hangHack`, `sendFlashLoader` error strings |
| MTK port bring-up sequence | `Port.CariPortMtk`, `HandshakeMtk`, `HandshakeMtkBrom` |
| USB VID/PID classification table (11 triples) | `usb_ids.default_ids` initialiser |
| Which code reads `usb_ids.default_ids` | not found (see R10) |
| The four native DLL roles | `ImplMap` import names |
| iOS activation flow | `LoaderIP`, `Passcode` string literals and calls |

---

## 4. Disproven hypotheses

| Hypothesis | Result |
|---|---|
| The supplied `.exe` *is* the unlocking tool | Disproven: it is an Inno Setup installer (R1) |
| The payload can be read without reversing `TransformCallInstructions` | Disproven: 68 method bodies are unreachable (R3) |
| The vendor README's key derivation is correct as written | Disproven: it omits the SHA-256 pre-hash (R6) |
| Both documented passwords open the payloads | Disproven: 0/606 with the second (R7) |
| `Port.magichex` is a compile-time constant | Disproven: it is assigned at runtime (R19) |
| The tree is internally consistent | Disproven: 1 241 missing scripts, 21 malformed scripts, 166 missing payloads (R14, R15) |
| The 33 non-ELF loaders are all one problem | Disproven: four distinct causes, two of them fully explained (R26) |
| A second AES key is a literal in the binary | Disproven: all 18 `FieldRVA` arrays tried, zero hits (R30) |
| `data/` is one tool's data tree | Disproven: five payload layouts coexist; `_MERGE-BACKUP` shows SAMSUNG going 11 → 201 program rows (R24) |
| The Odin path is managed code | Disproven: it shells out to `data/dn.exe`, which is not shipped (R28) |
| The `MMM` block length is a u32 | Disproven: it is a u16 that includes the 8-byte header; the u32 reading declares 329 KB for a 2.2 KB file (R32) |
| The 23 `auth.auth` files are a parseable third format | Disproven: they are ASCII-mangled copies, 7-bit clean with `0x3F` over every high byte (R33) |
| The `MotoKingProS` header is little-endian | Disproven: a BE read gives version 4, an LE read gives 67 108 864 (R34) |

---

## 5. What was never done

- No device was connected. Every hardware statement is either recovered from
  IL or explicitly marked simulated.
- No remote endpoint was contacted. The four URLs found in the code are
  documented as strings only.
- The four vendor DLLs were never loaded (they are not in the installer).
- The `windows-*` code paths were not executed; the PE is IL-only and was
  analysed statically.
