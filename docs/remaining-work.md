# Remaining work

Ordered by how much uncertainty each item removes per unit of effort.

## 1. Identify the last 4 undecrypted loader files

**Status after this round.** The 33 non-ELF loaders are no longer one mystery:

| Class | Count | Resolved |
|---|---|---|
| ARM pre-loader container | 6 | yes — `container.py`, `payload_len` invariant |
| ELF with one corrupted byte | 2 | yes — byte 3 is `0x45`, rest parses |
| correctly-encrypted empty file | 2 | yes — byte-identical to `encrypt(b'')` |
| undetermined | 23 | **no — but only 4 distinct files** |

The 23 are: 20 copies of one 661 280-byte file (`ae 91 a6 a9 …`), one OPPO
A77T file starting `data ddch` (ASCII magic), one XIAOMI Poco F4 file
(`aa 43 3b 30 …`) and one 16-byte XIAOMI Civi 2 file (`dc 7b bd 85 …`).

**Already tried, with results** (do not repeat):

1. Every `FieldRVA` literal in the binary as a password — zero hits (R30).
2. Length-prefixed ELF (`01 45 4C 46`) — none.
3. PKCS#7-of-empty — only the 2 already accounted for.
4. ARM32/ARM64 detection on the OPPO A77T body, in place and dword-swapped —
   neither; it is still encrypted.
5. The 20-copy file is byte-identical across OPPO/REALME/VIVO, so it is one
   chipset loader, not a per-model artefact.

**Next experiments that need a new artefact, not more work on this one:**

1. Find the merged-in tool that owns them. The OPPO A77T file's `data ddch`
   magic is the best lead: search the Electrosphere for that literal.
2. Ask the vendor. There is no in-tree documentation for these four.

**Why it matters**: it is the difference between "495/528 loaders usable" and
"all of them classified". See R39 for the full evidence table.

## 1b. Find the second AES key, if there is one

The 23 undetermined files above, plus the 33 loaders the tool *accepts but
cannot use*, suggest at least one more key exists somewhere. `Loader_Thread`
has exactly one `key` field, so the second key — if it exists — is in another
class or in the merged-in tools' payloads, not in `ColokTool.exe`.

**Next experiment**: enumerate every `FieldRVA`-initialised byte array in the
binary (there are 18) and try each 12-to-24-byte one as a password. This is
cheap: the KDF is 1000 iterations and there are 606 files.

## 2. Recover the device-side MTK reply format

**Blocker.** `Port.magichex` is assigned at runtime. Without a capture, the
mock's reply framing is an assumption.

**Next experiments**:

1. Trace `Port.HandshakeMtk` and `HandshakeMtkBrom` fully: the magic is
   probably copied from a specific offset of the handshake reply, which would
   make it derivable from the *request* sequence rather than from hardware.
2. Look for a `magichex` assignment site that reads from a constant array
   (`ldtoken` + `InitializeArray`) — the earlier scan only matched literal
   strings.

**Why it matters**: it would move MTK from "simulated" to "verified" without
hardware.

## 2b. Decode the `MotoKingProS` payload

**Status**: the container is parsed (`motoking.py`), the filename field is
decoded, but the ~1 049 686-byte payload is opaque.

**Next experiments**:

1. The three `fields` triples vary with magic revision *and* payload size
   class. Check whether `fields[2]` correlates with `len(payload)` — if it
   does, it is a length/CRC and the payload start is confirmed.
2. Compare two blobs of the same magic and same payload length byte for byte.
   If they differ only in a small region, the rest is a template (a DA image)
   and the differing region is per-model signing material.
3. The payload should begin with either an ELF header or an ARM branch, like
   the two containers already solved. Check the first 16 bytes of each.

## 2c. The `MMM` auth container's 256-byte trailer

**Status**: the container parses (three blocks + 256-byte trailer), and the
trailer size matches the `sig size_in_bytes="256"` in `EMMCBootFlash`. Whether
it *is* that signature is not established.

**Next experiment**: check whether the 256 bytes verify against anything in
the tree (a public key in `data/frp/SignedKey.txt`, which
`UserReg.cekauthfrp` reads, is the obvious candidate).

## 2d. What `data/DA/Extras/*.auth` are for

`data/DA/Extras/` holds exactly two `MMM` containers, `new_auth_sv5.auth` and
`old_auth_sv5.auth`. They are the only parseable ones in the tree. Diffing
them gives the template; finding what references them would say whether the
tool ever sends them.

## 3. Determine whether `usb_ids.default_ids` is live

**Blocker.** The list is `private static` and its only reference is its own
initialiser. Either it is dead code or it is read through an indirection we did
not resolve.

**Next experiments**:

1. Dump every `ldsfld`/`ldsflda` whose `FieldDef` resolves to
   `usb_ids::default_ids` — done, one hit, the `.cctor`. Re-check with a
   `MemberRef`-based scan (a field accessed from another assembly would appear
   as a `MemberRef`).
2. Check whether `SetupAPI`-style enumeration happens in
   `ColokTool.RDAmod.Qmslphone.Listdiagport` (`ListAllportxx`) instead.

**Why it matters**: it decides whether device identification is table-driven
(as documented) or purely probe-driven (in which case the table is misleading).

## 4. Model the four native DLL boundaries

**Blocker.** `QMSL_MSVC10R.dll`, `SPMETA_DLL.dll`, `spdio-1.0.dll`,
`PhoneCommand.dll` are absent from the installer. 68 P/Invoke sites stop there.

**Next experiments**:

1. Enumerate all 89 `ImplMap` entries with their declaring type and method
   signature, and write a typed stub module for each — enough to make the
   call graph complete even without the implementation.
2. For `QMSL_MSVC10R`, the exported names (`QLIB_DIAG_NV_READ_F`,
   `QLIB_NV_WriteNVsToMobile`, …) match Qualcomm's public QLIB API, so the
   semantics can be documented from the API rather than from the binary.

## 5. Explain the 1 241 missing operation scripts

**Blocker.** 1 241 of 2 230 advertised operations have no file. `XIAOMItyu`
alone advertises 533 and has zero files.

**Next experiments**:

1. Check whether those brand indexes are stale copies of a newer index (diff
   `XIAOMI/xiaomi.xml` against `XIAOMItyu/xiaomityu.xml`).
2. Check whether the missing scripts live in `_MERGE-BACKUP/` (27 files there).

**Why it matters**: it separates "the vendor shipped a broken index" from
"our extraction missed a file". The extraction already proves the latter is
false (all 7 387 entries were accounted for), so this is almost certainly a
vendor data defect — but confirming the mechanism is worth one pass.

## 6. Validate the `.ofp` reader against a real file

**Status**: `ofp.py` implements the layout from the IL (probe at
`len + 16 - page_size`, `xml_offset = u32_le(base+20) * page_size`,
`xml_size = u32_le(base+24)`, region rounded up to 16), and round-trips
fixtures at both page sizes. **No `.ofp` ships in the archive**, so nothing has
validated the offset arithmetic against real data.

**Next experiment**: set `OFP_SAMPLE=/path/to/file.ofp` and run
`python3 -m unittest tests.test_ofp`. If `xml_offset` lands on `<` and the
region parses as XML, the reader is confirmed; if not, the probe constant or
the `+20`/`+24` offsets need re-deriving from `BruteKeyQcom`.

## 6b. Decode the `.pac` container

`UniFlash.PACExtractor` (1 577 IL ops) is implemented but not reconstructed
here. It is self-contained with no device dependency, so it is the next cheap
win and would cover the Unisoc flashing path (29 models already have
`fdl1`/`fdl2`).

## 6c. The 158 scatter models are readable but not drivable — resolved

**Resolved this round, as a negative.** `android.txt` is parsed by both
`RDA.MtkScatter.ScatterTable` and `DXApplication.Mtkxml.ScatterTable`, but both
are reachable only from a manual `"Choice Scatter Or OFP File !"` dialog
(`Main.Button2_Click_1`, `Main.Button21_Click`, `Main.loadOfpScatter`). The
brand-index `[BROM]` path (`thread_handling.FormatFRP`) gets its partition map
from `gpt.readgpt` over the wire, never from the scatter file.

So the scatter layout does **not** make those 158 models drivable from the UI,
and the "missing script" count for them is a true negative. The honest
drivable figure is 383 method rows, not 715 folders.

**What is still open**: whether `gpt.readgpt` alone is sufficient for
`[BROM]` FRP — i.e. whether a model with a `programs.bin`-less folder and a
working BROM handshake could still reset FRP from the on-device GPT. That is a
device-side question, not a static one.

## 7. Not attempted

- iOS activation (`LoaderIP`, `Passcode`): depends on Apple infrastructure and
  a remote service. Documented, not reproduced, and not pursued.
- Samsung Odin (`Tread_SAMSUNG`): the protocol is implemented but its
  handshake constants were not extracted.
- Anything requiring a physical device.
