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

**Next experiments**:

1. The 20-copy file: since 20 folders across three brands share it byte for
   byte, it is one chipset's loader and probably comes from the *same* other
   tool as the PrimeToolX folders. Check whether it appears under a different
   name in a `_DA_BR`/PrimeToolX folder.
2. `data ddch`: the ASCII magic suggests a text-tagged container. Search the
   whole image for other files starting `data ` and compare headers.
3. The 16-byte file: `encrypt(b'')` is 16 bytes but a *different* 16 bytes, so
   this one is genuinely some other key or a 16-byte secret. Brute-force is not
   worth it; look for a second key literal in the binary first.

**Why it matters**: it is the difference between "495/528 loaders usable" and
"all of them classified".

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

## 2b. Read the MTK DA pairs (23 folders)

23 SAMSUNG folders ship `<Model>_DA_BR.bin` (1.5–1.8 MB) + `<Model>_auth_sv5.auth`
(1 049 756 bytes, a suspiciously round size) and a two-line advert as the only
README. Those are MTK Download Agents, which this binary never reads — it uses
its own `programs.bin` route.

**Next experiments**: the `.auth` blobs are all 1 049 756 bytes with a 2 269-
byte `auth.auth` sibling in 23 other folders. Diff two of them: if only a few
bytes differ, the common part is a template and the differing part is per-model
signing material.

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

## 6. Decode the `.ofp` and `.pac` containers

`OFPExtractor` (3 894 IL ops) and `UniFlash.PACExtractor` (1 577) are
implemented but their containers were not parsed here. Both are self-contained
file formats with no device dependency, so they are cheap to reproduce and
would extend the matrix to OPPO firmware flashing and Unisoc.

## 7. Not attempted

- iOS activation (`LoaderIP`, `Passcode`): depends on Apple infrastructure and
  a remote service. Documented, not reproduced, and not pursued.
- Samsung Odin (`Tread_SAMSUNG`): the protocol is implemented but its
  handshake constants were not extracted.
- Anything requiring a physical device.
