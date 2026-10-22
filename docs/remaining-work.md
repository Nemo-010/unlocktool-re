# Remaining work

Ordered by how much uncertainty each item removes per unit of effort.

## 1. Find the key for the 63 non-decrypting `programs.bin` payloads

**Blocker.** 63 of 606 loaders do not decrypt to ELF with either documented
password. 17 distinct ciphertext prefixes exist, so this is not one stray
file.

**Next experiments**, in order:

1. Search the whole 2.3 GB image for printable strings that look like a
   password (`^[A-Z0-9]{8,24}$`) and try each through the same KDF. The image
   is already parsed; this is a one-pass scan over `slice_offset`.
2. Check the two payloads whose plaintext begins `01 45 4C 46` ("\x01ELF") —
   that looks like a length-prefixed ELF written by a different code path, not
   a wrong key. Trace `Loader_Thread.EMMCMiFlash` for a second writer.
3. Check the 2 payloads whose plaintext begins `10 10 10 10`. Tested: a
   genuine all-`0x10` ciphertext block decrypts to random bytes, so this is
   *not* a PKCS#7 padding artefact. It is either a different key or a
   plaintext that really starts with 0x10 bytes.

**Why it matters**: it is the difference between "543/606 loaders usable" and
"606/606".

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
