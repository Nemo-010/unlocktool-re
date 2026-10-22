# Protocol report

Two independent protocol families are present. They do **not** share a
mechanism, a transport or an authorization model, and the tool keeps them in
separate namespaces.

| Family | Entry namespace | Transport | Authorization |
|---|---|---|---|
| Qualcomm EDL / firehose | `ColokTool.QCThread`, `ColokTool.Loader_Thread`, `ColokTool.RDA.*` | USB, vendor class, raw bulk through `kernel32` `DeviceIoControl` | signed firehose loader per chipset |
| MediaTek BROM / preloader | `ColokTool.Port`, `ColokTool.xflash_lib`, `ColokTool.RDA.pltools` | USB CDC/ACM serial | DA handshake; preloader auth for newer SoCs |
| Unisoc / SPD | `ColokTool.UniFlash.*`, `ColokTool.SPDLoader` | USB + `spdio-1.0.dll` | `fdl1`/`fdl2` |
| Samsung Odin | `ColokTool.Tread_SAMSUNG`, `ColokTool.SAMSUNG.*` | USB bulk | Odin handshake |
| Qualcomm DIAG | `ColokTool.RDAmod.Qmslphone` | serial + `QMSL_MSVC10R.dll` | QLIB session |
| Apple DFU/recovery | `ColokTool.LoaderIP`, `ColokTool.Passcode` | USB (libusb) + `irecovery` | checkm8-style + remote activation |
| ADB | `ColokTool.RDAmod.Adbcommond.Client` | TCP 5037 | none (device must be authorized) |

Only the first two are documented here in detail; the others were identified
but not reconstructed, because their device side is behind a native DLL we do
not have.

---

## 1. Qualcomm EDL / firehose

### 1.0 What is local and what is remote

`Loader_Thread.DownloadBytes(string path)` is **local only** in this build:

```csharp
static byte[] DownloadBytes(string path) {
    try { return OfflineData.ReadAllBytes(path); }
    catch { return new byte[0]; }
}
```

`OfflineData.ReadAllBytes` resolves against `Application.StartupPath\data`
with a path-traversal guard and returns an empty array when the file is
missing. So `Loader_Thread.server` / `server2` (both the literal `https:///`)
are vestigial: nothing in the EDL path performs an HTTP fetch. A missing
payload surfaces as a zero-length byte array, which is why the tool then
reports "Loader Data File corrupt" or "Invalid Loader Data" rather than a
network error.

### 1.1 What the tool sends

Firehose is an XML request/response protocol over raw USB bulk endpoints.
`Loader_Thread` builds requests as strings and wraps them:

```csharp
// cmd_getstorageinfo, repeated for every command
"<firehose-response>" ... "\n</firehose-response>"
```

The observed command set, from method names and literals in
`ColokTool.Loader_Thread`:

| Command | Where |
|---|---|
| `configure` | `EMMCBootPLUS`, `EMMCBootFlash` |
| `read` / `program` | `EMMCMiFlash`, `WriteEmmc` |
| `erase` | `thread_handling::Formatpartition` |
| `patch` | `thread_handling::FormatFRP` |
| `getstorageinfo` | `cmd_getstorageinfo` |
| `nop` | keep-alive between long operations |

### 1.1b The EDL path honours `SECTOR_SIZE_IN_BYTES`; the MTK path does not

`EMMCBootFlash` parses the operation script itself before handing it to
`ProcessQcomFlash`. The relevant IL, in order:

```
"program" / "erase" / "patch"          // element name dispatch, ToLower'd
"SECTOR_SIZE_IN_BYTES"  -> field:SectorSize
  SectorSize == "512"   -> TypeMemory = "emmc"
  SectorSize == "4096"  -> TypeMemory = "ufs"
```

So the firehose path reads the declared sector size and uses it to choose
eMMC vs UFS addressing, and the script's `SECTOR_SIZE_IN_BYTES` reaches
`WriteFlash` as its first argument. That is correct behaviour.

The MTK path (`thread_handling.FormatFRP`, `xflash_lib.ReadSector`) does
**not** do this: it multiplies by a literal `512.0`. On a 4096-byte-sector
script that address is 8x short. The two paths disagree about the same field,
which is the concrete defect recorded as R21.

`EMMCBootFlash` also handles all three element kinds — `program`, `erase` and
`patch` — so the Qualcomm path consumes the whole rawprogram vocabulary, not
just `<program>`.

### 1.2 What the tool expects back

The response is matched on `ACK`/`NAK` text and on a `<response value="..."/>`
substring. Because the tool only ever *compares strings*, the reproduction
does not need a device: the request strings and the comparison logic are the
whole of the client side.

### 1.2b The firehose command exchange, as the IL shows it

After `configure`, `EMMCBootFlash` loops:

```
SendXml(pkt_fhConfig(TypeMemory), 4)
CekResponseConfig(...)              -> Contains("ack")
    Contains("xml")                 -> "FAILED TO RESPON CPU!"
    Contains("Only nop and sig tag")-> signature/auth path:
        SendXml("<data><sig TargetName=\"sig\" size_in_bytes=\"256\" verbose=\"1\"/></data>")
        IsAck(...)
        DiskWrite(Resources.skip)
        DiskRead(8) -> Contains("\"ACK\"")
        else Contains("\"NAK\"") -> "Make sure you have select correct
                                     server loader or current SoC is not support!"
        else Contains("Signature Verification Failed")
```

Three things this pins down that were previously only inferred:

1. the exact `sig` request the tool sends for a signed loader,
2. that a loader failure surfaces as `NAK` or `Signature Verification Failed`
   and is reported as a *wrong-loader* error, not a transport error,
3. that `configure` is sent with a packet built by `Firehose_pkts.pkt_fhConfig`
   from `TypeMemory` (`emmc` / `ufs`), which is itself derived from the
   script's `SECTOR_SIZE_IN_BYTES`.

### 1.3 The loader

`programs.bin` is the firehose loader (a Qualcomm-signed ELF). It is stored
AES-256-CBC encrypted in the data tree and decrypted in memory before being
sent. See `docs/protocol-report.md#3-payload-encryption` for the derivation.

The loader is per-chipset, not per-device: 606 payloads exist for 852
advertised devices, and the vendor README states several phones share one
`programs.bin`.

### 1.4 State transitions

```
Sahara (device is in 0x05C6:0x9008)
   └── send loader  -> device reports READY
firehose
   └── configure   -> ACK
   └── (operation-specific commands) -> ACK / NAK
   └── reset       -> device reboots
```

The tool distinguishes "device is not in Firehose Mode" (string literal in
`QCThread.hangHack`) from "Firehose verification failed" (loader rejected),
i.e. it has separate handling for the two transitions.

---

## 2. MediaTek BROM / xflash

This is the family the reproduction implements, because its framing is
recoverable byte-for-byte from the IL.

### 2.1 Frame

`xflash_lib.xsend4(worker, e, payload)`:

```
EF EE EE FE  01 00 00 00  04 00 00 00   || payload
```

`xsend8`, `xsend10`, `xsend24` are the same helper with a different length
dword (`08`, `10`, `18`), used for larger payloads.

### 2.2 Command payload (`cmdformat` / `cmdread`)

From `xflash_lib.cmdformat(string partition, string start, string length)`:

```csharp
string cmd      = "01 00 00 00";
string selector = "";
if (partition.ToLower() == "boot1")    selector = "01 00 00 00";
if (partition == "userarea")           selector = "08 00 00 00";
string s = penggenapan8(applyshiftKiri2(start));
string l = penggenapan8(applyshiftKiri2(length));
string z = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";  // twice
return HexStringToBytes(cmd + selector + s + l + z + z);
```

`applyshiftKiri2` is "interpret as a number, multiply by 4, print as hex";
`penggenapan8` zero-pads to 8 hex characters, i.e. a little-endian uint32.
The callers (`thread_handling::FormatFRP`, `xflash_lib::ReadSector`) pass
`start * 512` and `length * 512`, so the ×4 in `applyshiftKiri2` is a further
×4 on top of the sector→byte conversion. That double conversion is in the
shipped code and is reproduced verbatim in `mtk.py` — it is almost certainly
a bug, but it is *their* wire format.

Resulting 48-byte payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | command (`1` for both format and read in this build) |
| 4 | 4 | partition selector: `0` default, `1` boot1, `8` userarea |
| 8 | 4 | start, byte address (already ×4 from the caller's value) |
| 12 | 4 | length, bytes (same caveat) |
| 16 | 32 | reserved, zero |

### 2.3 Port bring-up

`Port.CariPortMtk` / `CariMetaBromPort` scan serial ports for a device that
answers the BROM handshake; `HandshakeMtk` and `HandshakeMtkBrom` then read
back a fixed number of bytes and compare the first 8 hex characters against
`Port.magichex`. `Port.send00000` sends a command and then reads until it has
`2 * expected` hex characters or 200 iterations elapse, which is the tool's
entire timeout policy.

`magichex` is assigned at runtime from the DA handshake, so the reply magic is
**not** a compile-time constant. This is the one place where the reproduction
must use a mock rather than the real value (see `mockdevice.py`).

### 2.4 What the operation scripts mean

Each `method` slot names a file that is a Qualcomm *rawprogram* XML. It is
consumed by the EDL path (`Loader_Thread.EMMCBootFlash` reads it into
`Loader_Thread.StringXml`, then `ProcessQcomFlash` walks it with an
`XmlTextReader`); the MTK path uses it only as a partition map, because MTK
has no firehose.

Confirmed by the IL of `EMMCBootFlash`:

```
down2 = Brand + "/" + Modelselect + "/" + Qctool.operation
if not File.Exists(root + "\\" + Brand + "\\" + Modelselect + "\\" + operation):
    if OperationSupported(root + "\\" + Brand + "\\" + Modelselect).Length > 0
        log "Operation payload missing for this model"
        log "expected  data\\Brand\\Model\\operation"
    else
        log "Operation not supported by this model"
    return false
StringXml = UTF8.GetString(DownloadBytes(down2))     // the rawprogram XML
```

`OperationSupported` reads `{folder}\operations.xml` and returns the
`<operation name=...>` that matches `Qctool.operation`, so the two files have
to agree: the `method` slot, the `operations.xml` entry and the script
filename are the same string.

Four element kinds occur:

| Element | Meaning | Count (all 989 scripts) |
|---|---|---|
| `<program filename="x" label="y">` | write local file `x` to partition `y` | 241 scripts have at least one write |
| `<program filename="" label="y">` | erase partition `y` | 334 scripts are erase-only |
| `<erase start_sector= num_partition_sectors=>` | erase a raw range | 196 |
| `<patch value= byte_offset= start_sector=>` | write `value` at an offset | 46 214 patch rows across 392 scripts |

`<patches>` is only a container. Of the 968 parseable scripts: 241 contain at
least one write, 392 are patch-only, 334 are erase-only, 1 is empty after
parsing.

The element semantics match the public Qualcomm firehose command forms, which
is an independent cross-check rather than a guess: `edlclient`'s
`cmd_patch`/`cmd_program`/`cmd_erase`/`cmd_read` emit the same attribute sets
(`SECTOR_SIZE_IN_BYTES`, `physical_partition_number`, `start_sector`,
`num_partition_sectors`, `filename`, `label`, `byte_offset`, `size_in_bytes`,
`value`, `what`).

---

## 3. Payload encryption

### 3.1 The scheme

`Loader_Thread.Encryption(byte[] data, byte[] password, bool encrypt)`:

```csharp
password = SHA256.Create().ComputeHash(password);          // <-- digest
var prf  = new Rfc2898DeriveBytes(password, saltBytes, 1000);
aes.KeySize   = 256;
aes.BlockSize = 128;
aes.Mode      = CipherMode.CBC;                             // value 1
aes.Key       = prf.GetBytes(32);
aes.IV        = prf.GetBytes(16);                           // same instance!
```

The two literals come from `FieldRVA`-initialised arrays in `.cctor`:

```
saltBytes = 00 00 01 02 03 04 05 06 F1 F0 88 10 22 95     (14 bytes)
key       = "RDAXTEAM2024"                                (12 bytes)
```

Because `Rfc2898DeriveBytes` is a single stream, `GetBytes(32)` then
`GetBytes(16)` yields bytes 0..31 and 32..47 of one PBKDF2 output. Using two
separate instances gives a wrong IV — the vendor README says this explicitly
and it is correct.

### 3.2 Verified result

```
PBKDF2-HMAC-SHA1(SHA256("RDAXTEAM2024"), salt, 1000, 48)
  key = 9e90e8509a09b7ed0a724760eca89fab6992bbadd0cabe25cdd1491fa6fab836
  iv  = fe16a2cc7ba376bb4fe18855b62cd4ce
```

Decrypting the ASUS ROG Phone 2 payload with these yields
`7F 45 4C 46 02 01 01 00` — an ELF64 header. Across all 606 payloads, 543
decrypt to ELF.

### 3.3 Where the vendor README is wrong

`data/OFFLINE-DATA-README.md` says:

```
key   = SHA256(ASCII(password))
salt  = ...
       -> Rfc2898DeriveBytes(key, salt, 1000).GetBytes(32)   = AES key
```

Read literally, that makes `key` the PBKDF2 *password*. It is not: the IL
SHA-256s the password first and passes the **digest** to
`Rfc2898DeriveBytes`. Using the ASCII string directly produces a different key
and no payload decrypts. This is a documentation defect only; the code is
self-consistent.

### 3.4 Where the vendor README is right

- same PBKDF2 instance for key and IV
- 1000 iterations
- AES-256-CBC with PKCS#7
- `programs.bin` encrypted, operation scripts and aux payloads not
- re-encryption preserves file size (deterministic padding)

---

## 4. Local account / licence protocol

No network. `UserReg.Check00`:

```
GetserverTime("datetime.php")   -> stub: records DateTime.Now, returns true
accounts = OfflineData.LoadAccounts()          // data/accounts/accounts.json
acct     = OfflineData.FindAccount(accounts, email)   // UserName or Email, case-insensitive
if acct == null            -> "filed: this email is not registered", false
if acct.Password != pass   -> "filed: wrong password", false
if IsNullOrWhiteSpace(acct.Hwid):
        acct.Hwid = Get_HWID().Substring(1, 12); SaveAccounts()
... copy fields into the Login singleton ...
reportlogin = "sucsess"; true
```

`Get_HWID()` is `SHA512(processorId + machineId)` rendered as hex, and the
`.Substring(1, 12)` is why the shipped `Hwid` value is 12 characters.

`LoginPage.Btn_Login_Click` then requires `Status == "Active"` and
`Expired >= now`, and writes `config.ini` `[Setting Config] user/pass` when
the "save" checkbox is ticked.

This is a **local** gate: replacing `accounts.json` is sufficient. That is a
property of this offline build, not of the online one.

---

## 5. Limitations

- The device-side reply formats of both families are **not** recovered. For
  MTK the magic is a runtime value; for Qualcomm the tool only compares
  `ACK`/`NAK` strings and we have no captured traffic.
- No traffic was captured from real hardware, so every statement above about
  a device reply is either a mock or a description of what the client compares
  against, never an observation.
- The four vendor DLLs (`QMSL_MSVC10R`, `SPMETA_DLL`, `spdio-1.0`,
  `PhoneCommand`) are absent, so DIAG, META and Unisoc paths stop at the
  P/Invoke boundary.
