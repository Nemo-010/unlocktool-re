# Architecture report

## 1. What was supplied

```
UNLOCKTOOL OFFLINE (1).7z                      1 694 307 696 bytes
└── UNLOCKTOOL OFFLINE/
    ├── UNLOCKTOOL OFFLINE.exe                 2 327 092 946 bytes   <- Inno Setup 6.7.0 installer
    └── file_00000000cb2c8211af083e5a0bdbd69b.png                  <- GSM VARDAN branding
```

The `.exe` is **not** the tool. It is an Inno Setup 6.7.0 installer whose
payload is the tool plus a 4 GB data tree. Reaching the tool requires parsing
the installer, which `src/unlocktool_re/inno.py` and `setup0.py` do.

## 2. Installer layer

| Field | Value | Where |
|---|---|---|
| Setup data version | `Inno Setup Setup Data (6.7.0)` | `header_offset + 0` |
| `TSetupLdrOffsetTable.version` | 2 | RCDATA resource 11111 |
| `Offset0` (setup-0) | `0x8A9C1D1E` | offset table |
| `Offset1` (setup-1) | `0x00105200` | offset table |
| Total size | `0x8AB49ED2` = 2 327 092 946 | offset table |
| Setup encryption | `EncryptionUse = 0` (none) | `Offset0 + 68` |
| Blocks | 2, LZMA1 raw, 4 KiB-CRC-chunked | — |
| Files in payload | 7 387 entries, 7 386 with data | `TSetupFileEntry[]` |

Two post-processing steps matter and are easy to get wrong:

1. **Block framing.** Each `TCompressedBlockWriter` block is
   `CRC32(9-byte header) | Int64 stored_size | Bool compressed`, followed by
   `stored_size` bytes split into 4096-byte pieces, each prefixed with its own
   CRC32. Decompression is raw LZMA1 with properties from the first 5 bytes.
2. **`TransformCallInstructions`.** Inno Setup rewrites the low 3 bytes of
   every `E8`/`E9` rel32 displacement inside each 64 KiB buffer. Setup inverts
   it after decompression. Skipping this leaves a corrupt PE: 68 of 4101
   method RVAs land outside every section.

## 3. Application layer

`ColokTool.exe` is a single **PE32 / .NET Framework 4.0** assembly
(`v4.0.30319`, IL-only, no mixed-mode code).

| Metadata | Count |
|---|---|
| `TypeDef` | 339 |
| `MethodDef` | 4 101 (3 996 with IL bodies) |
| `Field` | 4 052 |
| `MemberRef` | 1 568 |
| `AssemblyRef` | 21 |
| `ModuleRef` | 6 |
| `ImplMap` (P/Invoke) | 89 |
| `ManifestResource` | 60 |
| Managed resources (`.resources`) | 16 |

Assembly references: `mscorlib`, `System`, `Microsoft.VisualBasic`,
`System.Windows.Forms`, `System.Drawing`, `System.Management`, `System.Xml`,
`System.Xml.Linq`, `System.Core`, `System.Numerics`,
`System.IO.Compression.FileSystem`, plus four third-party libraries
(`DevExpress.*.v24.1`, `LibUsbDotNet`, `Ionic.Zip`, `Renci.SshNet`,
`Newtonsoft.Json`, `HuaweiLib`). All of them are embedded as Costura
resources, so the installed app is a single file.

### Native dependencies (P/Invoke)

| DLL | Calls | Role |
|---|---|---|
| `QMSL_MSVC10R.dll` | 22 | Qualcomm QLIB: DIAG, NV read/write, EFS2, QCN backup |
| `data\Unisoc\PhoneCommand.dll` | 19 | Unisoc/SPD command channel |
| `data\Unisoc\spdio-1.0.dll` | 16 | Unisoc USB I/O |
| `\data\meta\SPMETA_DLL.dll` | 11 | MTK META mode |
| `kernel32.dll` | 21 | `CreateFile`/`DeviceIoControl`/`WriteFile` on the COM port |

The four vendor DLLs are **not** inside the installer: `data/Unisoc/*` is not
in the payload list and `data/meta/` contains only XML/ini. Any workflow that
crosses one of those boundaries cannot be reproduced from the artefacts alone.

### Component map (by IL volume)

| Namespace / type | IL ops | Role |
|---|---|---|
| `ColokTool.Main` | 80 855 | The whole WinForms UI: 1 491 methods, 691 of them click handlers. Holds `Buttonlist`, `LoadXmlFolder`, the per-OEM worker entry points. |
| `ColokTool.thread_handling` | 13 596 | MTK operation implementations: `FormatFRP`, `EraseEFS`, `WriteEFS`, `FRPSam`, `Unlockbootloader`, `Relockbootloader`, `Micloud`, `Formatpartition`, … |
| `ColokTool.Loader_Thread` | 12 127 | Qualcomm firehose driver: `EMMCBootPLUS`, `EMMCMiFlash`, `EMMCBootFlash`, `cmd_getstorageinfo`, and the payload `Encryption`. |
| `ColokTool.RDA.pltools` | 7 544 | MTK BROM/preloader bring-up: `BroMBoot`, `AuthBypass`, `PreloaderBoot`, `run_dump_preloader`. |
| `chipconfig` | 5 921 | MTK chip table (generated). |
| `ColokTool.LoaderIP` | 4 106 | Apple/iOS path (`irecovery`, checkm8-style boot, activation record). |
| `ColokTool.xflash_lib` | 4 065 | MTK xflash command layer: `cmdformat`, `cmdread`, `writeByPartitionName`, `ForMatSector`. |
| `ColokTool.gpt` | 3 915 | GPT parsing/rebuilding (`readgpt`, `BuildPgpt`, `parsepartition`). |
| `ColokTool.OFPExtractor` | 3 894 | OPPO `.ofp` firmware container. |
| `ColokTool.LoginPage` | 3 544 | Local account login UI. |
| `ColokTool.Passcode` | 2 453 | iOS passcode/hello-bypass path (SSH via `Renci.SshNet`). |
| `ColokTool.Tread_SAMSUNG` | 2 322 | Samsung Odin protocol. |
| `ColokTool.SPDLoader` | 2 215 | Unisoc `fdl1`/`fdl2` download. |
| `ColokTool.RDAmod.Qmslphone.*` | ~8 200 | Qualcomm DIAG/IMEI (`QLIB_*`). |
| `ColokTool.UniFlash.*` | ~13 600 | PAC extraction and Unisoc diag channel. |

The remaining namespaces (`ColokTool.SAMSUNG`, `ColokTool.RDA.*`,
`ColokTool.RDAmod.Adbcommond.*`, `ColokTool.DXApplication`) are smaller and
support the above.

## 4. Execution flow (user input → device operation)

```
LoginPage.Btn_Login_Click
   └── UserReg.Check00(user, pass, server)      reads data/accounts/accounts.json
         └── OfflineData.LoadAccounts / FindAccount
   └── status == "Active" and not expired        -> Main window

Main (brand ComboBox change)
   └── LoadXmlFolder(brand)
         └── XmlReader over data/{BRAND}/{brand}.xml
               <program Devices=.../>   -> payload folders that exist
               <name Devices= Models= Platform= EDL=|Broom= .../>
               <method Devices= M1..M8/>
   └── Buttonlist(brand, model, panel, List<ButtonInfoType>)
         match: info.Devices.Contains(brand & " " & model)
         -> one SimpleButton per non-empty M1..M8, caption == operation name

User clicks an operation button
   └── Loader_Thread.OperationSupported(folder)
         reads {folder}/operations.xml, matches <operation name="<caption>">
   └── dispatch on the operation's prefix:
         "[EDL] …"    -> Qualcomm path   (Loader_Thread / QCThread)
         "[BROM] …"   -> MTK BROM path   (Port / xflash_lib)
         "[META] …"   -> MTK META path   (RDA.META / SPMETA_DLL)
         "[SIDELOAD]…"-> ADB sideload    (Adbcommond)
         "[OFP] …"    -> OFP extractor
```

`Qctool.operation` is the raw button caption; it is used verbatim to build
`{BRAND}\{Devices Models}\{operation}`, which is why the folder name, the
`method` `Devices` value and the script filename must all agree.

## 5. Remote vs local

For the Android workflows in this build, **everything is local**: the brand
index, the payload folder, the firehose loader, the operation script and the
account database are all files under `data/`. No HTTP request is made by the
MTK or Qualcomm paths.

Four remote dependencies do exist in the code and are all on the **iOS** side:

| Site | Endpoint | Purpose |
|---|---|---|
| `LoaderIP.GetActivationRecordFromServer` | `https://pentaboy.my.id/ios/iOS16Act.php` | activation record lookup |
| `LoaderIP.downloadhello` | three URLs under the same host | ramdisk/iBSS/iBEC download |
| `Passcode.uploadBackup` | `WebClient.UploadFile` to `Passcode.Link_Web` | backup upload |
| `Loader_Thread.server` / `server2` | literal `https:///` | placeholder; Qualcomm `DownloadBytes` base |

`Loader_Thread.DownloadBytes` is the one shared helper, and in this build it
is local-only:

```csharp
static byte[] DownloadBytes(string path) {
    try { return OfflineData.ReadAllBytes(path); }
    catch { return new byte[0]; }
}
```

So `server` / `server2` are dead fields, and a missing payload comes back as an
empty array rather than a network error. That is what makes the Android
workflows "offline": every input is a file under `data/`.

## 6. Where the artefacts stop

Reproducible from artefacts:

- installer parsing, payload extraction, `TransformCallInstructions`
- the data tree: brand indexes, folder join, operation scripts
- `programs.bin` decryption and ELF validation
- the local account/licence check
- MTK command framing (client side)
- the operation-name → dispatch classification

Not reproducible from artefacts:

- device-side replies (DA handshake magic, firehose `<?xml>` responses)
- anything behind `QMSL_MSVC10R.dll`, `SPMETA_DLL.dll`, `spdio-1.0.dll`,
  `PhoneCommand.dll`
- the iOS activation flow (needs Apple infrastructure)
- 63 `programs.bin` payloads that do not decrypt with either known password
