# The data tree is not one tool's tree

The single most important structural finding of this investigation: `data/` is
a **merge of at least four different tools' payload layouts**, and only one of
them is the layout the vendor README documents.

`docs/offline-data-layout.md` in the vendor's own words describes layout E
below. The other three are present in the shipped tree, are referenced by the
brand indexes, and are *not* described anywhere in the shipped documentation.

## The layouts, counted

Measured over `data/SAMSUNG/`, which is where the merge is most visible
(202 directories, 202 distinct model folders):

| # | Layout | Marker files | Folders |
|---|---|---|---|
| A | **PrimeToolX** | `device_info.txt` + `model.json` + `operations.xml` (+ `qualcomm.pyd`, `loader.elf`) | 44 |
| B | **MTK DA pair** | `<Model>_DA_BR.bin` + `<Model>_auth_sv5.auth` | 23 (+23 nested duplicates) |
| C | **MTK auth only** | `auth.auth` (+ `download.bin`) | 23 |
| D | **Unisoc** | `fdl1.bin` + `fdl2.bin` | 2 |
| E | **ColokTool** (the documented one) | `programs.bin` (+ `Reset FRP`, `[EDL] RESET FRP`, `operations.xml`) | 108 |
| F | nested copy of B | `READ_ME .rtf` + the DA pair | 23 |
| G | partial / one file | `model.json`, `RESET FRP.xml`, … | 2 |

Only layout E is what `docs/architecture.md` describes and what the tool's
own `Loader_Thread` / `OperationSupported` code reads. A, B, C and D are
read by *other* code paths (or by nothing in this binary).

## Layout A — PrimeToolX

Every one of the 44 folders contains a `device_info.txt` with the same
template:

```
PrimeToolX v26.1.8 Device
=========================
Name: Samsung Galaxy A05s [SM-A057F]
Model: SM-A057F
Chipset: Qualcomm
Mode: EDL Mode
Method: ufs
Loader: system-brick-qfs_lfir_par0i5m7ef_tuocol.prime
From: PrimeToolX v26.1.8 Source Code
```

and a `model.json`:

```json
{
  "parameters": { "edl": "loader.elf", "broom": "edl" },
  "model": "SM-A057F", "deviceName": "SM-A057F",
  "chipset": "", "brand": "SAMSUNG", "platform": "", "mode": "EDL",
  "connection": "EDL"
}
```

`parameters` is a name → filename map, i.e. a *different* dispatch mechanism
from ColokTool's `method M1..M8` slots. `operations.xml` uses
`<operation name= type= file= enabled=>` with a `file` attribute, whereas
ColokTool's `operations.xml` has only `name` and infers the file from the
name.

`qualcomm.pyd` (69 632 bytes) is a CPython extension module — the same size in
all 44 folders. It is a compiled Python module, not data.

The `Loader:` line contains a filename that does not exist in the folder
(`system-brick-qfs_lfir_par0i5m7ef_tuocol.prime`), and `chipset`/`platform`
are empty strings, so `device_info.txt` is partly placeholder text.

## Layout B/F — MTK DA pairs

```
SM-A155F.B5.mt6789_DA_BR.bin         1 533 373 bytes   (the Download Agent)
SM-A155F.B5.mt6789_auth_sv5.auth    1 049 756 bytes   (the DA auth blob)
READ_ME .rtf                           259 bytes       (an ad, not a readme)
```

The `READ_ME .rtf` is a two-line advertisement for a Telegram channel; it is
the only documentation shipped with 23 of the folders. The naming encodes the
chipset (`mt6789`, `mt6835`, `mt6833`, `mt6989`), which is the first place in
the whole tree where the MTK chipset is stated per model.

The 23 `X.<ver>.mt<chip>_DA_BR/` folders are byte-identical *nested copies* of
the 23 `X [<ver>]` folders — the same two files plus the same README.

## Layout C — `auth.auth` only

23 folders contain exactly one file, `auth.auth` (2 263–2 272 bytes), and
sometimes a `download.bin` (720–1 315 KiB). The `auth.auth` header is:

```
MMM\x01 38 00 00 00 "FILE_INFO\0\0\0\1\0\0\0\5\0\5\2 \b \0"
```

with a second `MMM\x01` block at offset 56 that starts `MTK\0\0\0...`. The
whole file is only 2 269 bytes and has 128 distinct byte values, so it is
mostly text-ish, not a key blob. The `MTK` marker at offset 64 and the
`FILE_INFO` marker at offset 8 make this an MTK auth-file container.

Without the DA that consumes it we cannot say more; see
`docs/remaining-work.md`.

## Layout D — Unisoc

Two folders (`Samsung Galaxy A03 Core U2 [SM-A035F]`, `Samsung Galaxy A03 U2
[SM-A035F]`) contain `fdl1.bin` (51–59 KiB) and `fdl2.bin` (1.4–2.0 MiB) and
nothing else. That is the Unisoc/SPD download-agent pair, matching
`ColokTool.SPDLoader.SPDBootPLUS` which looks for `/fdl1.bin`.

## Why this matters for the compatibility matrix

`scripts/build_matrix.py` counts a model as having a payload only when
`data/{BRAND}/{Devices + " " + Models}/programs.bin` exists — layout E. That is
correct for *ColokTool's* behaviour, but it means:

- the 44 PrimeToolX folders, the 23 DA-pair folders and the 23 `auth.auth`
  folders are counted as "folder present, loader absent", which reads like a
  defect and is not one: those models use a different tool's data.
- the SAMSUNG row of `docs/oem-capability-matrix.md` therefore understates
  what is *shipped* while correctly stating what *ColokTool* can use.

The distinction is recorded here rather than folded into the matrix, because
the matrix is about what this binary does, and this document is about what the
archive contains.

## How the merge happened — measured from `_MERGE-BACKUP`

`data/_MERGE-BACKUP/` holds 9 timestamped snapshots (27 XML files) taken on
2026-09-29. Counting `<program>` and `<method>` rows in each snapshot and in
the shipped index makes the merge directly visible:

| Snapshot | asus | huawei | lenovo | oppo | samsung | xiaomi |
|---|---|---|---|---|---|---|
| 150417 | . | 12p/4m | . | 112p/112m | 11p/11m | . |
| 150720 | . | 12p/4m | . | 112p/112m | 11p/11m | . |
| 151040 | . | 12p/4m | . | 112p/112m | 11p/11m | . |
| 151559 | . | . | . | 112p/112m | 11p/11m | . |
| 152004 | . | 12p/4m | . | 112p/112m | 11p/11m | . |
| 152602 | . | 12p/4m | . | 112p/112m | 11p/11m | . |
| 155313 | . | . | . | 121p/121m | . | 100p/102m |
| 155622 | 27p/27m | . | 30p/15m | 121p/121m | . | 100p/102m |
| 155916 | 27p/27m | . | 30p/15m | 121p/121m | . | 100p/102m |
| **shipped** | **27p/28m** | **15p/7m** | **30p/15m** | **125p/127m** | **201p/62m** | **338p/97m** |

SAMSUNG went from 11 `<program>` rows to 201 in the final index, and XIAOMI
appears only in the last three snapshots. OPPO went 112 → 121 → 125. So the
merge ran in several passes over one afternoon, adding brands incrementally.

The PrimeToolX `device_info.txt` files say `v26.1.8`, i.e. a different
vendor's release numbering. The merge tool rewrote the brand XML index but did
not normalise the payload layouts, which is why four coexist.

`data/SAMSUNG/SM-X826B.B2.mt6989_DA_BR/samsung.xml` is a *third* brand index
inside a DA-pair folder, which is direct evidence of the merge copying whole
directory trees.
