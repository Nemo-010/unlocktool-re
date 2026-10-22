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

## Layout C — `auth.auth` only (23 folders)

23 folders contain exactly one file, `auth.auth`, of 2 250–2 272 bytes. These
are **ASCII-mangled copies** of the `MMM` container described below: every one
of them is 7-bit clean (`max(byte) <= 0x7F`), with `0x3F` (`'?'`) sitting in
exactly the positions where a high byte belonged — 509 of 2 269 bytes in the
A15 file. Some transfer step ran them through a text channel that replaced
every non-ASCII byte with `'?'`, so the block length fields are destroyed and
the containers can no longer be parsed. Nothing is recoverable from them
beyond their presence.

## Layout C2 — the `MMM` auth container (2 small + 40 large files)

`_auth_sv5.auth` is used for **two unrelated things**, which is worth knowing
before treating the name as meaningful:

| Size | Count | What it is |
|---|---|---|
| 2 256 / 2 272 | 2 | an `MMM` container, parseable |
| 1 049 756 – 1 049 762 | 40 | a `MotoKingProS`/`R` blob (see below) |

The `MMM` container (found at `data/DA/Extras/new_auth_sv5.auth` and
`old_auth_sv5.auth`) parses cleanly with a **u16** length that *includes* the
8-byte header:

```
off 0x00  "MMM\x01"  u16 total_len  body[total_len-8]
```

giving exactly three blocks and a 256-byte trailer:

| Block | Length | Tag | Meaning |
|---|---|---|---|
| 0 | 56 | `FILE_INFO` | header |
| 1 | 1944 | `MTK\0…` | the DA auth payload |
| 2 | 16 | zeros | separator |
| trailer | 256 | — | a 256-byte signature |

The 256-byte trailer is the same size as the `size_in_bytes="256"` in the
`sig` request `EMMCBootFlash` sends (`docs/protocol-report.md` §1.2b), which is
a strong hint that this container is a pre-captured auth exchange. The two
files differ only in the 1944-byte block and the trailer — i.e. per-model
signing material over a common template.

An earlier attempt read the length as u32 and concluded the files were
unparseable; that was wrong. The length is u16 and counts the header.

## Layout C3 — `MotoKingProS` / `MotoKingProR`

The 40 large `_auth_sv5.auth` files are a fifth vendor's container:

```
off 0x00  12 bytes  magic      "MotoKingProS" (34 files) or "MotoKingProR" (6)
off 0x0c  u32be     version    4
off 0x10  u32be     field      0x224D1840  (constant)
off 0x14  u32be     field      0x40C04400 | 0x40C04300
off 0x18  u32be     field      0x0000F017 | 0x0000F115 | 0x0000F118
off 0x1c  base64    filename   NUL-terminated, truncated mid-group
         6 bytes    marker     0C 00 3F 67 3D 00
                    payload    opaque, ~1 049 686 bytes
tail      4 bytes   0x00000000
```

The header integers are **big-endian**; reading them little-endian gives a
version of 67 108 864 and nonsense fields. The three `fields` triples are not
constant — they vary with the magic revision and the payload size class:

| Magic | fields | Count |
|---|---|---|
| `S` | `224D1840 40C04400 0000F017` | 34 |
| `R` | `224D1840 40C04300 0000F115` | 4 |
| `R` | `224D1840 40C04300 0000F118` | 2 |

The `base64` field decodes to the *original filename*, which is how these
blobs stayed attributable after the merge renamed them:

```
U00tQTE1NUYuQjUubXQ2Nzg5X2F1dGhfc3Y1Lm   ->  SM-A155F.B5.mt6789_auth_sv5.
```

The encode is truncated at 40 characters, so the extension is lost; that is
why the decoded name always ends in a dot. Parsing it recovers the model and
the **MTK chipset** (`mt6789`, `mt6835`, `mt6833`, `mt6989`) — the only place
in the tree where the chipset is stated per model for these folders.

Implemented in `src/unlocktool_re/motoking.py`.

### A merge defect this exposed

Two `_DA_BR` folders hold the *other* model's blob:

```
SM-A156B.B5.mt6835_DA_BR/  contains  SM-A156E.B5.mt6789_auth_sv5.auth
SM-A156E.B5.mt6789_DA_BR/  contains  SM-A156B.B5.mt6835_auth_sv5.auth
```

i.e. the two directory trees were swapped during the merge. The other 18
`_DA_BR` folders are self-consistent. Since the payload is base64-tagged with
its own name, the swap is provable rather than inferred.

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
