# OEM capability matrix

Per-manufacturer summary. The per-device machine-readable form is
`artifacts/matrix.json`, and the generated per-device tables are in
`docs/compatibility-matrix.md`. Everything below is counted, not claimed.

## How to read this

| Column | Definition |
|---|---|
| Models | `<name>` rows in the brand index |
| Folder | model folders that exist on disk |
| Loader | `programs.bin` files present |
| Loader ok | those that decrypt to ELF with the recovered key |
| Slots | `method` M1..M10 entries advertised in the index |
| Script | slots whose file exists |
| Parses | scripts that are well-formed XML |
| Usable | loader ok **and** at least one parseable script |

A device in the "Usable" column has every input the tool needs for at least
one operation. It is still not *validated* — that would need a device.

## Summary

| OEM | Platform | Models | Folder | Loader | Loader ok | Slots | Script | Parses | Usable | Authorization |
|---|---|---|---|---|---|---|---|---|---|---|
| ASUS | Qualcomm EDL + MTK BROM | 33 | 33 | 28 | 25 | 82 | 82 | 77 | 25 | firehose loader |
| HUAWEI | Qualcomm EDL | 28 | 27 | 7 | 7 | 14 | 11 | 11 | 7 | firehose loader |
| INFINIX | MTK | 31 | 30 | 6 | 6 | 18 | 18 | 18 | 6 | firehose loader |
| ITEL | — | 23 | 21 | 0 | 0 | 44 | 0 | 0 | 0 | none |
| LENOVO | Qualcomm EDL | 50 | 15 | 15 | 15 | 26 | 21 | 21 | 12 | firehose loader |
| LG | — | 52 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | none |
| MEIZU | Qualcomm EDL | 37 | 17 | 17 | 17 | 34 | 34 | 34 | 17 | firehose loader |
| NOKIA | — | 9 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | none |
| OPPO | Qualcomm EDL | 229 | 190 | 126 | 116 | 386 | 310 | 301 | 109 | firehose loader |
| REALME | Qualcomm EDL | 99 | 28 | 20 | 12 | 51 | 49 | 49 | 12 | firehose loader |
| SAMSUNG | Samsung Odin | 208 | 84 | 62 | 62 | 70 | 70 | 70 | 61 | Odin handshake |
| TECNO | — | 129 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | none |
| VIVO | Qualcomm EDL | 159 | 153 | 108 | 100 | 390 | 387 | 380 | 100 | firehose loader |
| XIAOMI | Qualcomm EDL | 348 | 148 | 139 | 135 | 580 | 6 | 6 | 0 | firehose loader |
| XIAOMItyu | — | 124 | 0 | 0 | 0 | 533 | 0 | 0 | 0 | none |
| **total** | | **1559** | **746** | **528** | **495** | **2228** | **988** | **967** | **349** |

`Usable` is lower than `Loader ok` wherever loaders exist but the operation
scripts that would use them are missing. XIAOMI is the extreme case: 135
working loaders, 580 advertised slots, 6 scripts.

## Operation families actually implemented, per OEM

Counted from *parseable* scripts only. A family absent from a row is not
implemented for that OEM, regardless of what appears in the UI.

| OEM | RESET FRP | FACTORY RESET | FORMAT DATA | RESET EFS | IMEI | UNLOCK BOOTLOADER | RELOCK BOOTLOADER | SAFE FORMAT | ERASE DEMO | MI CLOUD |
|---|---|---|---|---|---|---|---|---|---|---|
| ASUS | 27 | 28 | . | 21 | . | . | . | 1 | . | . |
| HUAWEI | 7 | 4 | . | . | . | . | . | . | . | . |
| INFINIX | 6 | 6 | . | 6 | . | . | . | . | . | . |
| LENOVO | 11 | 10 | . | . | . | . | . | . | . | . |
| MEIZU | 17 | 17 | . | . | . | . | . | . | . | . |
| OPPO | 115 | 111 | 5 | 59 | 10 | . | . | . | 2 | . |
| REALME | 19 | 20 | . | 10 | . | . | . | . | . | . |
| SAMSUNG | 70 | . | . | . | . | . | . | . | . | . |
| VIVO | 98 | 100 | . | 106 | . | 8 | 6 | 62 | . | . |
| XIAOMI | 1 | 1 | . | 1 | . | . | . | . | . | 3 |

Notes that matter:

- **Every** OEM's FRP/factory operation reduces to an erase of a partition
  range (or a `<patch>` write of zeros). There is no per-OEM unlock secret in
  the shipped data; the difference between OEMs is which partitions exist and
  where.
- SAMSUNG's 70 operations are all `RESET FRP`, but they are driven by the Odin
  path, not firehose — a different protocol family with its own handshake.
- `[EDL] UNLOCK BOOTLOADER` appears only under VIVO (8 slots) and in the
  generic index (49 slots), and the corresponding scripts only exist for VIVO.
- XIAOMI's 3 `MI CLOUD` operations belong to one model (`Xiaomi Mi Pro
  [Leo]`), the only XIAOMI device with any script at all.

## Devices advertised with no payload folder

852 of 1 559 indexed devices have a `<program>` row. Of those, 124 have no
folder. The largest groups: XIAOMI (176), OPPO (6), VIVO (6). They appear in
the UI and then fail with "payload folder missing" — the behaviour the vendor
README describes and this audit measures.

## Loaders that do not decrypt

33 devices have a `programs.bin` that does not become an ELF with either
documented password. They cluster in ASUS (3), OPPO (10), REALME (8), VIVO (8),
XIAOMI (4). See `docs/remaining-work.md` §1.

## Loader classification

All 528 shipped `programs.bin` files, after decryption with the recovered key:

| Class | Count | Meaning |
|---|---|---|
| ELF firehose loader | 495 | usable; this is what the Qualcomm path needs |
| ARM pre-loader container | 6 | a second container format (`container.py`); not a firehose loader |
| ELF with one corrupted byte | 2 | `7f 45 4c 45` instead of `7f 45 4c 46`; the rest parses |
| correctly-encrypted empty file | 2 | provably empty, not a missing key |
| undetermined | 23 | only 4 distinct files; see `docs/remaining-work.md` |

So "495 loaders ok" is not 33 failures of one kind — it is four different
situations, three of which are now explained.

## Slots vs rows

2 228 of the 2 230 `method` slots in the tree are reachable: 3 slots belong to
`method` rows whose `Devices` value has no matching `<name>` row, so the tool's
`info.Devices.Contains(brand & " " & model)` match can never fire for them.

## Per-device matrix

`docs/compatibility-matrix.md` has the full per-device tables:
advertised-without-folder, folder-without-loader, and fully-usable. Regenerate
with

```sh
PYTHONPATH=src python3 scripts/build_matrix.py
```
