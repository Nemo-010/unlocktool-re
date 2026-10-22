#!/usr/bin/env python3
"""Build the evidence-backed OEM compatibility matrix.

Every row is derived from artefacts in the shipped tree plus the recovered
programs.bin key; nothing is inferred from a name appearing in a string table.

Usage:
    PYTHONPATH=src python3 scripts/build_matrix.py --tree artifacts/tree/data \
        --out docs/compatibility-matrix.md
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'src'))

from unlocktool_re import crypto, firehose, scatter   # noqa: E402
from unlocktool_re.datatree import DataTree          # noqa: E402

# How each model folder's payload is shaped.  The first four are layouts
# ColokTool itself reads (verified against its string literals); the rest are
# merged-in foreign layouts (docs/data-layouts.md).
LAYOUT_EDL = 'programs.bin (EDL)'
LAYOUT_SCATTER = 'android.txt (MTK scatter)'
LAYOUT_UNISOC = 'fdl1/fdl2 (Unisoc)'
LAYOUT_NONE = 'no payload folder'
LAYOUT_FOREIGN = ('auth.auth', 'loader.elf', 'MTK scatter XML', 'empty', 'other')


def classify_layout(tree, brand, key):
    import os
    d = tree.model_dir(brand, key)
    if not os.path.isdir(d):
        return LAYOUT_NONE
    f = set(os.listdir(d))
    if 'programs.bin' in f:
        return LAYOUT_EDL
    if 'fdl1.bin' in f:
        return LAYOUT_UNISOC
    if 'android.txt' in f:
        return LAYOUT_SCATTER
    if any(x.endswith('scatter.xml') or x.endswith('scatter.txt') for x in f):
        return 'MTK scatter XML'
    if 'loader.elf' in f:
        return 'loader.elf'
    if 'auth.auth' in f:
        return 'auth.auth'
    if not f:
        return 'empty'
    return 'other'

OPERATION_FAMILIES = [
    ('RESET FRP', lambda n: 'FRP' in n.upper()),
    ('FACTORY RESET', lambda n: 'FACTORY RESET' in n.upper()),
    ('FORMAT DATA', lambda n: 'FORMAT DATA' in n.upper()
        or 'FORMAT USERDATA' in n.upper()),
    ('RESET EFS', lambda n: 'EFS' in n.upper()),
    ('IMEI', lambda n: 'IMEI' in n.upper() or 'MEID' in n.upper()),
    ('UNLOCK BOOTLOADER', lambda n: 'UNLOCK' in n.upper()
        and 'BOOTLOADER' in n.upper()),
    ('RELOCK BOOTLOADER', lambda n: 'RELOCK' in n.upper()),
    ('SAFE FORMAT', lambda n: 'SAFE FORMAT' in n.upper()),
    ('ERASE DEMO', lambda n: 'DEMO' in n.upper()),
    ('FIX DM-VERITY', lambda n: 'DM' in n.upper() and 'VERITY' in n.upper()),
    ('MI CLOUD', lambda n: 'MI CLOUD' in n.upper() or 'MICLOUD' in n.upper()),
    ('READ / BACKUP', lambda n: 'READ' in n.upper() or 'BACKUP' in n.upper()),
]


def classify(name):
    out = []
    for label, pred in OPERATION_FAMILIES:
        if pred(name):
            out.append(label)
    return out or ['OTHER']


def scan(tree):
    rows = []
    for brand in tree.all_brands():
        ops_by_key = {o.devices: o for o in brand.operations}
        programs = set(brand.programs)
        for model in brand.models:
            key = model.key
            row = {
                'brand': brand.brand,
                'key': key,
                'platform': model.platform,
                'edl': model.edl,
                'broom': model.broom,
                'conn': model.conn,
                'soc': model.soc,
                'advertised_in_programs': key in programs,
                'has_folder': tree.has_payload_dir(brand.brand, key),
                'operations': [],
                'programs_bin': False,
                'loader_ok': None,
                'loader_error': None,
                'layout': classify_layout(tree, brand.brand, key),
                'scatter_ok': None,
                'scatter_entries': None,
            }
            if row['layout'] == LAYOUT_SCATTER:
                sc = scatter.load(
                    tree.model_dir(brand.brand, key) + '/android.txt')
                row['scatter_ok'] = bool(sc and not sc.error and sc.entries)
                row['scatter_entries'] = len(sc.entries) if sc else 0
            ops = ops_by_key.get(key)
            if ops:
                for name in ops.operations:
                    rp = firehose.load_rawprogram(
                        tree.model_dir(brand.brand, key), name)
                    row['operations'].append({
                        'name': name,
                        'present': rp is not None,
                        'error': rp.error if rp else 'script missing',
                        'families': classify(name),
                        'writes': rp.payload_names() if rp else [],
                        'patches': len(rp.patches) if rp else 0,
                        'erase_ranges': len(rp.erases) if rp else 0,
                    })
            pb = tree.programs_path(brand.brand, key)
            if os.path.isfile(pb):
                row['programs_bin'] = True
                try:
                    plain = crypto.decrypt_programs_bin(open(pb, 'rb').read())
                    row['loader_ok'] = crypto.is_elf(plain)
                    if not row['loader_ok']:
                        row['loader_error'] = 'decrypted data is not ELF'
                except Exception as exc:      # noqa: BLE001 - reported
                    row['loader_ok'] = False
                    row['loader_error'] = '%s: %s' % (type(exc).__name__, exc)
            rows.append(row)
    return rows


def summarise(rows):
    by_brand = collections.defaultdict(lambda: collections.Counter())
    layouts = collections.Counter(r['layout'] for r in rows)
    fam = collections.defaultdict(lambda: collections.Counter())
    for r in rows:
        b = by_brand[r['brand']]
        b['models'] += 1
        b['advertised'] += 1 if r['advertised_in_programs'] else 0
        b['folder'] += 1 if r['has_folder'] else 0
        b['loader'] += 1 if r['programs_bin'] else 0
        b['loader_ok'] += 1 if r['loader_ok'] else 0
        b['loader_bad'] += 1 if r['programs_bin'] and not r['loader_ok'] else 0
        for op in r['operations']:
            b['op_advertised'] += 1
            b['op_present'] += 1 if op['present'] else 0
            b['op_broken'] += 1 if op['present'] and op['error'] else 0
            if op['present'] and not op['error']:
                for f in op['families']:
                    fam[r['brand']][f] += 1
    return by_brand, fam, layouts


def write_report(tree, rows, by_brand, fam, layouts, out):
    total = len(rows)
    lines = []
    w = lines.append
    w('# OEM / device compatibility matrix')
    w('')
    w('Generated by `scripts/build_matrix.py` from the shipped `data/` tree.')
    w('Every column is a measurement, not a claim: `advertised` counts `<program>`')
    w('rows in the brand index, `folder` counts directories that actually exist,')
    w('`loader ok` counts `programs.bin` files that decrypt to an ELF with the')
    w('recovered key, and the operation columns count scripts that parse.')
    w('')
    w('A device is only usable end-to-end when `folder` and `loader ok` are both')
    w('set and at least one operation script parses. Devices that are advertised')
    w('but have no folder are visible in the UI and then fail, which is the')
    w('behaviour the vendor README itself describes.')
    w('')
    w('| Brand | Models | Advertised | Folder | Loader | Loader ok | Loader bad | Ops advertised | Ops present | Ops broken |')
    w('|---|---|---|---|---|---|---|---|---|---|')
    grand = collections.Counter()
    for brand in sorted(by_brand):
        c = by_brand[brand]
        w('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
            brand, c['models'], c['advertised'], c['folder'], c['loader'],
            c['loader_ok'], c['loader_bad'], c['op_advertised'],
            c['op_present'], c['op_broken']))
        for k, v in c.items():
            grand[k] += v
    w('| **total** | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
        grand['models'], grand['advertised'], grand['folder'], grand['loader'],
        grand['loader_ok'], grand['loader_bad'], grand['op_advertised'],
        grand['op_present'], grand['op_broken']))
    w('')
    w('## Payload layouts')
    w('')
    w('A model can only be driven by ColokTool if its folder is one of the first')
    w('three layouts below. The last three are merged-in foreign layouts that')
    w('this binary never reads (see `docs/data-layouts.md`).')
    w('')
    w('| Layout | Models | Read by ColokTool |')
    w('|---|---|---|')
    for name in (LAYOUT_EDL, LAYOUT_SCATTER, LAYOUT_UNISOC, LAYOUT_NONE,
                 'auth.auth', 'other', 'MTK scatter XML', 'loader.elf', 'empty'):
        if layouts.get(name):
            readable = 'yes' if name in (LAYOUT_EDL, LAYOUT_SCATTER,
                                         LAYOUT_UNISOC) else 'no'
            w('| %s | %d | %s |' % (name, layouts[name], readable))
    w('')
    w('Scatter files parse in %d of %d `android.txt` folders.' % (
        sum(1 for r in rows if r['scatter_ok']),
        sum(1 for r in rows if r['layout'] == LAYOUT_SCATTER)))
    w('')
    w('## Operation families per brand')
    w('')
    w('Counts are of *parseable* scripts, i.e. operations the tool can actually')
    w('build a firehose plan from. A family appearing here is implemented; it is')
    w('not merely listed.')
    w('')
    families = [f for f, _ in OPERATION_FAMILIES] + ['OTHER']
    w('| Brand | ' + ' | '.join(families) + ' |')
    w('|' + '---|' * (len(families) + 1))
    for brand in sorted(fam):
        row = fam[brand]
        w('| %s | ' % brand + ' | '.join(
            str(row[f]) if row[f] else '.' for f in families) + ' |')
    w('')
    w('## Devices advertised with no payload folder')
    w('')
    orphans = [r for r in rows if r['advertised_in_programs'] and not r['has_folder']]
    w('%d of %d indexed devices.' % (len(orphans), total))
    w('')
    if orphans:
        w('| Brand | Device |')
        w('|---|---|')
        for r in orphans[:60]:
            w('| %s | %s |' % (r['brand'], r['key']))
        if len(orphans) > 60:
            w('')
            w('(%d more; see `artifacts/matrix.json`.)' % (len(orphans) - 60))
    w('')
    w('## Devices with a payload folder but no working loader')
    w('')
    bad = [r for r in rows if r['programs_bin'] and not r['loader_ok']]
    w('%d devices.' % len(bad))
    w('')
    if bad:
        w('| Brand | Device | Error |')
        w('|---|---|---|')
        for r in bad[:40]:
            w('| %s | %s | %s |' % (r['brand'], r['key'], r['loader_error']))
    w('')
    w('## Devices fully usable')
    w('')
    ok = [r for r in rows
          if r['has_folder'] and r['loader_ok']
          and any(op['present'] and not op['error'] for op in r['operations'])]
    w('%d of %d indexed devices (%.1f%%).' % (len(ok), total,
                                              100.0 * len(ok) / total))
    w('')
    w('"Fully usable" here means: payload folder present, `programs.bin` decrypts')
    w('to an ELF with the recovered key, and at least one operation script parses')
    w('and names only payloads that exist in the folder.')
    w('')
    with open(out, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tree', default='artifacts/tree/data')
    ap.add_argument('--out', default='docs/compatibility-matrix.md')
    ap.add_argument('--json', default='artifacts/matrix.json')
    args = ap.parse_args()
    tree = DataTree(args.tree)
    rows = scan(tree)
    by_brand, fam, layouts = summarise(rows)
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    write_report(tree, rows, by_brand, fam, layouts, args.out)
    with open(args.json, 'w') as fh:
        json.dump(rows, fh, indent=1)
    print('models', len(rows), '->', args.out, 'and', args.json)


if __name__ == '__main__':
    main()
