#!/usr/bin/env python3
"""Dump types, methods, IL, P/Invokes, FieldRVA arrays and resources.

Examples
--------
    # every type name
    tools/ildump.py ColokTool.exe --types

    # disassemble one method
    tools/ildump.py ColokTool.exe --method 'ColokTool.Loader_Thread::Encryption'

    # every method whose name matches a regex
    tools/ildump.py ColokTool.exe --grep 'Encryption|cmdformat' --il

    # summary used by docs/architecture.md
    tools/ildump.py ColokTool.exe --summary
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'il'))

from assembly import Assembly          # noqa: E402
from il import disassemble             # noqa: E402
from metadata import TABLE_NAMES       # noqa: E402


def iter_methods(asm):
    for rid, ns, name, _row in asm.types():
        full = (ns + '.' + name) if ns else name
        for mid in asm.type_methods(rid):
            yield full, mid, asm.md.string(asm.row(asm.md, 6, mid)['Name'])


def cmd_summary(asm):
    md = asm.md
    print('assembly        :', asm.assembly_name())
    print('runtime         :', md.runtime_version)
    print('image base      : %#x' % asm.image_base)
    print('sections        :', ', '.join(s[0] for s in asm.sections))
    print('streams         :', ', '.join(sorted(md.streams)))
    print()
    for t in (2, 4, 6, 10, 11, 12, 28, 29, 40, 41, 42, 8):
        n = md.rows.get(t, 0)
        if n:
            print('%-24s %6d' % (TABLE_NAMES[t], n))
    print()
    print('assembly refs   :', len(asm.assembly_refs()))
    for r in asm.assembly_refs():
        print('   ', r)
    print()
    print('module refs     :')
    for rid, n in asm.module_refs().items():
        print('   ', n)
    print()
    print('P/Invoke targets:')
    by = {}
    for scope, entry, who in asm.pinvokes():
        by.setdefault(scope, []).append((entry, who))
    for scope in sorted(by):
        print('   %-34s %d' % (scope, len(by[scope])))
    print()
    print('FieldRVA arrays :', len(asm.field_rva_arrays()))
    for name, data in asm.field_rva_arrays():
        print('   %-64s %s' % (name, data[:24].hex(' ')))
    print()
    print('manifest resources:', len(asm.manifest_resources()))
    print('managed .resources:', sum(1 for n, _o, _f in asm.manifest_resources()
                                      if n.endswith('.resources')))


def cmd_types(asm):
    for rid, ns, name, row in asm.types():
        full = (ns + '.' + name) if ns else name
        n = len(asm.type_methods(rid))
        print('%5d %-58s %3d methods' % (rid, full, n))


def cmd_methods(asm, pattern):
    rx = re.compile(pattern) if pattern else None
    for full, mid, name in iter_methods(asm):
        label = '%s::%s' % (full, name)
        if rx and not rx.search(label):
            continue
        try:
            sig = asm.method_sig(mid)
            desc = '%s <- (%s)' % (sig['ret'], ', '.join(sig['params']))
        except Exception as exc:              # noqa: BLE001 - reported
            desc = '<sig error: %s>' % exc
        print('%5d %-64s %s' % (mid, label, desc))


def cmd_il(asm, pattern):
    rx = re.compile(pattern) if pattern else None
    shown = 0
    for full, mid, name in iter_methods(asm):
        label = '%s::%s' % (full, name)
        if rx and not rx.search(label):
            continue
        code = asm.body(mid)
        if code is None:
            continue
        print('=' * 78)
        print(label, '  [MethodDef rid %d]' % mid)
        shown += 1
        for off, op, arg, _raw in disassemble(asm, code):
            print('  IL_%04X: %-16s %s' % (off, op, arg))
    if not shown:
        print('no matching method with a body', file=sys.stderr)


def cmd_pinvoke(asm):
    for scope, entry, who in asm.pinvokes():
        print('%-34s %-42s %s' % (scope, entry, who))


def cmd_rva(asm):
    for name, data in asm.field_rva_arrays():
        printable = all(32 <= c < 127 for c in data[:24])
        print('%-64s %s%s' % (name, data[:32].hex(' '),
                              '  ' + repr(data[:32]) if printable else ''))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('assembly')
    ap.add_argument('--summary', action='store_true')
    ap.add_argument('--types', action='store_true')
    ap.add_argument('--methods', action='store_true')
    ap.add_argument('--il', action='store_true')
    ap.add_argument('--pinvoke', action='store_true')
    ap.add_argument('--rva', action='store_true')
    ap.add_argument('--grep', default=None)
    ap.add_argument('--method', default=None,
                    help="exact 'Type::Method' to disassemble")
    args = ap.parse_args()

    asm = Assembly(args.assembly)
    if args.method:
        cmd_il(asm, '^' + re.escape(args.method) + '$')
        return
    did = False
    if args.summary:
        cmd_summary(asm); did = True
    if args.types:
        cmd_types(asm); did = True
    if args.methods:
        cmd_methods(asm, args.grep); did = True
    if args.il:
        cmd_il(asm, args.grep); did = True
    if args.pinvoke:
        cmd_pinvoke(asm); did = True
    if args.rva:
        cmd_rva(asm); did = True
    if not did:
        ap.print_help()


if __name__ == '__main__':
    main()
