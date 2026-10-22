#!/usr/bin/env python3
"""Extract the shipped data/ tree (and optionally the embedded exe) from the installer.

Large binaries are skipped by default; pass --all to take everything.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'src'))

from unlocktool_re.installer import Installer      # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pieces', nargs='+')
    ap.add_argument('--out', default='artifacts/tree')
    ap.add_argument('--max-size', type=int, default=100000,
                    help='skip files larger than this (bytes); 0 = no limit')
    ap.add_argument('--only', action='append', default=[],
                    help='only extract paths ending with one of these suffixes')
    args = ap.parse_args()

    inst = Installer(args.pieces)
    try:
        n = 0
        total = 0
        for entry in inst.files:
            name = entry['DestName']
            if not name:
                continue
            rel = name.replace('{app}\\', '').replace('\\', '/')
            li = entry['LocationEntry']
            if li < 0 or li >= len(inst.locations):
                continue
            loc = inst.locations[li]
            size = loc['OriginalSize']
            if args.max_size and size > args.max_size:
                continue
            if args.only and not any(rel.endswith(s) for s in args.only):
                continue
            data = inst.read_file(entry)
            dest = os.path.join(args.out, rel)
            os.makedirs(os.path.dirname(dest) or args.out, exist_ok=True)
            with open(dest, 'wb') as fh:
                fh.write(data)
            n += 1
            total += size
        print('extracted %d files, %.1f MiB' % (n, total / 2 ** 20))
    finally:
        inst.close()


if __name__ == '__main__':
    main()
