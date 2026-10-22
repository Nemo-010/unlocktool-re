#!/usr/bin/env python3
"""Split the 2.3 GB installer into <1 GB pieces so the sandbox can hold it.

The harness here enforces a hard 1 GB per-file write limit (RLIMIT_FSIZE),
so a single file larger than that cannot exist on disk.  ChunkSource reads
across pieces, which is why this is a supported layout rather than a hack.
"""
import os
import sys

CHUNK = 900 * 1024 * 1024


def main():
    if len(sys.argv) != 3:
        print('usage: split_installer.py <installer.exe> <outdir>', file=sys.stderr)
        return 2
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    size = os.path.getsize(src)
    paths = []
    with open(src, 'rb') as fh:
        n = 0
        while True:
            data = fh.read(CHUNK)
            if not data:
                break
            path = os.path.join(outdir, 'part%03d' % n)
            with open(path, 'wb') as out:
                out.write(data)
            paths.append(path)
            n += 1
    print('size', size, 'pieces', len(paths))
    for p in paths:
        print(p, os.path.getsize(p))
    return 0


if __name__ == '__main__':
    sys.exit(main())
