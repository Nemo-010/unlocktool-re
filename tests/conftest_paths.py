"""Shared helper: locate the installer pieces for the integration tests."""
import os

CHUNK_DIRS = [
    os.environ.get('UNLOCKTOOL_CHUNKS', ''),
    '/workspace/src/chunks',
]


def installer_pieces():
    for d in CHUNK_DIRS:
        if not d or not os.path.isdir(d):
            continue
        parts = sorted(os.path.join(d, p) for p in os.listdir(d)
                       if p.startswith('ut.part'))
        if parts:
            return parts
    return []


def installer_path():
    p = os.environ.get('UNLOCKTOOL_INSTALLER')
    if p and os.path.isfile(p):
        return p
    return None
