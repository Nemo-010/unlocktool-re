"""Qualcomm firehose rawprogram scripts, as the tool's operation files use them.

Every file named by a `method` M1..M8 slot in a brand XML is a rawprogram XML
consumed by the Qualcomm firehose protocol.  Four element kinds occur in the
shipped tree (measured over all 989 scripts that exist):

    <program>   write `filename` to `label`, or erase `label` when filename=""
    <erase>     erase a raw sector range (no partition label)
    <patch>     write `value` at `byte_offset` inside `start_sector`
    <patches>   container for <patch> elements

Two structural defects are present in the shipped data and are preserved here
rather than hidden, because the point of this module is to describe what the
tool actually loads:

  * some scripts end with the literal text `EndCF` after the closing root tag
    (XML parsers reject "junk after document element")
  * some scripts are truncated and never close the root element
  * some scripts are zero bytes

`RawProgram.error` records all of these; nothing is silently repaired.
"""

import os
import re
import xml.etree.ElementTree as ET

KNOWN_ELEMENTS = ('program', 'erase', 'patch', 'patches')


def _int(v, default=None):
    if v is None or v == '':
        return default
    try:
        return int(str(v), 0)
    except ValueError:
        return default


def _float(v, default=None):
    if v is None or v == '':
        return default
    try:
        return float(v)
    except ValueError:
        return default


class ProgramEntry:
    """A `<program>` element."""

    __slots__ = ('filename', 'label', 'physical_partition_number',
                 'start_sector', 'num_partition_sectors', 'sector_size',
                 'size_in_kb', 'sparse', 'start_byte_hex', 'attrs')

    def __init__(self, attrs):
        self.attrs = dict(attrs)
        self.filename = attrs.get('filename', '')
        self.label = attrs.get('label', '')
        self.physical_partition_number = _int(attrs.get('physical_partition_number'))
        self.start_sector = _int(attrs.get('start_sector'))
        self.num_partition_sectors = _int(attrs.get('num_partition_sectors'))
        self.sector_size = _int(attrs.get('SECTOR_SIZE_IN_BYTES'), 512)
        self.size_in_kb = _float(attrs.get('size_in_KB'))
        self.sparse = attrs.get('sparse', 'false').lower() == 'true'
        self.start_byte_hex = attrs.get('start_byte_hex', '')

    @property
    def action(self):
        return 'write' if self.filename else 'erase'

    @property
    def start_byte(self):
        if self.start_sector is not None and self.sector_size:
            return self.start_sector * self.sector_size
        return None

    @property
    def length_bytes(self):
        if self.num_partition_sectors is None:
            return None
        return self.num_partition_sectors * (self.sector_size or 512)

    def __repr__(self):
        return 'ProgramEntry(%s %r ppn=%s)' % (self.action, self.label,
                                               self.physical_partition_number)


class EraseEntry:
    """A `<erase>` element: raw sector range, no label."""

    __slots__ = ('start_sector', 'num_partition_sectors', 'sector_size',
                 'physical_partition_number', 'attrs')

    def __init__(self, attrs):
        self.attrs = dict(attrs)
        self.start_sector = _int(attrs.get('start_sector'))
        self.num_partition_sectors = _int(attrs.get('num_partition_sectors'))
        self.sector_size = _int(attrs.get('SECTOR_SIZE_IN_BYTES'), 512)
        self.physical_partition_number = _int(attrs.get('physical_partition_number'))

    @property
    def start_byte(self):
        return self.start_sector * self.sector_size

    @property
    def length_bytes(self):
        return self.num_partition_sectors * self.sector_size

    def __repr__(self):
        return 'EraseEntry(start=%s n=%s)' % (self.start_sector,
                                             self.num_partition_sectors)


class PatchEntry:
    """A `<patch>` element: write `value` at `byte_offset` of `start_sector`."""

    __slots__ = ('start_sector', 'byte_offset', 'size_in_bytes', 'value',
                 'sector_size', 'physical_partition_number', 'what', 'attrs')

    def __init__(self, attrs):
        self.attrs = dict(attrs)
        self.start_sector = _int(attrs.get('start_sector'))
        self.byte_offset = _int(attrs.get('byte_offset'))
        self.size_in_bytes = _int(attrs.get('size_in_bytes'))
        self.value = _int(attrs.get('value'), 0)
        self.sector_size = _int(attrs.get('SECTOR_SIZE_IN_BYTES'), 512)
        self.physical_partition_number = _int(attrs.get('physical_partition_number'))
        self.what = attrs.get('what', '')

    @property
    def absolute_byte(self):
        return self.start_sector * self.sector_size + self.byte_offset

    def __repr__(self):
        return 'PatchEntry(at=%s value=%s size=%s)' % (
            self.absolute_byte, self.value, self.size_in_bytes)


class RawProgram:
    """A parsed operation script."""

    def __init__(self, name, xml_text):
        self.name = name
        self.entries = []
        self.programs = []
        self.erases = []
        self.patches = []
        self.error = None
        self.warnings = []
        self.raw = xml_text or ''
        self._parse()

    def _parse(self):
        if not self.raw.strip():
            self.error = 'empty script'
            return
        text = self.raw
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            self.error = 'XML parse error: %s' % exc
            self._salvage(text)
            return
        self._collect(root)

    def _collect(self, root):
        for el in root.iter():
            tag = el.tag
            if tag == 'program':
                e = ProgramEntry(el.attrib)
                self.programs.append(e)
                self.entries.append(e)
            elif tag == 'erase':
                e = EraseEntry(el.attrib)
                self.erases.append(e)
                self.entries.append(e)
            elif tag == 'patch':
                e = PatchEntry(el.attrib)
                self.patches.append(e)
                self.entries.append(e)

    def _salvage(self, text):
        """Recover the elements we can from a script XML cannot parse.

        Deliberately conservative: we only report what a per-element regex
        finds, and we keep `error` set so callers know the script is broken.
        """
        for tag in KNOWN_ELEMENTS:
            for m in re.finditer(r'<%s\b([^>]*)/?>' % tag, text):
                attrs = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', m.group(1)))
                if tag == 'program':
                    self.programs.append(ProgramEntry(attrs))
                elif tag == 'erase':
                    self.erases.append(EraseEntry(attrs))
                elif tag == 'patch':
                    self.patches.append(PatchEntry(attrs))
        self.entries = self.programs + self.erases + self.patches

    # -- queries -----------------------------------------------------------
    @property
    def writes(self):
        return [e for e in self.programs if e.action == 'write']

    @property
    def label_erases(self):
        return [e for e in self.programs if e.action == 'erase']

    def payload_names(self):
        return [e.filename for e in self.writes]

    def __repr__(self):
        return 'RawProgram(%r, %d entries%s)' % (
            self.name, len(self.entries), ', ERROR' if self.error else '')


def load_rawprogram(model_dir, name):
    path = os.path.join(model_dir, name)
    if not os.path.isfile(path):
        return None
    with open(path, encoding='utf-8', errors='replace') as fh:
        return RawProgram(name, fh.read())
