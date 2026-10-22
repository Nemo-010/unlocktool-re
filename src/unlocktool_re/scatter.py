"""MediaTek scatter files (`android.txt` / `MTxxxx_Android_scatter.xml`).

`ColokTool.RDA.MtkScatter.ScatterTable(string)` reads a scatter file and
returns `List<mtk>`. The IL is unambiguous about the format it expects:

```
text = File.ReadAllText(path)
text = text.Replace("- partition_index:", "+ partition_index:")
parts = text.Split('+')
for each part:
    if part.Contains("partition_name"):
        use a StringReader over the part, pulling fields line by line
```

So it is the **YAML-ish MediaTek scatter format** (the one with
`- partition_index: SYS0` / `  partition_name: frp`), not the XML one. The
`Replace("- partition_index:", "+ partition_index:")` before splitting on `+`
is the giveaway: the tool rewrites the list marker so that a plain `+` split
separates the entries.

Two on-disk forms exist in the shipped tree and both are this format:

    android.txt                          (158 model folders)
    MT6765_Android_scatter.xml           (a handful; XML-shaped, different parser)

Only `android.txt` matches `ScatterTable`'s expectations. `DXApplication.Mtkxml`
has the same surface API (`CPU`, `Cache`, `Userdata`, `Cachepath`, `Userpath`,
`IsSupport`, `ScatterTable`) and is the XML variant.

The field names the tool reads are the standard ones; this module parses them
all, plus the `- general:` block.
"""

import re

# Indentation is not stable across vendors: some files use
#   - partition_index: SYS0
# and some use
#   "  - partition_index: SYS0"
# so both the marker and the fields are matched with leading whitespace allowed.
ENTRY_SPLIT = re.compile(r'^\s*-\s+partition_index\s*:', re.M)
FIELD_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*$', re.M)


class ScatterEntry:
    __slots__ = ('index', 'name', 'file_name', 'is_download', 'type',
                 'linear_start_addr', 'physical_start_addr', 'partition_size',
                 'region', 'storage', 'boundary_check', 'is_reserved',
                 'operation_type', 'fields')

    def __init__(self, index, fields):
        self.index = index
        self.fields = dict(fields)
        self.name = fields.get('partition_name', '')
        self.file_name = fields.get('file_name', '')
        self.is_download = fields.get('is_download', '').lower() == 'true'
        self.type = fields.get('type', '')
        self.linear_start_addr = _int(fields.get('linear_start_addr'))
        self.physical_start_addr = _int(fields.get('physical_start_addr'))
        self.partition_size = _int(fields.get('partition_size'))
        self.region = fields.get('region', '')
        self.storage = fields.get('storage', '')
        self.boundary_check = fields.get('boundary_check', '').lower() == 'true'
        self.is_reserved = fields.get('is_reserved', '').lower() == 'true'
        self.operation_type = fields.get('operation_type', '')

    @property
    def has_payload(self):
        """`file_name: NONE` means the partition is described but not written."""
        return bool(self.file_name) and self.file_name.upper() != 'NONE'

    def __repr__(self):
        return 'ScatterEntry(%s %s%s)' % (
            self.index, self.name,
            ' -> ' + self.file_name if self.has_payload else '')


class ScatterFile:
    def __init__(self, text):
        self.general = {}
        self.entries = []
        self.error = None
        self._parse(text)

    def _parse(self, text):
        if not text or not text.strip():
            self.error = 'empty scatter file'
            return
        # the `- general:` block
        gen = re.search(r'^\s*-\s+general\s*:\s*(\S+)', text, re.M)
        if gen:
            self.general['name'] = gen.group(1)
        for key in ('platform', 'project', 'storage', 'block_size',
                    'boot_channel', 'config_version'):
            m = re.search(r'^\s+%s\s*:\s*(\S+)' % key, text, re.M)
            if m:
                self.general[key] = m.group(1)

        # entries: split on the partition_index marker
        starts = [m.start() for m in ENTRY_SPLIT.finditer(text)]
        if not starts:
            self.error = 'no partition_index entries'
            return
        starts.append(len(text))
        for i in range(len(starts) - 1):
            chunk = text[starts[i]:starts[i + 1]]
            fields = dict(FIELD_RE.findall(chunk))
            # `partition_index: SYS0` sits on the marker line itself, which the
            # indented-field regex cannot see; take it from the marker.
            head = ENTRY_SPLIT.match(chunk)
            idx = ''
            if head:
                rest = chunk[head.end():].split('\n', 1)[0].strip()
                idx = rest or ''
            fields.pop('partition_index', None)
            self.entries.append(ScatterEntry(idx, fields))

    def by_name(self, name):
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def downloads(self):
        return [e for e in self.entries if e.is_download and e.has_payload]

    def __repr__(self):
        return 'ScatterFile(platform=%r, %d entries)' % (
            self.general.get('platform'), len(self.entries))


def _int(v):
    if not v:
        return None
    try:
        return int(str(v), 0)
    except ValueError:
        return None


def parse(text):
    return ScatterFile(text)


def is_scatter_text(text):
    return bool(text) and '- partition_index' in text


def load(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            return ScatterFile(fh.read())
    except OSError:
        return None
