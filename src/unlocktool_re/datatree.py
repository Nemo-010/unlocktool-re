"""The offline data tree: brand XML indexes and per-model payload folders.

Layout, as established from the shipped tree and the IL that reads it:

    data/
      accounts/accounts.json
      {BRAND}/{brand}.xml                      brand index (3 sections)
      {BRAND}/{Devices + " " + Models}/        one folder per model
          programs.bin                         AES-256-CBC firehose loader
          <operation name>                     plain-text operation script
          <aux payloads>                       referenced by filename="..."
      DA/, SPD/, Tespoint/, misc/, ...         shared payload trees

Brand XML, in this order (the loader walks it with an XmlReader, so the order
is load-bearing):

    <program Devices="..."/>                 payload folders that exist
    <name Devices="..." Models="..." .../>   display entry
    <method Devices="..." M1="..." .. M8=".."/>   operation buttons

`Main::Buttonlist` matches a model with `info.Devices.Contains(brand & " " & model)`,
i.e. the `method` element's Devices value must equal `<name Devices> + " " + <name Models>`.
"""

import json
import os
import re
import xml.etree.ElementTree as ET

from . import crypto

OPERATION_SLOTS = 8


class ModelEntry:
    __slots__ = ('devices', 'models', 'platform', 'edl', 'broom', 'patch',
                 'conn', 'soc', 'beta', 'memory', 'emi_server', 'attrs')

    def __init__(self, attrs):
        self.attrs = dict(attrs)
        self.devices = attrs.get('Devices', '')
        self.models = attrs.get('Models', '')
        self.platform = attrs.get('Platform', '')
        self.edl = attrs.get('EDL', '')
        self.broom = attrs.get('Broom', '')
        self.patch = attrs.get('Patch', '')
        self.conn = attrs.get('Conn', '')
        self.soc = attrs.get('Soc', '')
        self.beta = attrs.get('Beta', '')
        self.memory = attrs.get('Memory', '')
        self.emi_server = attrs.get('EMI_server', '')

    @property
    def key(self):
        """The folder name and the `method` Devices value."""
        return (self.devices + ' ' + self.models).strip()

    def __repr__(self):
        return 'ModelEntry(%r)' % self.key


class OperationSet:
    __slots__ = ('devices', 'operations', 'attrs')

    def __init__(self, attrs):
        self.attrs = dict(attrs)
        self.devices = attrs.get('Devices', '')
        self.operations = []
        for i in range(1, 11):
            name = attrs.get('M%d' % i, '')
            if name:
                self.operations.append(name)

    def __repr__(self):
        return 'OperationSet(%r, %r)' % (self.devices, self.operations)


class BrandIndex:
    """One `{brand}.xml` file."""

    def __init__(self, brand, xml_text):
        self.brand = brand
        self.programs = []      # Devices strings that have a payload folder
        self.models = []        # ModelEntry
        self.operations = []    # OperationSet
        self.attrs = {}
        self._parse(xml_text)

    def _parse(self, xml_text):
        root = ET.fromstring(xml_text)
        self.attrs = dict(root.attrib)
        for el in root:
            tag = el.tag
            if tag == 'program':
                d = el.get('Devices', '')
                if d:
                    self.programs.append(d)
            elif tag == 'name':
                self.models.append(ModelEntry(el.attrib))
            elif tag == 'method':
                self.operations.append(OperationSet(el.attrib))

    def model(self, devices, models):
        key = (devices + ' ' + models).strip()
        for m in self.models:
            if m.key == key:
                return m
        return None

    def operations_for(self, key):
        for op in self.operations:
            if op.devices == key:
                return op
        return None

    def has_payload(self, key):
        return key in self.programs


class DataTree:
    """The `data/` directory of an installed copy."""

    def __init__(self, root):
        self.root = root
        self._brands = {}

    # -- index ------------------------------------------------------------
    def brand_names(self):
        out = []
        for name in sorted(os.listdir(self.root)):
            path = os.path.join(self.root, name)
            if not os.path.isdir(path) or name.startswith('_'):
                continue
            xml = os.path.join(path, name.lower() + '.xml')
            if os.path.isfile(xml):
                out.append(name)
        return out

    def brand(self, name):
        if name in self._brands:
            return self._brands[name]
        xml = os.path.join(self.root, name, name.lower() + '.xml')
        if not os.path.isfile(xml):
            raise KeyError('no brand index for %r' % name)
        with open(xml, encoding='utf-8', errors='replace') as fh:
            idx = BrandIndex(name, fh.read())
        self._brands[name] = idx
        return idx

    def all_brands(self):
        for name in self.brand_names():
            yield self.brand(name)

    # -- payloads ---------------------------------------------------------
    def model_dir(self, brand, key):
        return os.path.join(self.root, brand, key)

    def has_payload_dir(self, brand, key):
        return os.path.isdir(self.model_dir(brand, key))

    def programs_path(self, brand, key):
        return os.path.join(self.model_dir(brand, key), 'programs.bin')

    def operation_script_path(self, brand, key, operation):
        return os.path.join(self.model_dir(brand, key), operation)

    def read_operation_script(self, brand, key, operation):
        path = self.operation_script_path(brand, key, operation)
        if not os.path.isfile(path):
            return None
        with open(path, encoding='utf-8', errors='replace') as fh:
            return fh.read()

    def load_programs(self, brand, key, password=crypto.PASSWORD_RDA):
        """Return the decrypted firehose loader, or raise."""
        with open(self.programs_path(brand, key), 'rb') as fh:
            blob = fh.read()
        return crypto.decrypt_programs_bin(blob, password)

    # -- accounts ---------------------------------------------------------
    def accounts_path(self):
        return os.path.join(self.root, 'accounts', 'accounts.json')

    def load_accounts(self):
        path = self.accounts_path()
        if not os.path.isfile(path):
            return []
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)

    def find_account(self, accounts, user):
        user = (user or '').strip().lower()
        for a in accounts:
            for field in ('UserName', 'Email'):
                if str(a.get(field, '')).strip().lower() == user:
                    return a
        return None


# --- payload reconciliation ------------------------------------------------

_ENTRY_RE = re.compile(
    r'filename\s*=\s*"([^"]+)"|partition_name\s*=\s*"([^"]+)"|'
    r'label\s*=\s*"([^"]+)"', re.I)


def referenced_payloads(script_text):
    """Names referenced by an operation script."""
    out = []
    for m in _ENTRY_RE.finditer(script_text or ''):
        for g in m.groups():
            if g:
                out.append(g)
    return out


def audit_model(tree, brand, entry):
    """Report what a model actually has versus what its index advertises.

    Returns a dict; this is what the compatibility matrix is built from.
    """
    key = entry.key
    dirname = tree.model_dir(brand, key)
    result = {
        'brand': brand, 'key': key,
        'indexed': True,
        'payload_folder': os.path.isdir(dirname),
        'programs_bin': os.path.isfile(os.path.join(dirname, 'programs.bin')),
        'operations': [],
        'missing_scripts': [],
        'missing_payloads': [],
        'loader_ok': None,
        'loader_error': None,
    }
    ops = tree.brand(brand).operations_for(key)
    if ops:
        result['operations'] = list(ops.operations)
    present = set(os.listdir(dirname)) if result['payload_folder'] else set()
    for name in result['operations']:
        if name not in present:
            result['missing_scripts'].append(name)
    if result['programs_bin']:
        try:
            data = tree.load_programs(brand, key)
            result['loader_ok'] = crypto.is_elf(data)
            if not result['loader_ok']:
                result['loader_error'] = 'not an ELF after decryption'
        except Exception as exc:                 # noqa: BLE001 - reported
            result['loader_ok'] = False
            result['loader_error'] = '%s: %s' % (type(exc).__name__, exc)
    for name in result['operations']:
        text = tree.read_operation_script(brand, key, name)
        if text is None:
            continue
        for ref in referenced_payloads(text):
            if ref and ref not in present:
                result['missing_payloads'].append((name, ref))
    return result
